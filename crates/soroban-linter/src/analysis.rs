//! Shared AST helpers used by the rules.
//!
//! The analysis is purely syntactic: it recognises Soroban storage calls
//! (`env.storage().persistent().set(..)` and friends), auth calls, and calls
//! between functions of the analysed crate. Calls are resolved **by name**,
//! which is a deliberate trade-off: it needs no type information and works on
//! stable Rust, at the cost of occasional imprecision when two functions share
//! a name.

use std::collections::HashMap;

use proc_macro2::{Span, TokenStream, TokenTree};
use quote::ToTokens;
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{
    Attribute, BinOp, Block, Expr, ExprBinary, ExprCall, ExprMethodCall, ImplItem, Item, Local,
    Macro, Pat, RangeLimits, Signature, Token, Visibility,
};

// ---------------------------------------------------------------------------
// Storage call recognition
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StorageKind {
    Persistent,
    Temporary,
    Instance,
}

impl StorageKind {
    pub fn as_str(self) -> &'static str {
        match self {
            StorageKind::Persistent => "persistent",
            StorageKind::Temporary => "temporary",
            StorageKind::Instance => "instance",
        }
    }

    fn from_method(name: &str) -> Option<Self> {
        match name {
            "persistent" => Some(StorageKind::Persistent),
            "temporary" => Some(StorageKind::Temporary),
            "instance" => Some(StorageKind::Instance),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageOp {
    Read,
    Write,
    Remove,
    ExtendTtl,
}

impl StorageOp {
    fn from_method(name: &str) -> Option<Self> {
        match name {
            "get" | "has" | "try_get" => Some(StorageOp::Read),
            "set" | "update" | "try_update" => Some(StorageOp::Write),
            "remove" => Some(StorageOp::Remove),
            "extend_ttl" | "bump" => Some(StorageOp::ExtendTtl),
            _ => None,
        }
    }

    pub fn is_mutation(self) -> bool {
        matches!(self, StorageOp::Write | StorageOp::Remove)
    }
}

/// One recognised call on a Soroban storage handle.
#[derive(Debug, Clone)]
pub struct StorageCall {
    pub kind: StorageKind,
    pub op: StorageOp,
    pub method: String,
    /// Source text of the key expression (after resolving simple `let key = ..` bindings).
    pub key: Option<String>,
    /// True when the key is an enum variant / constructor with arguments,
    /// e.g. `DataKey::Balance(user)` — i.e. one entry per user/id.
    pub key_is_parameterized: bool,
    /// For writes: the stored value is computed with a subtraction (`balance - amount`).
    pub value_subtracts: bool,
    pub line: usize,
    pub column: usize,
}

impl StorageCall {
    /// True if `ident` appears as a word in the key expression.
    pub fn key_mentions(&self, ident: &str) -> bool {
        self.key.as_deref().is_some_and(|k| {
            k.split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .any(|w| w == ident)
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Binding {
    /// `let s = env.storage();`
    Storage,
    /// `let s = env.storage().persistent();`
    Kind(StorageKind),
    /// `let key = DataKey::Balance(id);`
    Key { text: String, parameterized: bool },
}

/// Local variable bindings that matter for storage recognition.
#[derive(Debug, Clone, Default)]
pub struct Bindings(HashMap<String, Binding>);

/// Removes parentheses, references and invisible groups around an expression.
pub fn strip(mut expr: &Expr) -> &Expr {
    loop {
        expr = match expr {
            Expr::Paren(e) => &e.expr,
            Expr::Reference(e) => &e.expr,
            Expr::Group(e) => &e.expr,
            _ => return expr,
        };
    }
}

fn single_ident(expr: &Expr) -> Option<String> {
    match strip(expr) {
        Expr::Path(p) if p.qself.is_none() => p.path.get_ident().map(|i| i.to_string()),
        _ => None,
    }
}

fn is_storage_handle(expr: &Expr, b: &Bindings) -> bool {
    match strip(expr) {
        Expr::MethodCall(m) => m.method == "storage" && m.args.is_empty(),
        e => single_ident(e).is_some_and(|id| b.0.get(&id) == Some(&Binding::Storage)),
    }
}

/// Returns the storage kind if `expr` is `<storage>.persistent()` (or a variable bound to one).
pub fn storage_kind(expr: &Expr, b: &Bindings) -> Option<StorageKind> {
    match strip(expr) {
        Expr::MethodCall(m) if m.args.is_empty() => {
            let kind = StorageKind::from_method(&m.method.to_string())?;
            is_storage_handle(&m.receiver, b).then_some(kind)
        }
        e => match b.0.get(&single_ident(e)?) {
            Some(Binding::Kind(k)) => Some(*k),
            _ => None,
        },
    }
}

/// True for keys built from runtime values, e.g. `DataKey::Balance(user)`.
/// Constant keys such as `Symbol::new(e, ADMIN_KEY)` or `DataKey::Tier(1)` are not.
fn is_parameterized_key(expr: &Expr) -> bool {
    let dynamic = |e: &Expr| match strip(e) {
        Expr::Lit(_) => false,
        e => match single_ident(e) {
            // The environment, or a CONSTANT.
            Some(id) => {
                !(matches!(id.as_str(), "e" | "env" | "_env")
                    || id
                        .chars()
                        .all(|c| c.is_uppercase() || c.is_ascii_digit() || c == '_'))
            }
            None => true,
        },
    };
    match strip(expr) {
        Expr::Call(c) => c.args.iter().any(dynamic),
        Expr::Tuple(t) => t.elems.len() > 1 && t.elems.iter().any(dynamic),
        Expr::Struct(s) => s.fields.iter().any(|f| dynamic(&f.expr)),
        _ => false,
    }
}

/// Recognises `<storage kind>.<op>(..)`.
pub fn storage_call(m: &ExprMethodCall, b: &Bindings) -> Option<StorageCall> {
    let op = StorageOp::from_method(&m.method.to_string())?;
    let kind = storage_kind(&m.receiver, b)?;
    // Instance `extend_ttl(threshold, extend_to)` has no key argument.
    let key_expr = if kind == StorageKind::Instance && op == StorageOp::ExtendTtl {
        None
    } else {
        m.args.first()
    };
    let (key, key_is_parameterized) = match key_expr {
        None => (None, false),
        Some(e) => match plain_ident(e).and_then(|id| b.0.get(&id)) {
            Some(Binding::Key {
                text,
                parameterized,
            }) => (Some(text.clone()), *parameterized),
            _ => (Some(tokens_to_string(e)), is_parameterized_key(e)),
        },
    };
    let (line, column) = line_col(m.method.span());
    let value_subtracts = op == StorageOp::Write && m.args.iter().nth(1).is_some_and(subtracts);
    Some(StorageCall {
        kind,
        op,
        method: m.method.to_string(),
        key,
        key_is_parameterized,
        value_subtracts,
        line,
        column,
    })
}

/// True if the expression contains a subtraction (`a - b`, `a -= b`, `checked_sub`, `-x`, ...).
pub fn subtracts(expr: &Expr) -> bool {
    struct Sub(bool);
    impl<'ast> Visit<'ast> for Sub {
        fn visit_expr_binary(&mut self, b: &'ast ExprBinary) {
            if matches!(b.op, BinOp::Sub(_) | BinOp::SubAssign(_)) {
                self.0 = true;
            }
            visit::visit_expr_binary(self, b);
        }
        fn visit_expr_unary(&mut self, u: &'ast syn::ExprUnary) {
            if matches!(u.op, syn::UnOp::Neg(_)) {
                self.0 = true;
            }
            visit::visit_expr_unary(self, u);
        }
        fn visit_expr_method_call(&mut self, m: &'ast ExprMethodCall) {
            let n = m.method.to_string();
            if n.ends_with("_sub") || n == "sub" {
                self.0 = true;
            }
            visit::visit_expr_method_call(self, m);
        }
    }
    let mut v = Sub(false);
    v.visit_expr(expr);
    v.0
}

/// One argument of a call to a crate-local function.
#[derive(Debug, Clone)]
pub struct CallArg {
    /// The variable passed, if the argument is a plain variable (`x`, `&x`, `x.clone()`).
    pub ident: Option<String>,
    pub subtracts: bool,
    /// Source text of the argument, with `let key = ..` bindings resolved
    /// (so it can be matched as a storage key).
    pub key_text: String,
}

/// A call to a crate-local function.
#[derive(Debug, Clone)]
pub struct CallSite {
    pub callee: String,
    pub args: Vec<CallArg>,
}

fn plain_ident(arg: &Expr) -> Option<String> {
    let mut e = strip(arg);
    if let Expr::MethodCall(m) = e {
        if m.method == "clone" && m.args.is_empty() {
            e = strip(&m.receiver);
        }
    }
    single_ident(e)
}

/// Helper names that take value away from an account.
const DEBIT_WORDS: &[&str] = &[
    "spend",
    "debit",
    "burn",
    "withdraw",
    "deduct",
    "decrease",
    "decrement",
    "subtract",
    "charge",
];

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

/// 1-based (line, column) of a span.
pub fn line_col(span: Span) -> (usize, usize) {
    let start = span.start();
    (start.line, start.column + 1)
}

pub fn tokens_to_string(t: &impl ToTokens) -> String {
    t.to_token_stream().to_string()
}

/// True if `name` appears as an identifier anywhere in `tokens`.
pub fn mentions_ident(tokens: TokenStream, name: &str) -> bool {
    tokens.into_iter().any(|tt| match tt {
        TokenTree::Ident(i) => i == name,
        TokenTree::Group(g) => mentions_ident(g.stream(), name),
        _ => false,
    })
}

/// Best-effort parse of macro arguments (`assert!(..)`, `panic!(..)`, ...) as expressions,
/// so storage calls inside common macros are not missed.
pub fn macro_exprs(mac: &Macro) -> Vec<Expr> {
    mac.parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated)
        .map(|p| p.into_iter().collect())
        .unwrap_or_default()
}

/// Resolves calls to crate-local functions: `foo(..)` and `Self::foo(..)` give `foo`,
/// `storage::foo(..)` / `crate::storage::foo(..)` give `storage::foo`.
/// Calls through a type path such as `Vec::new` or `token::Client::new` are not
/// resolved, since they are almost never functions defined in the contract crate.
pub fn local_callee(call: &ExprCall) -> Option<String> {
    let Expr::Path(p) = strip(&call.func) else {
        return None;
    };
    if p.qself.is_some() {
        return None;
    }
    let segs: Vec<String> = p
        .path
        .segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect();
    let (last, prefix) = segs.split_last()?;
    let is_upper = |n: &str| n.chars().next().is_some_and(|c| c.is_uppercase());
    let module_like =
        |n: &String| matches!(n.as_str(), "Self" | "self" | "crate" | "super") || !is_upper(n);
    if prefix.iter().all(module_like) {
        return Some(match prefix.last().map(String::as_str) {
            Some(m) if !matches!(m, "Self" | "self" | "crate" | "super") => format!("{m}::{last}"),
            _ => last.clone(),
        });
    }
    // `Base::update(..)`, `Self::ContractType::transfer(..)`: a call through a type.
    // Resolved later only if the type is defined in the analysed crate.
    let ty = prefix
        .iter()
        .rev()
        .find(|n| is_upper(n) && n.as_str() != "Self")?;
    Some(format!("{ty}::{last}"))
}

/// Module path of the functions defined in `path`, prefixed with the crate
/// (`<crate dir>@@<module path>`), so that crates and same-named files
/// (`a/storage.rs`, `b/storage.rs`) never share functions:
/// `src/lib.rs` -> `crate`, `src/pool/mod.rs` -> `crate::pool`,
/// `src/pool/storage.rs` -> `crate::pool::storage`.
pub fn module_name(path: &std::path::Path) -> String {
    let p = path.to_string_lossy().replace('\\', "/");
    let rel = match p.rfind("/src/") {
        Some(i) => &p[i + 5..],
        None => p
            .strip_prefix("src/")
            .unwrap_or_else(|| p.rsplit('/').next().unwrap_or(&p)),
    };
    let mut parts: Vec<&str> = rel.split('/').collect();
    let file = parts.pop().unwrap_or("lib.rs");
    let stem = file.strip_suffix(".rs").unwrap_or(file);
    let mut module = vec!["crate"];
    module.extend(parts);
    if !matches!(stem, "lib" | "main" | "mod") {
        module.push(stem);
    }
    format!("{}@@{}", crate_dir(path), module.join("::"))
}

/// The crate a source file belongs to: the path before its `src/` directory.
fn crate_dir(path: &std::path::Path) -> String {
    let p = path.to_string_lossy().replace('\\', "/");
    match p.rfind("/src/") {
        Some(i) => p[..i].to_string(),
        None if p.starts_with("src/") => String::new(),
        None => path
            .parent()
            .map(|d| d.to_string_lossy().to_string())
            .unwrap_or_default(),
    }
}

/// The crate part of a function key or module name.
fn crate_of(key: &str) -> &str {
    key.split_once("@@").map_or("", |(c, _)| c)
}

/// Evaluates simple integer constant expressions (`500`, `30 * DAY`, `N as u32`).
pub fn eval_int(expr: &Expr, consts: &HashMap<String, u128>) -> Option<u128> {
    match strip(expr) {
        Expr::Lit(l) => match &l.lit {
            syn::Lit::Int(i) => i.base10_parse().ok(),
            _ => None,
        },
        Expr::Cast(c) => eval_int(&c.expr, consts),
        Expr::Binary(b) => {
            let l = eval_int(&b.left, consts)?;
            let r = eval_int(&b.right, consts)?;
            match b.op {
                BinOp::Add(_) => l.checked_add(r),
                BinOp::Sub(_) => l.checked_sub(r),
                BinOp::Mul(_) => l.checked_mul(r),
                BinOp::Div(_) => l.checked_div(r),
                _ => None,
            }
        }
        e => consts.get(&single_ident(e)?).copied(),
    }
}

fn attr_is(attr: &Attribute, name: &str) -> bool {
    attr.path().segments.last().is_some_and(|s| s.ident == name)
}

pub fn has_attr(attrs: &[Attribute], name: &str) -> bool {
    attrs.iter().any(|a| attr_is(a, name))
}

/// `#[test]`, `#[cfg(test)]`, `#[cfg(any(test, ..))]` — but not `#[cfg(not(test))]`.
pub fn is_test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|a| {
        if attr_is(a, "test") {
            return true;
        }
        if !a.path().is_ident("cfg") {
            return false;
        }
        let tokens = a.meta.to_token_stream();
        mentions_ident(tokens.clone(), "test") && !mentions_ident(tokens, "not")
    })
}

// ---------------------------------------------------------------------------
// Function discovery
// ---------------------------------------------------------------------------

/// A function with a body found in a source file.
#[derive(Debug, Clone)]
pub struct FnDef<'a> {
    /// Module the function is defined in (see [`module_name`]).
    pub module: String,
    pub attrs: &'a [Attribute],
    pub sig: &'a Signature,
    pub block: &'a Block,
    /// True for functions exported by a `#[contractimpl]` block.
    pub is_contract_entry: bool,
}

impl FnDef<'_> {
    pub fn name(&self) -> String {
        self.sig.ident.to_string()
    }

    /// `module::name`, the key used by [`CrateIndex`].
    pub fn key(&self) -> String {
        format!("{}::{}", self.module, self.sig.ident)
    }

    /// Typed parameters as `(name, type source text)`.
    pub fn params(&self) -> Vec<(String, String)> {
        self.sig
            .inputs
            .iter()
            .filter_map(|a| match a {
                syn::FnArg::Typed(t) => match &*t.pat {
                    Pat::Ident(p) => Some((p.ident.to_string(), tokens_to_string(&t.ty))),
                    _ => None,
                },
                syn::FnArg::Receiver(_) => None,
            })
            .collect()
    }

    /// Parameters of type `Address` (by value or reference).
    pub fn address_params(&self) -> Vec<String> {
        self.params()
            .into_iter()
            .filter(|(_, ty)| ty.split_whitespace().last() == Some("Address"))
            .map(|(n, _)| n)
            .collect()
    }

    pub fn line_col(&self) -> (usize, usize) {
        line_col(self.sig.ident.span())
    }
}

/// Collects every non-test function (free functions, impl methods, nested modules).
/// `module` is the module of the file (see [`module_name`]).
pub fn collect_fns<'a>(file: &'a syn::File, module: &str) -> Vec<FnDef<'a>> {
    let mut out = Vec::new();
    collect_items(&file.items, module, &mut out);
    out
}

fn collect_items<'a>(items: &'a [Item], module: &str, out: &mut Vec<FnDef<'a>>) {
    for item in items {
        match item {
            Item::Fn(f) if !is_test_only(&f.attrs) => out.push(FnDef {
                module: module.to_string(),
                attrs: &f.attrs,
                sig: &f.sig,
                block: &f.block,
                is_contract_entry: false,
            }),
            Item::Impl(imp) if !is_test_only(&imp.attrs) => {
                let contract = has_attr(&imp.attrs, "contractimpl");
                let trait_impl = imp.trait_.is_some();
                for ii in &imp.items {
                    if let ImplItem::Fn(m) = ii {
                        if is_test_only(&m.attrs) {
                            continue;
                        }
                        out.push(FnDef {
                            module: module.to_string(),
                            attrs: &m.attrs,
                            sig: &m.sig,
                            block: &m.block,
                            is_contract_entry: contract
                                && (trait_impl || matches!(m.vis, Visibility::Public(_))),
                        });
                    }
                }
            }
            // Default methods of `#[contracttrait]` traits are exported by every contract
            // that implements the trait (the OpenZeppelin Stellar pattern).
            Item::Trait(t) if !is_test_only(&t.attrs) => {
                let contract = has_attr(&t.attrs, "contracttrait");
                for ti in &t.items {
                    if let syn::TraitItem::Fn(m) = ti {
                        if let Some(block) = &m.default {
                            if !is_test_only(&m.attrs) {
                                out.push(FnDef {
                                    module: module.to_string(),
                                    attrs: &m.attrs,
                                    sig: &m.sig,
                                    block,
                                    is_contract_entry: contract,
                                });
                            }
                        }
                    }
                }
            }
            Item::Mod(m) if !is_test_only(&m.attrs) => {
                if let Some((_, items)) = &m.content {
                    let inner = format!("{module}::{}", m.ident);
                    collect_items(items, &inner, out);
                }
            }
            _ => {}
        }
    }
}

/// Names of types defined in the crate (structs, enums, traits, aliases and
/// associated types), used to resolve `Type::function(..)` calls.
/// Type name -> crates defining it.
type TypeMap = HashMap<String, std::collections::BTreeSet<String>>;

fn collect_types(items: &[Item], krate: &str, out: &mut TypeMap) {
    fn add(out: &mut TypeMap, name: String, krate: &str) {
        out.entry(name).or_default().insert(krate.to_string());
    }
    for item in items {
        match item {
            Item::Struct(s) => add(out, s.ident.to_string(), krate),
            Item::Enum(e) => add(out, e.ident.to_string(), krate),
            Item::Type(t) => add(out, t.ident.to_string(), krate),
            Item::Trait(t) => {
                add(out, t.ident.to_string(), krate);
                for ti in &t.items {
                    if let syn::TraitItem::Type(at) = ti {
                        add(out, at.ident.to_string(), krate);
                    }
                }
            }
            Item::Mod(m) => {
                if let Some((_, items)) = &m.content {
                    collect_types(items, krate, out);
                }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Per-function facts
// ---------------------------------------------------------------------------

/// Signature-verification host functions that do not contain "verify" in their name.
const VERIFY_FNS: &[&str] = &["secp256k1_recover", "pairing_check"];

/// True for calls that verify a signature: host functions such as `ed25519_verify`,
/// `secp256r1_verify`, BLS `pairing_check`, or helpers like `webauthn::verify`.
fn is_verify_call(name: &str) -> bool {
    name.contains("verify") || VERIFY_FNS.contains(&name)
}

/// What a function does directly (not counting callees).
#[derive(Debug, Clone, Default)]
pub struct FnFacts {
    /// Module of the function, used to resolve unqualified calls.
    pub module: String,
    /// `module::name` of the function.
    pub key: String,
    pub storage_calls: Vec<StorageCall>,
    /// Names of crate-local functions this function calls.
    pub callees: Vec<String>,
    pub requires_auth: bool,
    pub upgrades: bool,
    pub publishes_event: bool,
    pub verifies_signature: bool,
    /// Receivers of `require_auth*` calls that are plain variables (`caller.require_auth()`).
    pub auth_targets: Vec<(String, (usize, usize))>,
    /// Auth not on a plain variable: `read_admin(&e).require_auth()`, or an auth attribute.
    pub other_auth: bool,
    /// Forwards authorization to other accounts (`custom_account().delegate_auth(..)`).
    pub delegates_auth: bool,
    /// Calls to crate-local functions, with argument details.
    pub call_sites: Vec<CallSite>,
    /// Locations of `storage.get(..).unwrap()` / `.expect(..)`.
    pub unwrapped_gets: Vec<(usize, usize)>,
    pub bindings: Bindings,
}

pub fn scan_block(block: &Block) -> FnFacts {
    let mut s = Scanner::default();
    s.visit_block(block);
    s.facts
}

/// Access-control attribute macros that expand to `require_auth`
/// (e.g. OpenZeppelin Stellar `#[only_owner]`, `#[only_role(caller, "minter")]`).
pub fn is_auth_attr(attr: &Attribute) -> bool {
    attr.path().segments.last().is_some_and(|s| {
        let n = s.ident.to_string();
        n.starts_with("only_") || matches!(n.as_str(), "has_role" | "has_any_role" | "require_auth")
    })
}

/// Facts for a function, including auth implied by its attributes.
pub fn scan_fn(f: &FnDef<'_>) -> FnFacts {
    let mut facts = scan_block(f.block);
    facts.module = f.module.clone();
    facts.key = f.key();
    if f.attrs.iter().any(is_auth_attr) {
        facts.requires_auth = true;
        facts.other_auth = true;
    }
    facts
}

#[derive(Default)]
struct Scanner {
    facts: FnFacts,
}

impl Scanner {
    fn bind(&mut self, pat: &Pat, init: &Expr) {
        let name = match pat {
            Pat::Ident(p) => p.ident.to_string(),
            Pat::Type(t) => return self.bind(&t.pat, init),
            _ => return,
        };
        let b = &self.facts.bindings;
        let binding = if is_storage_handle(init, b) {
            Some(Binding::Storage)
        } else if let Some(k) = storage_kind(init, b) {
            Some(Binding::Kind(k))
        } else if matches!(strip(init), Expr::Call(_) | Expr::Path(_) | Expr::Struct(_)) {
            Some(Binding::Key {
                text: tokens_to_string(strip(init)),
                parameterized: is_parameterized_key(init),
            })
        } else {
            None
        };
        match binding {
            Some(binding) => self.facts.bindings.0.insert(name, binding),
            // Shadowing with something unrelated forgets the old binding.
            None => self.facts.bindings.0.remove(&name),
        };
    }
}

impl<'ast> Visit<'ast> for Scanner {
    fn visit_local(&mut self, l: &'ast Local) {
        visit::visit_local(self, l);
        if let Some(init) = &l.init {
            self.bind(&l.pat, &init.expr);
        }
    }

    fn visit_expr_method_call(&mut self, m: &'ast ExprMethodCall) {
        let name = m.method.to_string();
        match name.as_str() {
            "publish" => self.facts.publishes_event = true,
            "require_auth" | "require_auth_for_args" => {
                self.facts.requires_auth = true;
                match single_ident(&m.receiver) {
                    Some(id) => self
                        .facts
                        .auth_targets
                        .push((id, line_col(m.method.span()))),
                    // e.g. `read_admin(&e).require_auth()`
                    None => self.facts.other_auth = true,
                }
            }
            // `update_current_contract(ContractExecutable::Wasm(..))` is the newer SDK API.
            "update_current_contract_wasm" | "update_current_contract" => {
                self.facts.upgrades = true
            }
            "delegate_auth" => self.facts.delegates_auth = true,
            n if is_verify_call(n) => self.facts.verifies_signature = true,
            "unwrap" | "expect" => {
                if let Expr::MethodCall(inner) = strip(&m.receiver) {
                    if inner.method == "get" && storage_call(inner, &self.facts.bindings).is_some()
                    {
                        self.facts.unwrapped_gets.push(line_col(m.method.span()));
                    }
                }
            }
            _ => {}
        }
        if let Some(call) = storage_call(m, &self.facts.bindings) {
            self.facts.storage_calls.push(call);
        }
        visit::visit_expr_method_call(self, m);
    }

    fn visit_expr_call(&mut self, c: &'ast ExprCall) {
        if let Expr::Path(p) = strip(&c.func) {
            if p.path
                .segments
                .last()
                .is_some_and(|s| is_verify_call(&s.ident.to_string()))
            {
                self.facts.verifies_signature = true;
            }
        }
        if let Some(name) = local_callee(c) {
            self.facts.call_sites.push(CallSite {
                callee: name.clone(),
                args: c
                    .args
                    .iter()
                    .map(|a| {
                        let ident = plain_ident(a);
                        let key_text =
                            match ident.as_ref().and_then(|id| self.facts.bindings.0.get(id)) {
                                Some(Binding::Key { text, .. }) => text.clone(),
                                _ => tokens_to_string(a),
                            };
                        CallArg {
                            ident,
                            subtracts: subtracts(a),
                            key_text,
                        }
                    })
                    .collect(),
            });
            self.facts.callees.push(name);
        }
        visit::visit_expr_call(self, c);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        for e in macro_exprs(mac) {
            Visit::visit_expr(self, &e);
        }
    }
}

// ---------------------------------------------------------------------------
// Crate-wide index (transitive effects)
// ---------------------------------------------------------------------------

/// Key words that mark a storage key as controlling who may do what.
pub const AUTHORITY_KEYWORDS: &[&str] = &[
    "admin", "owner", "operator", "minter", "signer", "manager", "governor", "guardian", "setter",
];

/// Key words that mark allowance-style delegated spending.
const ALLOWANCE_KEYWORDS: &[&str] = &["allowance", "approv"];

/// Words of a key expression without path qualifiers:
/// `GovernorDataKey :: Proposal (id)` -> `["proposal", "id"]`.
pub fn key_words(key: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut rest = key;
    while !rest.is_empty() {
        let start = rest
            .find(|c: char| c.is_alphanumeric() || c == '_')
            .unwrap_or(rest.len());
        rest = &rest[start..];
        let end = rest
            .find(|c: char| !(c.is_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        let word = &rest[..end];
        rest = &rest[end..];
        // Skip `Type ::` qualifiers.
        if !rest.trim_start().starts_with("::") && !word.is_empty() {
            words.push(word.to_lowercase());
        }
    }
    words
}

fn is_authority_key(key: &str) -> bool {
    key_words(key)
        .iter()
        .any(|w| AUTHORITY_KEYWORDS.iter().any(|k| w.contains(k)))
}

/// Effects of a function including everything it (transitively) calls.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Effects {
    pub requires_auth: bool,
    pub mutates_storage: bool,
    pub touches_storage: bool,
    /// Writes persistent or temporary entries (which carry their own TTL).
    pub writes_entry_storage: bool,
    /// Extends the TTL of persistent or temporary entries.
    pub extends_entry_ttl: bool,
    pub upgrades: bool,
    pub publishes_event: bool,
    pub verifies_signature: bool,
    pub delegates_auth: bool,
    /// Writes a key such as `DataKey::Admin` / `Owner`.
    pub writes_authority_key: bool,
    /// Reads a key such as `DataKey::Admin` / `Owner`.
    pub reads_authority_key: bool,
    /// Touches allowance/approval storage (delegated spending).
    pub uses_allowance: bool,
}

impl Effects {
    pub fn direct(f: &FnFacts) -> Self {
        let entry = |c: &&StorageCall| c.kind != StorageKind::Instance;
        Effects {
            requires_auth: f.requires_auth,
            mutates_storage: f.storage_calls.iter().any(|c| c.op.is_mutation()),
            touches_storage: !f.storage_calls.is_empty(),
            writes_entry_storage: f
                .storage_calls
                .iter()
                .filter(entry)
                .any(|c| c.op == StorageOp::Write),
            extends_entry_ttl: f
                .storage_calls
                .iter()
                .filter(entry)
                .any(|c| c.op == StorageOp::ExtendTtl),
            upgrades: f.upgrades,
            publishes_event: f.publishes_event,
            verifies_signature: f.verifies_signature,
            delegates_auth: f.delegates_auth,
            writes_authority_key: f
                .storage_calls
                .iter()
                .filter(|c| c.op == StorageOp::Write)
                .any(|c| c.key.as_deref().is_some_and(is_authority_key)),
            reads_authority_key: f
                .storage_calls
                .iter()
                .filter(|c| c.op == StorageOp::Read)
                .any(|c| c.key.as_deref().is_some_and(is_authority_key)),
            uses_allowance: f.storage_calls.iter().any(|c| {
                c.key.as_deref().is_some_and(|k| {
                    let k = k.to_lowercase();
                    ALLOWANCE_KEYWORDS.iter().any(|w| k.contains(w))
                })
            }),
        }
    }

    /// Ors `other` into `self`; returns true if anything changed.
    fn merge(&mut self, o: Effects) -> bool {
        let before = *self;
        self.requires_auth |= o.requires_auth;
        self.mutates_storage |= o.mutates_storage;
        self.touches_storage |= o.touches_storage;
        self.writes_entry_storage |= o.writes_entry_storage;
        self.extends_entry_ttl |= o.extends_entry_ttl;
        self.upgrades |= o.upgrades;
        self.publishes_event |= o.publishes_event;
        self.verifies_signature |= o.verifies_signature;
        self.delegates_auth |= o.delegates_auth;
        self.writes_authority_key |= o.writes_authority_key;
        self.reads_authority_key |= o.reads_authority_key;
        self.uses_allowance |= o.uses_allowance;
        before != *self
    }
}

/// Crate-wide facts about every function.
///
/// Each function is stored under `module::name`. Calls are resolved to the exact
/// function when the module is known (`storage::read(..)`, or an unqualified call to a
/// function in the caller's own module); otherwise all functions with that name are
/// merged.
#[derive(Debug, Default)]
pub struct CrateIndex {
    effects: HashMap<String, Effects>,
    /// Per function, per typed parameter: is it range-checked here or in a callee?
    validated: HashMap<String, Vec<bool>>,
    /// Per function, per typed parameter: does the call take value from that address/id?
    debited: HashMap<String, Vec<bool>>,
    /// Per function, per typed parameter: is `require_auth` called on it (here or in a callee)?
    authorized: HashMap<String, Vec<bool>>,
    /// Per function: persistent/temporary key variants written and TTL-extended (transitive).
    ttl: HashMap<String, TtlKeys>,
    /// Call resolution (types defined in the analysed crates, cache).
    resolver: Resolver,
    /// Key variants extended somewhere in the analysed code (e.g. on read).
    extended_anywhere: std::collections::BTreeSet<String>,
    /// Integer constants (`const MAX: u32 = 100;`) usable as loop bounds.
    pub consts: HashMap<String, u128>,
}

/// Persistent/temporary keys a function writes and extends, by key variant
/// (`DataKey::Balance(id)` -> `DataKey::Balance`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TtlKeys {
    pub written: std::collections::BTreeSet<String>,
    pub extended: std::collections::BTreeSet<String>,
}

/// Direct TTL facts of one function.
struct DirectTtl {
    keys: TtlKeys,
    /// Parameter `i` is used as the key of a persistent/temporary write.
    writes_param: Vec<bool>,
    /// Parameter `i` is used as the key of an `extend_ttl`.
    extends_param: Vec<bool>,
}

impl TtlKeys {
    fn direct(facts: &FnFacts, params: &[String]) -> DirectTtl {
        let krate = crate_of(&facts.key);
        let mut d = DirectTtl {
            keys: TtlKeys::default(),
            writes_param: vec![false; params.len()],
            extends_param: vec![false; params.len()],
        };
        for c in &facts.storage_calls {
            if c.kind == StorageKind::Instance {
                continue;
            }
            let Some(key) = c.key.as_deref() else {
                continue;
            };
            // `&key`, `key.clone()`: the key is a parameter of this function
            // (a generic `write(e, key, v)` / `extend(e, key)` helper).
            let plain = key
                .trim_start_matches(['&', ' '])
                .trim_end_matches(". clone ()")
                .trim();
            let param = params.iter().position(|p| plain == p);
            match (c.op, param) {
                (StorageOp::Write, Some(i)) => d.writes_param[i] = true,
                (StorageOp::ExtendTtl, Some(i)) => d.extends_param[i] = true,
                (StorageOp::Write, None) => d.keys.written.extend(crate_variant(krate, key)),
                (StorageOp::ExtendTtl, None) => d.keys.extended.extend(crate_variant(krate, key)),
                _ => {}
            }
        }
        d
    }

    fn merge(&mut self, o: &TtlKeys) -> bool {
        let before = (self.written.len(), self.extended.len());
        self.written.extend(o.written.iter().cloned());
        self.extended.extend(o.extended.iter().cloned());
        before != (self.written.len(), self.extended.len())
    }

    /// Written variants that are never extended.
    pub fn unextended(&self) -> Vec<&str> {
        self.written
            .difference(&self.extended)
            .map(String::as_str)
            .collect()
    }
}

/// Identifies a storage key independent of its runtime arguments:
/// `DataKey::Balance(id)` -> `DataKey::Balance`, `&COUNTER` -> `COUNTER`,
/// `Symbol::new(e, ADMIN_KEY)` -> `ADMIN_KEY`.
fn key_variant(key: &str) -> Option<String> {
    let text = key.trim_start_matches(['&', ' ']);
    // Leading path: `A :: B :: C`.
    let head = text.split(['(', '{', ' ']).collect::<Vec<_>>();
    let mut path: Vec<&str> = Vec::new();
    let mut expect_ident = true;
    for tok in head.iter().filter(|t| !t.is_empty()) {
        if expect_ident && tok.chars().all(|c| c.is_alphanumeric() || c == '_') {
            path.push(tok);
            expect_ident = false;
        } else if !expect_ident && *tok == "::" {
            expect_ident = true;
        } else {
            break;
        }
    }
    let last = path.last()?;
    // A constructor such as `Symbol::new(e, KEY)`: the constant argument is the key.
    if last.chars().next().is_some_and(|c| c.is_lowercase()) && path.len() > 1 {
        return key_words(text)
            .into_iter()
            .zip(
                text.split(|c: char| !(c.is_alphanumeric() || c == '_'))
                    .filter(|w| !w.is_empty()),
            )
            .find(|(_, orig)| {
                orig.chars()
                    .all(|c| c.is_uppercase() || c == '_' || c.is_ascii_digit())
                    && orig.len() > 1
            })
            .map(|(_, orig)| orig.to_string())
            .or_else(|| Some(path.join("::")));
    }
    let n = path.len();
    Some(path[n.saturating_sub(2)..].join("::"))
}

/// A key variant scoped to the crate whose code uses it (two crates may both define
/// `DataKey::Balance`): `<crate>|DataKey::Balance`.
fn crate_variant(krate: &str, key: &str) -> Option<String> {
    key_variant(key).map(|v| format!("{krate}|{v}"))
}

/// The last segment of a key variant, for messages.
pub fn short_variant(v: &str) -> &str {
    let v = v.rsplit_once('|').map_or(v, |(_, v)| v);
    v.rsplit("::").next().unwrap_or(v)
}

fn bare_name(callee: &str) -> &str {
    callee.rsplit("::").next().unwrap_or(callee)
}

/// Where a call resolves to: one function's key, or a merged by-name key.
#[derive(Debug, Clone)]
enum Target {
    Key(String),
    Name(String),
}

/// Resolves `callee` (as returned by [`local_callee`]) called from `caller`, mirroring
/// Rust's rules where it can:
///
/// - `f`: the same module, then functions named `f` (same crate first).
/// - `m::f`: child or sibling module `m`, any module `m` in the crate, any module `m`
///   anywhere (re-exported directories such as `pausable/storage.rs`), then by name.
/// - `Type::f`: functions named `f` in the crate(s) defining `Type`; unresolved if
///   `Type` is not defined in the analysed code (`Vec::new`, `TokenClient::new`).
/// - A call that would resolve to the caller itself is almost always a same-named
///   function elsewhere (`governor::execute` called from a contract's own `execute`),
///   so it falls back to all functions with that name.
///
/// Independent of which facts are looked up (every fact map has the same keys):
/// `has_key` / `has_name` tell which keys exist.
fn resolve_target(
    has_key: &dyn Fn(&str) -> bool,
    has_name: &dyn Fn(&str) -> bool,
    types: &TypeMap,
    caller: &FnFacts,
    callee: &str,
) -> Option<Target> {
    let (qualifier, name) = match callee.rsplit_once("::") {
        Some((q, n)) => (Some(q), n),
        None => (None, callee),
    };
    let krate = crate_of(&caller.key);
    let key = |k: String| has_key(&k).then_some(Target::Key(k));
    let named = |k: String| has_name(&k).then_some(Target::Name(k));
    // A call with the caller's own name is almost always to a same-named function in
    // another crate (a contract's `set_limit` calling `module::set_limit` of a library).
    let calls_own_name = bare_name(&caller.key) == name;
    // Same-crate functions with this name first, then any crate (e.g. a library).
    let by_name_lookup = || {
        if calls_own_name {
            return named(name.to_string());
        }
        named(crate_name_key(krate, name)).or_else(|| named(name.to_string()))
    };

    match qualifier {
        // `Type::f(..)`: look in the crate(s) defining the type. Skip the caller's own
        // crate when that would just find the caller (`fn transfer` -> `Base::transfer`).
        Some(q) if q.chars().next().is_some_and(|c| c.is_uppercase()) => {
            let crates = types.get(q)?;
            crates
                .iter()
                .filter(|c| !(c.as_str() == krate && calls_own_name))
                .find_map(|c| named(crate_name_key(c, name)))
                .or_else(|| named(name.to_string()))
        }
        // `m::f(..)`: child module, sibling module, any module `m` in this crate,
        // any module `m` anywhere, then by name.
        Some(q) => {
            let module = caller.module.as_str();
            let parent = module.rsplit_once("::").map_or(module, |(p, _)| p);
            [
                format!("{module}::{q}::{name}"),
                format!("{parent}::{q}::{name}"),
            ]
            .into_iter()
            .filter(|k| *k != caller.key)
            .find_map(key)
            .or_else(|| {
                // In this crate, a same-named function is usually the caller itself.
                (!calls_own_name)
                    .then(|| named(crate_module_key(krate, q, name)))
                    .flatten()
            })
            .or_else(|| named(module_global_key(q, name)))
            .or_else(by_name_lookup)
        }
        // `f(..)`: same module, then by name.
        None => {
            let exact = format!("{}::{callee}", caller.module);
            if exact == caller.key {
                return named(name.to_string());
            }
            key(exact).or_else(by_name_lookup)
        }
    }
}

/// Resolves calls, caching results per `(caller, callee)`.
#[derive(Debug, Default)]
struct Resolver {
    keys: std::collections::HashSet<String>,
    names: std::collections::HashSet<String>,
    types: TypeMap,
    cache: std::cell::RefCell<HashMap<String, HashMap<String, Option<Target>>>>,
}

impl Resolver {
    fn target(&self, caller: &FnFacts, callee: &str) -> Option<Target> {
        if let Some(t) = self
            .cache
            .borrow()
            .get(&caller.key)
            .and_then(|m| m.get(callee))
        {
            return t.clone();
        }
        let t = resolve_target(
            &|k| self.keys.contains(k),
            &|n| self.names.contains(n),
            &self.types,
            caller,
            callee,
        );
        self.cache
            .borrow_mut()
            .entry(caller.key.clone())
            .or_default()
            .insert(callee.to_string(), t.clone());
        t
    }

    /// Looks `callee` up in a fact map (`by_key`) and its merged by-name view.
    fn get<'m, V>(
        &self,
        by_key: &'m HashMap<String, V>,
        by_name: &'m HashMap<String, V>,
        caller: &FnFacts,
        callee: &str,
    ) -> Option<&'m V> {
        match self.target(caller, callee)? {
            Target::Key(k) => by_key.get(&k),
            Target::Name(n) => by_name.get(&n),
        }
    }
}

fn crate_name_key(krate: &str, name: &str) -> String {
    format!("{krate}@@#{name}")
}

/// Keys under which a function's facts are merged with same-named functions:
/// within its crate, and globally.
/// Per function key, the keys it is merged under with same-named functions:
/// same crate (`<crate>@@#f`), any crate (`f`), and module aliases
/// (`@@pausable::f`, `<crate>@@~pausable::f`). Computed once per index build.
type Aliases = HashMap<String, Vec<String>>;

fn name_keys<'a>(key: &str, aliases: &'a Aliases) -> &'a [String] {
    aliases.get(key).map_or(&[], Vec::as_slice)
}

fn module_global_key(module: &str, name: &str) -> String {
    format!("@@{module}::{name}")
}

fn crate_module_key(krate: &str, module: &str, name: &str) -> String {
    format!("{krate}@@~{module}::{name}")
}

/// Short module names a file's functions are reachable under: the file's own module and,
/// for files inside a module directory (`pausable/storage.rs`), that directory's module,
/// which commonly re-exports them (`pub use storage::*`).
fn module_aliases(path: &std::path::Path) -> Vec<String> {
    let module = module_name(path);
    let segments: Vec<&str> = module
        .split_once("@@")
        .map_or(module.as_str(), |(_, m)| m)
        .split("::")
        .collect();
    segments
        .iter()
        .rev()
        .take(2)
        .filter(|s| **s != "crate")
        .map(|s| s.to_string())
        .collect()
}

fn merge_effects_by_name(
    by_key: &HashMap<String, Effects>,
    aliases: &Aliases,
) -> HashMap<String, Effects> {
    let mut out: HashMap<String, Effects> = HashMap::new();
    for (k, e) in by_key {
        for nk in name_keys(k, aliases) {
            out.entry(nk.clone()).or_default().merge(*e);
        }
    }
    out
}

fn merge_flags_by_name(
    by_key: &HashMap<String, Vec<bool>>,
    aliases: &Aliases,
) -> HashMap<String, Vec<bool>> {
    let mut out: HashMap<String, Vec<bool>> = HashMap::new();
    for (k, v) in by_key {
        for nk in name_keys(k, aliases) {
            let o = out.entry(nk.clone()).or_default();
            o.resize(o.len().max(v.len()), false);
            for (i, b) in v.iter().enumerate() {
                o[i] |= b;
            }
        }
    }
    out
}

fn flag(map: &HashMap<String, Vec<bool>>, key: &str, pos: usize) -> bool {
    map.get(key)
        .and_then(|v| v.get(pos))
        .copied()
        .unwrap_or(false)
}

struct IndexedFn {
    key: String,
    params: Vec<String>,
    facts: FnFacts,
}

impl CrateIndex {
    pub fn build<'a>(
        files: impl IntoIterator<Item = (&'a std::path::Path, &'a syn::File)>,
    ) -> Self {
        let mut fns: Vec<IndexedFn> = Vec::new();
        let mut const_exprs = Vec::new();
        let mut effects: HashMap<String, Effects> = HashMap::new();
        let mut validated: HashMap<String, Vec<bool>> = HashMap::new();
        let mut authorized: HashMap<String, Vec<bool>> = HashMap::new();
        let mut ttl: HashMap<String, TtlKeys> = HashMap::new();
        let mut writes_key: HashMap<String, Vec<bool>> = HashMap::new();
        let mut extends_key: HashMap<String, Vec<bool>> = HashMap::new();
        let mut types = TypeMap::new();
        let mut aliases = Aliases::new();

        for (path, file) in files {
            let file_aliases = module_aliases(path);
            collect_types(&file.items, &crate_dir(path), &mut types);
            for f in collect_fns(file, &module_name(path)) {
                let facts = scan_fn(&f);
                let key = f.key();
                let params: Vec<String> = f.params().into_iter().map(|(p, _)| p).collect();
                effects
                    .entry(key.clone())
                    .or_default()
                    .merge(Effects::direct(&facts));
                for (map, direct) in [
                    (
                        &mut validated,
                        params
                            .iter()
                            .map(|p| param_use(f.block, p).validated)
                            .collect::<Vec<_>>(),
                    ),
                    (
                        &mut authorized,
                        params
                            .iter()
                            .map(|p| facts.auth_targets.iter().any(|(t, _)| t == p))
                            .collect(),
                    ),
                ] {
                    let v = map.entry(key.clone()).or_default();
                    v.resize(v.len().max(direct.len()), false);
                    for (i, d) in direct.into_iter().enumerate() {
                        v[i] |= d;
                    }
                }
                let direct_ttl = TtlKeys::direct(&facts, &params);
                ttl.entry(key.clone()).or_default().merge(&direct_ttl.keys);
                for (map, direct) in [
                    (&mut writes_key, direct_ttl.writes_param),
                    (&mut extends_key, direct_ttl.extends_param),
                ] {
                    let v = map.entry(key.clone()).or_default();
                    v.resize(v.len().max(direct.len()), false);
                    for (i, d) in direct.into_iter().enumerate() {
                        v[i] |= d;
                    }
                }
                let krate = crate_dir(path);
                let name = f.name();
                let mut keys = vec![crate_name_key(&krate, &name), name.clone()];
                for m in &file_aliases {
                    keys.push(module_global_key(m, &name));
                    keys.push(crate_module_key(&krate, m, &name));
                }
                aliases.insert(key.clone(), keys);
                fns.push(IndexedFn { key, params, facts });
            }
            collect_consts(&file.items, &mut const_exprs);
        }

        let resolver = Resolver {
            keys: fns.iter().map(|f| f.key.clone()).collect(),
            names: aliases.values().flatten().cloned().collect(),
            types,
            cache: Default::default(),
        };

        // Propagate effects from callees to callers until nothing changes. Facts only
        // grow, so the merged by-name view is updated incrementally.
        let mut effects_by_name = merge_effects_by_name(&effects, &aliases);
        loop {
            let mut changed = false;
            for f in &fns {
                let mut acc = effects[&f.key];
                for c in &f.facts.callees {
                    if let Some(e) = resolver.get(&effects, &effects_by_name, &f.facts, c) {
                        acc.merge(*e);
                    }
                }
                if effects.get_mut(&f.key).unwrap().merge(acc) {
                    changed = true;
                    let new = effects[&f.key];
                    for nk in name_keys(&f.key, &aliases) {
                        effects_by_name.entry(nk.clone()).or_default().merge(new);
                    }
                }
            }
            if !changed {
                break;
            }
        }

        // Direct debits: value taken from an account identified by a parameter.
        let mut debited: HashMap<String, Vec<bool>> = HashMap::new();
        for f in &fns {
            let d = debited.entry(f.key.clone()).or_default();
            d.resize(d.len().max(f.params.len()), false);
            for (i, p) in f.params.iter().enumerate() {
                let storage_debit =
                    f.facts.storage_calls.iter().any(|c| {
                        c.op == StorageOp::Write && c.value_subtracts && c.key_mentions(p)
                    });
                let call_debit = f.facts.call_sites.iter().any(|cs| {
                    let passes_p = cs.args.iter().any(|a| a.ident.as_deref() == Some(p));
                    let callee = bare_name(&cs.callee).to_lowercase();
                    let mutates = resolver
                        .get(&effects, &effects_by_name, &f.facts, &cs.callee)
                        .is_some_and(|e| e.mutates_storage);
                    // A debit-named helper (`spend_balance`) or a write with a subtracted
                    // value (`write_balance(id, b - amount)`); either must change storage.
                    passes_p
                        && mutates
                        && (DEBIT_WORDS.iter().any(|w| callee.contains(w))
                            || cs.args.iter().any(|a| a.subtracts))
                });
                d[i] |= storage_debit || call_debit;
            }
        }

        // Propagate parameter properties through calls that forward the parameter:
        // validated / debited / authorized in a helper => same for the caller.
        for map in [
            &mut validated,
            &mut debited,
            &mut authorized,
            &mut writes_key,
            &mut extends_key,
        ] {
            let mut by_name = merge_flags_by_name(map, &aliases);
            loop {
                let mut changed = false;
                for f in &fns {
                    for (i, p) in f.params.iter().enumerate() {
                        if flag(map, &f.key, i) {
                            continue;
                        }
                        let hit = f.facts.call_sites.iter().any(|cs| {
                            cs.args.iter().enumerate().any(|(pos, a)| {
                                a.ident.as_deref() == Some(p)
                                    && resolver
                                        .get(map, &by_name, &f.facts, &cs.callee)
                                        .and_then(|v| v.get(pos))
                                        .copied()
                                        .unwrap_or(false)
                            })
                        });
                        if hit {
                            map.get_mut(&f.key).unwrap()[i] = true;
                            for nk in name_keys(&f.key, &aliases) {
                                let v = by_name.entry(nk.clone()).or_default();
                                v.resize(v.len().max(i + 1), false);
                                v[i] = true;
                            }
                            changed = true;
                        }
                    }
                }
                if !changed {
                    break;
                }
            }
        }

        // Keys handed to generic write/extend helpers count for the caller:
        // `extend(e, &DataKey::Balance(id))` extends `DataKey::Balance`.
        {
            let wk_name = merge_flags_by_name(&writes_key, &aliases);
            let ek_name = merge_flags_by_name(&extends_key, &aliases);
            for f in &fns {
                let t = ttl.get_mut(&f.key).unwrap();
                for cs in &f.facts.call_sites {
                    for (pos, a) in cs.args.iter().enumerate() {
                        // Forwarding our own parameter is covered by the flags above.
                        if a.ident.as_ref().is_some_and(|i| f.params.contains(i)) {
                            continue;
                        }
                        let hit =
                            |m: &HashMap<String, Vec<bool>>, n: &HashMap<String, Vec<bool>>| {
                                resolver
                                    .get(m, n, &f.facts, &cs.callee)
                                    .and_then(|v| v.get(pos))
                                    .copied()
                                    .unwrap_or(false)
                            };
                        let krate = crate_of(&f.key);
                        if hit(&writes_key, &wk_name) {
                            t.written.extend(crate_variant(krate, &a.key_text));
                        }
                        if hit(&extends_key, &ek_name) {
                            t.extended.extend(crate_variant(krate, &a.key_text));
                        }
                    }
                }
            }
        }

        // Same for TTL key sets.
        let merge_ttl = |by_key: &HashMap<String, TtlKeys>| {
            let mut out: HashMap<String, TtlKeys> = HashMap::new();
            for (k, t) in by_key {
                for nk in name_keys(k, &aliases) {
                    out.entry(nk.clone()).or_default().merge(t);
                }
            }
            out
        };
        let mut ttl_by_name = merge_ttl(&ttl);
        loop {
            let mut changed = false;
            for f in &fns {
                let mut acc = ttl[&f.key].clone();
                for c in &f.facts.callees {
                    if let Some(t) = resolver.get(&ttl, &ttl_by_name, &f.facts, c) {
                        acc.merge(t);
                    }
                }
                if ttl.get_mut(&f.key).unwrap().merge(&acc) {
                    changed = true;
                    for nk in name_keys(&f.key, &aliases) {
                        ttl_by_name.entry(nk.clone()).or_default().merge(&acc);
                    }
                }
            }
            if !changed {
                break;
            }
        }

        // Constants may refer to each other; a few passes resolve the chains.
        let mut consts = HashMap::new();
        for _ in 0..4 {
            for (name, expr) in &const_exprs {
                if let Some(v) = eval_int(expr, &consts) {
                    consts.insert(name.clone(), v);
                }
            }
        }

        // Also expose merged-by-name entries for lookups without a module.
        effects.extend(effects_by_name);
        for map in [&mut validated, &mut debited, &mut authorized] {
            let by_name = merge_flags_by_name(map, &aliases);
            map.extend(by_name);
        }

        CrateIndex {
            effects,
            validated,
            debited,
            authorized,
            extended_anywhere: ttl
                .values()
                .flat_map(|t| t.extended.iter().cloned())
                .collect(),
            ttl,
            resolver,
            consts,
        }
    }

    /// Transitive effects of `callee` (as returned by [`local_callee`]) called from `caller`.
    pub fn effects_of(&self, caller: &FnFacts, callee: &str) -> Effects {
        self.resolver
            .get(&self.effects, &self.effects, caller, callee)
            .copied()
            .unwrap_or_default()
    }

    /// Whether some code path extends the TTL of this key variant (e.g. extend-on-read
    /// in a getter), even if not the path that writes it.
    pub fn extended_anywhere(&self, variant: &str) -> bool {
        self.extended_anywhere.contains(variant)
    }

    /// Persistent/temporary keys written and extended by function `key`, transitively.
    pub fn ttl_keys(&self, key: &str) -> TtlKeys {
        self.ttl.get(key).cloned().unwrap_or_default()
    }

    /// Whether parameter `pos` of function `key` (`module::name`) is range-checked,
    /// directly or in a callee.
    pub fn validates_param(&self, key: &str, pos: usize) -> bool {
        flag(&self.validated, key, pos)
    }

    /// Whether calling `key` takes value from the account/id given as parameter `pos`
    /// (directly or in a helper).
    pub fn debits_param(&self, key: &str, pos: usize) -> bool {
        flag(&self.debited, key, pos)
    }

    /// Whether `require_auth` is called on parameter `pos` of `key` (directly or in a helper).
    pub fn authorizes_param(&self, key: &str, pos: usize) -> bool {
        flag(&self.authorized, key, pos)
    }

    /// True if every `require_auth` reachable from function `key` is on one of its own
    /// parameters (addresses the caller chose) that is never compared with anything or
    /// passed to a `check_*`/`require_*` helper.
    pub fn auth_only_on_unchecked_params(
        &self,
        key: &str,
        facts: &FnFacts,
        params: &[String],
    ) -> bool {
        let unchecked_param = |t: &String| {
            params
                .iter()
                .position(|p| p == t)
                .is_some_and(|i| !self.validates_param(key, i))
        };
        !facts.auth_targets.is_empty()
            && !facts.other_auth
            && facts.auth_targets.iter().all(|(t, _)| unchecked_param(t))
            && !facts
                .callees
                .iter()
                .any(|c| self.effects_of(facts, c).requires_auth)
    }

    /// Transitive effects of a specific function body.
    pub fn transitive(&self, facts: &FnFacts) -> Effects {
        let mut e = Effects::direct(facts);
        for c in &facts.callees {
            e.merge(self.effects_of(facts, c));
        }
        e
    }
}

fn collect_consts(items: &[Item], out: &mut Vec<(String, Expr)>) {
    for item in items {
        match item {
            Item::Const(c) => out.push((c.ident.to_string(), (*c.expr).clone())),
            Item::Mod(m) => {
                if let Some((_, items)) = &m.content {
                    collect_consts(items, out);
                }
            }
            Item::Impl(imp) => {
                for ii in &imp.items {
                    if let ImplItem::Const(c) = ii {
                        out.push((c.ident.to_string(), c.expr.clone()));
                    }
                }
            }
            _ => {}
        }
    }
}

/// Number of iterations of a `for` loop / iterator, if statically known.
pub fn loop_bound(expr: &Expr, consts: &HashMap<String, u128>) -> Option<u128> {
    match strip(expr) {
        Expr::Range(r) => {
            let start = match &r.start {
                Some(s) => eval_int(s, consts)?,
                None => 0,
            };
            let end = eval_int(r.end.as_deref()?, consts)?;
            let n = end.saturating_sub(start);
            Some(match r.limits {
                RangeLimits::Closed(_) => n + 1,
                RangeLimits::HalfOpen(_) => n,
            })
        }
        Expr::Array(a) => Some(a.elems.len() as u128),
        Expr::MethodCall(m) => match m.method.to_string().as_str() {
            "rev" | "iter" | "into_iter" | "enumerate" | "step_by" | "skip" => {
                loop_bound(&m.receiver, consts)
            }
            "take" => {
                let n = m.args.first().and_then(|a| eval_int(a, consts));
                match (loop_bound(&m.receiver, consts), n) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                }
            }
            _ => None,
        },
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Parameter validation (used by SG010)
// ---------------------------------------------------------------------------

/// Names of helpers that validate their argument.
const VALIDATOR_WORDS: &[&str] = &[
    "check", "valid", "require", "assert", "ensure", "verify", "positive", "negative",
];

/// Methods that inspect the sign / range of a number.
const SIGN_METHODS: &[&str] = &[
    "is_negative",
    "is_positive",
    "signum",
    "max",
    "clamp",
    "unsigned_abs",
    "abs",
];

/// How a function body uses one of its parameters.
pub fn param_use<'p>(block: &Block, param: &'p str) -> Validation<'p> {
    let mut v = Validation {
        param,
        used: false,
        validated: false,
    };
    v.visit_block(block);
    v
}

pub struct Validation<'p> {
    param: &'p str,
    pub used: bool,
    pub validated: bool,
}

impl Validation<'_> {
    fn is_param(&self, e: &Expr) -> bool {
        match strip(e) {
            Expr::Path(p) => p.path.is_ident(self.param),
            _ => false,
        }
    }

    fn mentions_param(&self, e: &Expr) -> bool {
        mentions_ident(quote::ToTokens::to_token_stream(e), self.param)
    }
}

impl<'ast> Visit<'ast> for Validation<'_> {
    fn visit_expr_path(&mut self, p: &'ast syn::ExprPath) {
        if p.path.is_ident(self.param) {
            self.used = true;
        }
    }

    fn visit_expr_binary(&mut self, b: &'ast ExprBinary) {
        let comparison = matches!(
            b.op,
            BinOp::Lt(_) | BinOp::Le(_) | BinOp::Gt(_) | BinOp::Ge(_) | BinOp::Eq(_) | BinOp::Ne(_)
        );
        if comparison && (self.mentions_param(&b.left) || self.mentions_param(&b.right)) {
            self.validated = true;
        }
        visit::visit_expr_binary(self, b);
    }

    fn visit_expr_call(&mut self, c: &'ast ExprCall) {
        if let Expr::Path(p) = strip(&c.func) {
            let name = p
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string().to_lowercase())
                .unwrap_or_default();
            if VALIDATOR_WORDS.iter().any(|w| name.contains(w))
                && c.args.iter().any(|a| self.mentions_param(a))
            {
                self.validated = true;
            }
        }
        visit::visit_expr_call(self, c);
    }

    fn visit_expr_method_call(&mut self, m: &'ast ExprMethodCall) {
        let name = m.method.to_string().to_lowercase();
        if (SIGN_METHODS.contains(&name.as_str()) && self.is_param(&m.receiver))
            || (VALIDATOR_WORDS.iter().any(|w| name.contains(w))
                && m.args.iter().any(|a| self.mentions_param(a)))
        {
            self.validated = true;
        }
        visit::visit_expr_method_call(self, m);
    }

    fn visit_expr_match(&mut self, m: &'ast syn::ExprMatch) {
        // `match amount { ..=0 => panic!(), _ => .. }`
        if self.is_param(&m.expr) {
            self.validated = true;
        }
        visit::visit_expr_match(self, m);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        let exprs = macro_exprs(mac);
        let name = mac
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        // assert!(amount > 0), require!(..), ensure!(..)
        if (name.contains("assert") || name == "require" || name == "ensure")
            && exprs.iter().any(|e| self.mentions_param(e))
        {
            self.validated = true;
        }
        for e in &exprs {
            Visit::visit_expr(self, e);
        }
    }
}
