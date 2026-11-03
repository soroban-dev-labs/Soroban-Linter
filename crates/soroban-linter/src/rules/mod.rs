//! Detector rules. Each rule lives in its own module and is registered in [`all_rules`].
//!
//! To add a rule: copy an existing module, give it the next free `SGxxx` id,
//! register it below, and add `// expect: SGxxx` cases to the test fixtures.

use std::path::Path;

use crate::analysis::{collect_fns, scan_fn, CrateIndex, FnDef, FnFacts};
use crate::finding::{Finding, Severity};
use crate::manifest::ManifestSet;
use crate::LintConfig;

mod critical_state_in_temporary;
mod missing_admin_event;
mod missing_require_auth;
mod missing_ttl_extension;
mod overflow_checks;
mod storage_get_unwrap;
mod unbounded_instance_storage;
mod unbounded_storage_loop;
mod unchecked_auth_address;
mod unchecked_custom_auth;
mod unvalidated_amount;

/// Static metadata describing a rule.
#[derive(Debug)]
pub struct RuleInfo {
    /// Stable identifier, e.g. `SG001`.
    pub id: &'static str,
    /// Kebab-case name, e.g. `missing-require-auth`.
    pub name: &'static str,
    pub default_severity: Severity,
    /// One-line description.
    pub summary: &'static str,
    /// How to fix it.
    pub help: &'static str,
}

pub trait Rule: Sync {
    fn info(&self) -> &'static RuleInfo;
    /// Checks one Rust source file.
    fn check(&self, cx: &FileContext<'_>, out: &mut Vec<Finding>);

    /// Checks the `Cargo.toml` manifests being linted. Most rules don't need this.
    fn check_manifests(&self, _manifests: &ManifestSet, _out: &mut Vec<Finding>) {}
}

/// Every built-in rule, in id order.
pub fn all_rules() -> Vec<&'static dyn Rule> {
    vec![
        &missing_require_auth::MissingRequireAuth,
        &critical_state_in_temporary::CriticalStateInTemporary,
        &unbounded_storage_loop::UnboundedStorageLoop,
        &unchecked_custom_auth::UncheckedCustomAuth,
        &missing_ttl_extension::MissingTtlExtension,
        &unbounded_instance_storage::UnboundedInstanceStorage,
        &storage_get_unwrap::StorageGetUnwrap,
        &unchecked_auth_address::UncheckedAuthAddress,
        &overflow_checks::OverflowChecks,
        &unvalidated_amount::UnvalidatedAmount,
        &missing_admin_event::MissingAdminEvent,
    ]
}

pub fn find_rule(id_or_name: &str) -> Option<&'static dyn Rule> {
    all_rules()
        .into_iter()
        .find(|r| r.info().id.eq_ignore_ascii_case(id_or_name) || r.info().name == id_or_name)
}

/// Everything a rule needs to analyse one file.
pub struct FileContext<'a> {
    pub path: &'a Path,
    pub source: &'a str,
    pub ast: &'a syn::File,
    pub fns: Vec<(FnDef<'a>, FnFacts)>,
    pub index: &'a CrateIndex,
    pub config: &'a LintConfig,
}

impl<'a> FileContext<'a> {
    pub fn new(
        path: &'a Path,
        source: &'a str,
        ast: &'a syn::File,
        index: &'a CrateIndex,
        config: &'a LintConfig,
    ) -> Self {
        let module = crate::analysis::module_name(path);
        let fns = collect_fns(ast, &module)
            .into_iter()
            .map(|f| {
                let facts = scan_fn(&f);
                (f, facts)
            })
            .collect();
        FileContext {
            path,
            source,
            ast,
            fns,
            index,
            config,
        }
    }

    /// Functions exported by `#[contractimpl]` blocks.
    pub fn entry_points(&self) -> impl Iterator<Item = &(FnDef<'a>, FnFacts)> {
        self.fns.iter().filter(|(f, _)| f.is_contract_entry)
    }

    pub fn finding(
        &self,
        info: &'static RuleInfo,
        severity: Severity,
        (line, column): (usize, usize),
        message: impl Into<String>,
    ) -> Finding {
        Finding {
            rule_id: info.id,
            rule_name: info.name,
            severity,
            message: message.into(),
            file: self.path.to_path_buf(),
            line,
            column,
        }
    }
}
