# soroban-linter

Static analysis for Soroban smart contracts. It finds auth, storage-lifecycle, arithmetic and resource-limit bugs before they reach the network.

- **Works on stable Rust.** It parses source with [`syn`](https://docs.rs/syn), so you don't need nightly, `rustc_private`, or a compiled contract.
- **Analyzes the whole crate.** It follows calls between helper functions, modules and crates, so `withdraw()` calling `storage::write_balance()` is analyzed as one unit. It understands:
  - auth attributes such as `#[only_owner]` and `#[only_role(..)]`;
  - `#[contracttrait]` default methods;
  - library calls such as `Base::transfer(..)` (the OpenZeppelin Stellar style).
- **Measured on real code.** The linter is benchmarked on about 620 files of production contracts, and every error it reports there has been checked by hand. See [benchmarks](../../benchmarks/README.md).
- **Checks manifests too.** It reads `Cargo.toml` files to verify the release profile.
- **Fits into CI.** Output can be text, JSON, or SARIF 2.1.0 (GitHub code scanning). There's also a ready-made GitHub Action.

## Install & run

```bash
cargo install --path crates/soroban-linter

soroban-linter path/to/contract          # lint a crate, workspace or file
cargo soroban-linter                     # same, as a cargo subcommand
soroban-linter --list-rules
soroban-linter --explain SG008
soroban-linter . --format sarif -o soroban-linter.sarif
```

| Option | Meaning |
|---|---|
| `--format text\|json\|sarif` | Output format (default `text`) |
| `-o, --output <file>` | Write the report to a file |
| `--fail-on error\|warning\|note\|never` | Exit with `1` on findings at/above this severity (default `error`) |
| `--config <file>` | Config file (default `./soroban-guard.toml` if present) |
| `--disable SG005,storage-get-unwrap` | Turn rules off (id or name) |
| `--only SG001` | Run only these rules |
| `--max-footprint-entries <N>` | Per-tx footprint limit used by SG003 (default `400`) |
| `--max-write-entries <N>` | Per-tx written-entry limit used by SG003 (default `200`) |
| `--critical-keyword vault,shares` | Extra key words SG002 treats as critical state |
| `--include-tests` | Also lint `tests/` and `test.rs` (skipped by default) |
| `--baseline <file>` | Report only findings not in this baseline (a previous JSON report) |
| `--write-baseline <file>` | Save the current findings as the baseline |
| `--list-rules`, `--explain <RULE>` | Rule documentation |

Exit codes: `0` means clean, `1` means there are findings at or above `--fail-on`, and `2` means a usage, config or I/O error.

**Severity levels:**

- `error`: almost certainly a bug.
- `warning`: needs a human look.
- `note`: worth knowing about.

`--fail-on error`, the default, is built to keep false CI failures rare on mature codebases. For new contracts, `--fail-on warning` is stricter and recommended.

## Rules

| ID | Name | Default | Detects |
|---|---|---|---|
| SG001 | `missing-require-auth` | error / warning / note | A public contract function that changes storage without `require_auth`, either directly, in a helper, or via an `#[only_*]`/`#[has_role]` attribute. It reports at three severities:<br>**Error** when:<br>• anyone could upgrade the contract;<br>• anyone could overwrite an admin/owner-style key;<br>• a function takes value from a caller-supplied address that never signs (e.g. `withdraw(from)`, or `pull(spender, from)` where only `spender` signs);<br>• a function loads the admin from storage but authorizes no one.<br>**Warning** when the change is driven by a caller-supplied `Address`, or the function is an `init*` function (front-running).<br>**Note** for other permissionless changes. Allowance flows (`transfer_from`) and liquidations are recognized. |
| SG002 | `critical-state-in-temporary` | error | `temporary().set(..)` where the key or function mentions balances, owners, admins, supply, deposits, stakes, collateral, debt or reserves. Temporary entries are **deleted for good** when their TTL expires. Data that is meant to expire is ignored (allowances, approvals, nonces, locks, queues, …). |
| SG003 | `unbounded-storage-loop` | warning / error | Loops (`for`, `while`, `loop`, `.map(..)`, `.for_each(..)`, …) that access storage. It's a warning when the iteration count isn't statically bounded. It's an error when a bounded loop (`0..BATCH`, `.take(N)`; consts are resolved) exceeds the footprint or write-entry limit. |
| SG004 | `unchecked-custom-auth` | error | A `__check_auth` that never verifies a signature (`ed25519_verify`, `secp256r1_verify`, `secp256k1_recover`, BLS `pairing_check`, …) and doesn't delegate (`require_auth`, `delegate_auth`), or that ignores `signature_payload`. |
| SG005 | `missing-ttl-extension` | warning | Persistent/temporary keys that a contract function writes but that no code path ever extends with `extend_ttl`, so they expire after the minimum TTL. Keys are matched per variant and per crate (`DataKey::Balance`). The check also follows extend-on-read getters and generic `extend(e, key)` helpers. |
| SG006 | `unbounded-instance-storage` | warning | Per-id keys such as `DataKey::Balance(user)` written to `instance()` storage. The single instance entry grows without bound and is loaded on every call. Constant keys such as `Symbol::new(e, ADMIN_KEY)` are ignored. |
| SG007 | `storage-get-unwrap` | note | `storage.get(..).unwrap()` / `.expect(..)`. A missing or expired entry aborts with an opaque panic instead of a contract error. |
| SG008 | `unchecked-auth-address` | error | It covers two cases:<br>• `caller.require_auth()` where `caller` is a parameter that is never used otherwise (e.g. never compared with the stored admin);<br>• a function that overwrites an admin/owner key while authorizing only caller-supplied addresses (`set_admin(new) { new.require_auth(); .. }`).<br>Either way, anyone can pass their own address and pass the check. |
| SG009 | `overflow-checks-disabled` | error | A contract crate (`soroban-sdk` + `cdylib`) whose governing release profile, i.e. the workspace root's, lacks `overflow-checks = true`. Without it, `i128` arithmetic wraps silently. |
| SG010 | `unvalidated-amount` | warning | A signed amount parameter (`i128`/`i64`/`i32`) used in a state-changing entry point but never range-checked: no comparison, `assert!`, or `check_*`/`require_*` helper. This includes helpers the value is forwarded to. A negative amount turns a debit into a credit. |
| SG014 | `panic-without-contract-error` | note | A contract entry point, or a helper it calls, can abort with `panic!`, `unreachable!`, or `.expect(..)` / `.unwrap()` on a non-storage value. Use `panic_with_error!(&env, Error::X)` with a `#[contracterror]` enum so callers can distinguish failures. Storage `get(..).unwrap()` / `.expect(..)` is covered by SG007. |

## Configuration file

Put a `soroban-guard.toml` in the directory you run from, or pass `--config`. Command-line flags take precedence over the file. See [`soroban-guard.example.toml`](../../soroban-guard.example.toml):

```toml
max-footprint-entries = 400
max-write-entries = 200
critical-keywords = ["vault", "shares"]
disable = ["SG007"]
fail-on = "warning"

[severity]
SG005 = "error"
```

### Network limits

The SG003 defaults come from **Stellar mainnet's on-chain config** (protocol 29, read in November 2026):

| Limit | Value |
|---|---|
| Footprint entries per transaction (`txMaxFootprintEntries`) | 400 |
| Written entries per transaction (`txMaxWriteLedgerEntries`) | 200 |
| Disk-read entries per transaction (`txMaxDiskReadEntries`) | 200 |

Since protocol 23, live contract data is held in memory and does not count toward disk reads. A storage loop is therefore bounded by the footprint and write limits. Networks change these values by validator vote, so check yours with `stellar network settings`.

## Suppressing findings

```rust
// soroban-guard: allow(SG001)          -- intentionally permissionless
pub fn distribute(e: Env) { ... }

let v = e.st

/* … truncated 4717 chars — edit only what you need near the top … */
