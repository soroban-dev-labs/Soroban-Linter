# Benchmarks

`run.py` measures soroban-linter on real Soroban code, pinned to exact commits in [`corpus.txt`](corpus.txt):

```bash
cargo build --release
python3 benchmarks/run.py --linter target/release/soroban-linter --cache /tmp/sg-corpus
python3 benchmarks/run.py ... --show-missed      # list undetected mutants on stderr
```

It runs about 400 lints and takes about 2 minutes.

## What is measured

**Findings.** The number of findings per repository. These are audited, production-grade codebases, so every **error** should be a real issue. Each one has been checked by hand (see below).

**Mutation recall.** This measures how often the linter notices a security-relevant line that has been deleted from real code. Each mutant is a copy of the repo with one change. A mutant counts as *detected* if the linter reports a new finding (warning or error) from the relevant rules.

| Mutation | Removes | Rules |
|---|---|---|
| `auth` | one `x.require_auth()` / `x.require_auth_for_args(..)` statement | SG001, SG008 |
| `ttl` | one persistent/temporary `.extend_ttl(..)` statement (multi-line chains included) | SG005 |
| `ttl-file` | every persistent/temporary `.extend_ttl(..)` in one file | SG005 |

Not every mutant introduces a bug. Some removals don't change behavior ("equivalent mutants"), and a perfect tool would not flag them:

- **auth**: `buyer.require_auth()` before `token.transfer(&buyer, ..)` is redundant, because the token contract requires the same auth. Removing auth from a function that changes no state (e.g. one that only emits an event) has no effect either. In soroban-examples, Soroswap and Blend, 11 of the 74 auth mutants are of this kind.
- **ttl**: many contracts extend the same key on read *and* on write. Removing one of the two leaves the key maintained, and SG005 deliberately reports only keys that are never extended. That's why `ttl-file` is the more meaningful TTL number.

## Results (November 2026, soroban-linter 0.1.0)

### Findings

| Repository | Files | Errors | Warnings | SG011 warnings | Notes |
|---|---|---|---|---|---|
| soroban-examples | 131 | 0 | 39 | 17 | 39 |
| blend-contracts | 88 | 0 | 19 | 1 | 15 |
| soroswap-core | 45 | 2 | 10 | 2 | 10 |
| soroban-governor | 33 | 0 | 5 | 1 | 2 |
| oz-stellar-contracts | 323 | 1 | 85 | 23 | 42 |

The 3 errors, checked by hand:

- **soroswap-core `pair` and `router`, SG009:** the release profile lacks `overflow-checks = true`, while the sibling `factory`, `token` and `library` crates set it. Accurate.
- **OpenZeppelin `fungible-governor`, SG008:** `executor.require_auth()` authenticates a caller-chosen address that is never checked. Accurate. The code documents it as intentional "open execution", so suppressing it is the right action.

### Mutation recall

| Repository | auth | ttl (single site) | ttl-file |
|---|---|---|---|
| soroban-examples | 24/32 (75.0%) | 1/6 | 3/4 |
| blend-contracts | 17/23 (73.9%) | 5/27 | 5/5 |
| soroswap-core | 15/19 (78.9%) | 0/11 | 3/5 |
| soroban-governor | 15/18 (83.3%) | 6/16 | 2/2 |
| oz-stellar-contracts | 47/87 (54.0%) | 60/79 | 33/39 |
| **Total** | **118/179 (65.9%)** | 72/139 (51.8%) | **46/55 (83.6%)** |

Excluding the equivalent auth mutants identified above, recall on the four non-OpenZeppelin codebases is 71/81 (87.7%).

**OpenZeppelin is the hardest case.** Its contracts dispatch through generic associated types (`Self::ContractType::transfer`, `Compose<(TotalSupply,)>`). Resolving those needs type information that a syntactic analyzer does not have. Reaching 54% there relies on these features:

- `#[contracttrait]` default methods treated as entry points;
- module-path call resolution with directory re-exports;
- crate-scoped type paths (`Base::update`);
- parameter-level tracking of generic `extend(e, key)` helpers.

## Robustness and speed

- **Robustness:** on the full Soroban SDK dependency tree (6,614 `.rs` and `Cargo.toml` files, 121 MB), there are no crashes and no parse failures.
- **Speed:** about 25 s for that whole set (single thread). Real projects are much faster: OpenZeppelin (323 files) takes 0.38 s and Blend (88 files) 0.16 s.
