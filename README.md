# Soroban-Linter (soroban-guard)

Safety tooling for [Soroban](https://developers.stellar.org/docs/build/smart-contracts/overview) smart contracts on Stellar.

```
soroban-guard/
├── crates/
│   └── soroban-linter/          # Static analysis: 11 detectors for auth, storage lifecycle,
│                                # arithmetic and resource limits
├── benchmarks/                  # Reproducible benchmark on production contracts
├── action.yml                   # GitHub Action (lint + SARIF upload)
├── soroban-guard.example.toml   # Example configuration
└── .github/workflows/           # CI: fmt, clippy, tests, SARIF self-check
```

Planned crates (not yet started): `soroban-storage` (typed storage wrappers with TTL lifecycle), `soroban-fuzzer` (property-based fuzzing harness), and `daemons/rent-keeper` (automated TTL extension daemon).

## Quick start

```bash
cargo install --path crates/soroban-linter
soroban-linter path/to/your/contract
```

```text
error[SG008] unchecked-auth-address: `admin.require_auth()` authorizes an address the caller chose, but `admin` is never checked against an admin/owner or used otherwise; any account can pass its own address and pass this check
  --> src/lib.rs:121:15
    |
121 |         admin.require_auth();
    |               ^
  = help: `caller.require_auth()` only proves the transaction was signed by `caller`, and the caller chooses that argument. ...
```

In GitHub Actions:

```yaml
- uses: ArchBishop051/Soroban-Linter@main
  with:
    path: contracts/
```

It is benchmarked on about 620 files of production Soroban code: Blend, Soroswap, OpenZeppelin, soroban-examples and soroban-governor. It reports 3 errors there, all accurate. In mutation testing, it catches 66% of deleted `require_auth` calls (88% outside OpenZeppelin's generic code) and 84% of files with all TTL extensions removed. See [benchmarks/](benchmarks/README.md). See [crates/soroban-linter/README.md](crates/soroban-linter/README.md) for all rules, options, configuration, suppressions and the validation results.

## Contributing

New detectors are self-contained and easy to add. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT OR Apache-2.0
