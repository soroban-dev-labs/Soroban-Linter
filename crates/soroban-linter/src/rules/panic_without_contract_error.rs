use super::{FileContext, Rule, RuleInfo};
use crate::finding::{Finding, Severity};

pub struct PanicWithoutContractError;

static INFO: RuleInfo = RuleInfo {
    id: "SG014",
    name: "panic-without-contract-error",
    default_severity: Severity::Note,
    summary: "Contract code can abort with an opaque panic instead of a contract error",
    help:
        "Handle `Option` / `Result` explicitly or use `panic_with_error!(&env, Error::X)` with a \
         `#[contracterror]` enum so callers can distinguish failures.",
};

impl Rule for PanicWithoutContractError {
    fn info(&self) -> &'static RuleInfo {
        &INFO
    }

    fn check(&self, cx: &FileContext<'_>, out: &mut Vec<Finding>) {
        for (f, facts) in cx.entry_points() {
            if cx.index.transitive(facts).opaque_abort {
                out.push(cx.finding(
                    &INFO,
                    INFO.default_severity,
                    f.line_col(),
                    "this contract entry point can abort with an opaque panic; use a contract \
                     error so callers can distinguish failures",
                ));
            }
        }
    }
}
