use super::{FileContext, Rule, RuleInfo};
use crate::finding::{Finding, Severity};

pub struct MissingAdminEvent;

static INFO: RuleInfo = RuleInfo {
    id: "SG011",
    name: "missing-admin-event",
    default_severity: Severity::Warning,
    summary: "Privileged configuration changes and contract upgrades should publish an event",
    help: "Publish an event when changing an admin/owner-style key or upgrading the contract. \
           Indexers and monitoring systems rely on events to observe these changes.",
};

impl Rule for MissingAdminEvent {
    fn info(&self) -> &'static RuleInfo {
        &INFO
    }

    fn check(&self, cx: &FileContext<'_>, out: &mut Vec<Finding>) {
        for (f, facts) in cx.entry_points() {
            let effects = cx.index.transitive(facts);
            if (effects.writes_authority_key || effects.upgrades) && !effects.publishes_event {
                out.push(cx.finding(
                    &INFO,
                    INFO.default_severity,
                    f.line_col(),
                    format!(
                        "`{}` changes an admin/owner-style key or upgrades the contract without publishing an event",
                        f.name()
                    ),
                ));
            }
        }
    }
}
