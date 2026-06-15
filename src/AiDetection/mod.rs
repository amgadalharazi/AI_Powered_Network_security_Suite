pub mod ai_detector;
pub mod flowtracker;

pub use ai_detector::AIDetector;
// FlowKey and FlowStats are used internally by packet_sniffing via FlowTracker;
// suppress the warning if they are not directly imported elsewhere.
#[allow(unused_imports)]
pub use flowtracker::{FlowKey, FlowStats, FlowTracker};
