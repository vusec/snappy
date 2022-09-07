#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StatusType {
    Normal(Option<i32>),
    Timeout,
    Crash,
    Skip,
}
