#[derive(Debug)]
pub enum PwsSafeError {
    FileNotFound,
    FailedToOpenFile,
    FileReadError,
    FileNotSupported,
    SaltNotFound,
    NumberOfIterationsNotFound,
    IterationsNotInitialized,
    FileToSmall,
    EofPositionError,
    InvalidKey
}
