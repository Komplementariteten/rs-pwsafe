#[derive(Debug)]
pub enum PswSafeError {
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
