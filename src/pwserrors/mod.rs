#[derive(Debug)]
pub enum PwSafeError {
    FileNotFound,
    FailedToOpenFile,
    FileReadError,
    FileNotSupported,
    SaltNotFound,
    NumberOfIterationsNotFound,
    IterationsNotInitialized,
    FileToSmall,
    EofPositionError,
    InvalidKey,
    CantCreateHmacWithL,
    HmacSigSizeDoesNotMatch,
    InvalidSignature,
    SignatureAlgorithmNotInitialized
}
