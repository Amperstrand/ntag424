#[derive(Debug, Copy, Clone, PartialEq, Eq)]
/// A response status word returned by the tag after processing a command.
pub enum ResponseStatus {
    /// Successful operation.
    OperationOk,
    /// Command code not supported.
    IllegalCommandCode,
    /// CRC or MAC does not match data. Padding bytes not valid.
    IntegrityError,
    /// Invalid key number specified.
    NoSuchKey,
    /// Length of command string invalid.
    LengthError,
    /// Curent configuration / status does not allow the requested command.
    PermissionDenied,
    /// Value of the parameter(s) invalid.
    ParameterError,
    /// Currently not allowed to authenticate.
    /// Keep trying until full delay is spent.
    AuthenticationDelay,
    /// Current authentication status does not allow the requested command.
    AuthenticationError,
    /// Additional frame expected to be sent.
    AdditionalFrame,
    /// Attempt to read/write data from/to byeond the file's/record's limits.
    /// Attempt to exceed the limits of a value file.
    BoundaryError,
    /// Previous command was not fully completed. Not all frames were requested or provided by the PCD.
    CommandAborted,
    /// Failure when reading or writing to non-volatile memory.
    MemoryError,
    /// Specified file number does not exist.
    FileNotFound,
    WrongLength,
    SecurityStatusNotSatisfied,
    ConditionsOfUseNotSatisfied,
    IncorrectParametersInTheCommandDataField,
    FileOrApplicationNotFound,
    IncorrectParametersP1P2,
    LcInconsistentWithParametersP1P2,
    WrongLeField,
    /// Wrong Le field.
    ///
    /// SW2 encodes the exact expected length.
    WrongLeFieldExpected(u8),
    InstructionCodeNotSupportedOrInvalid,
    ClassNotSupported,
    NormalProcessing,
    Unknown(u16),
}
