use thiserror::Error;

/// ## SchnorrError Enum
/// The `SchnorrError` enum encapsulates different kinds of errors that can be encountered.
/// //!
/// ### Variants
/// - `GroupParametersError(String)`: Represents errors related to group parameters in the Schnorr signature scheme.
/// - `InteractiveZkError(String)`: Represents errors that occur during the interactive Zero-Knowledge protocol.
/// - `NonInteractiveZkError(String)`: Represents errors that occur during the non interactive Zero-Knowledge protocol.
///
/// ### Functions
/// - `group_parameters_error(msg: &str) -> Self`: A constructor function for creating a `GroupParametersError` variant. It takes a message string as input and returns an instance of `SchnorrError`.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum SchnorrError {
    /// - `GroupParametersError(String)`: Represents errors related to group parameters in the Schnorr signature scheme.
    #[error("An error occurred: {0}")]
    GroupParametersError(String),

    /// - `InteractiveZkError(String)`: Represents errors that occur during the interactive Zero-Knowledge protocol.
    #[error("interactive zk Error: {0}")]
    InteractiveZkError(String),

    /// - `NonInteractiveZkError(String)`: Represents errors that occur during the non interactive Zero-Knowledge protocol.
    #[error("non interactive zk Error: {0}")]
    NonInteractiveZkError(String),

    /// - `SignatureError(String)`: An error that occurs during signature generation or verification.
    #[error("signature Error: {0}")]
    SignatureError(String),

    /// - `MuSig2Error(String)`: An error that occurs during multiparty signature generation or verification.
    #[error("musig2 Error: {0}")]
    MuSig2Error(String),
}
impl SchnorrError {
    /// - `group_parameters_error(msg: &str) -> Self`: A constructor function for creating a `GroupParametersError` variant. It takes a message string as input and returns an instance of `SchnorrError`.
    pub fn group_parameters_error(msg: &str) -> Self {
        SchnorrError::GroupParametersError(msg.to_string())
    }
}
