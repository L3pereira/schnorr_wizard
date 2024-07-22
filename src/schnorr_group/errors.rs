use thiserror::Error;

/// ## SchnorrError Enum
/// The `SchnorrError` enum encapsulates different kinds of errors that can be encountered.
/// //!
/// ### Variants
/// - `GroupParametersError(String)`: Represents errors related to group parameters in the Schnorr signature scheme.
/// - `ZkInteractiveError(String)`: Represents errors that occur during the Zero-Knowledge interactive protocol.
/// - `ParseError`: Represents errors that occur during parsing of integers. This error variant is automatically generated from `std::num::ParseIntError`.
///
/// ### Functions
/// - `group_parameters_error(msg: &str) -> Self`: A constructor function for creating a `GroupParametersError` variant. It takes a message string as input and returns an instance of `SchnorrError`.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum SchnorrError {
    /// - `GroupParametersError(String)`: Represents errors related to group parameters in the Schnorr signature scheme.
    #[error("An error occurred: {0}")]
    GroupParametersError(String),

    /// - `ZkInteractiveError(String)`: Represents errors that occur during the Zero-Knowledge interactive protocol.
    #[error("zk interactive Error: {0}")]
    ZkInteractiveError(String),
}
impl SchnorrError {
    /// - `group_parameters_error(msg: &str) -> Self`: A constructor function for creating a `GroupParametersError` variant. It takes a message string as input and returns an instance of `SchnorrError`.
    pub fn group_parameters_error(msg: &str) -> Self {
        SchnorrError::GroupParametersError(msg.to_string())
    }
}
