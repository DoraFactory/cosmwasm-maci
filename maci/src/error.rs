use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("Insufficient funds sent")]
    InsufficientFundsSend {},

    #[error("PeriodError")]
    PeriodError {},

    #[error("Must update from height 0")]
    MustUpdate {},

    #[error("Data error")]
    DataError {},

    #[error("Error verification")]
    ErrorVerificationKey {},

    #[error("Error proof")]
    ErrorProof {},

    #[error("Error public signal")]
    ErrorPublicSignal {},

    #[error("No verification key")]
    NoVerificationKey {},

    #[error("No public signal")]
    NoPublicSignal {},

    #[error("Parse public signal error")]
    ParsePulbicSignalError {},

    #[error("invalid hex format")]
    HexDecodingError {},

    #[error("Invalid proof, step {step} verify failed")]
    InvalidProof { step: String },

    #[error("whitelist already exist")]
    AlreadySetWhitelist {},

    #[error("already set {time_name} time")]
    AlreadySetVotingTime { time_name: String },

    #[error("end_time must big than start_time")]
    WrongTimeSet {},

    #[error("round title can not be empty")]
    TitleIsEmpty,

    #[error("Fee Grant already exists")]
    FeeGrantAlreadyExists,

    #[error("Fee Grant is not exists")]
    FeeGrantIsNotExists,

    #[error("this account({difficuty_issuer}) didn't issue difficulty problem")]
    NonPublishDifficulty { difficuty_issuer: String },

    #[error("could not convert into prime field")]
    InvalidPrimeField {},

    #[error("SynthesisError of zk verify")]
    SynthesisError {},

    #[error("still have messages left to process.")]
    MsgLeftProcess {},

    #[error("still have usertally left to process.")]
    UserTallyLeftProcess {},
}
