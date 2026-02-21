// redb::TransactionError is 160 bytes — upstream concern, not worth boxing
#![allow(clippy::result_large_err)]

pub mod error;
pub mod store;
