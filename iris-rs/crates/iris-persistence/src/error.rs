/// Errors from the persistence layer.
#[derive(Debug, thiserror::Error)]
pub enum PersistenceError {
    #[error("database error: {0}")]
    Database(#[from] redb::DatabaseError),

    #[error("table error: {0}")]
    Table(#[from] redb::TableError),

    #[error("storage error: {0}")]
    Storage(#[from] redb::StorageError),

    #[error("transaction error: {0}")]
    Transaction(#[from] redb::TransactionError),

    #[error("commit error: {0}")]
    Commit(#[from] redb::CommitError),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, PersistenceError>;
