mod field;
pub use self::field::HeaderField;

mod dynamic;
pub use self::dynamic::{
    DynamicInsertionResult, DynamicLookupResult, DynamicTable, DynamicTableDecoder,
    DynamicTableEncoder, DynamicTableInserter, Error as DynamicTableError,
    SETTINGS_HEADER_TABLE_SIZE_DEFAULT,
};

pub mod static_;
pub use self::static_::StaticTable;
