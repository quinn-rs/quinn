// This is only here because qpack is new and quinn no uses it yet.
// TODO remove allow dead code
#![allow(dead_code)]

use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};

use super::field::HeaderField;
use crate::qpack::vas::{self, VirtualAddressSpace};

/**
 * https://tools.ietf.org/html/draft-ietf-quic-qpack-01
 * 4. Configuration
 */
pub const SETTINGS_HEADER_TABLE_SIZE_DEFAULT: usize = 4096;

/**
 * https://tools.ietf.org/html/draft-ietf-quic-qpack-01
 * 4. Configuration
 */
pub const SETTINGS_HEADER_TABLE_SIZE_MAX: usize = 1073741823; // 2^30 -1

#[derive(Debug, PartialEq)]
pub enum Error {
    BadRelativeIndex(usize),
    BadPostbaseIndex(usize),
    BadIndex(usize),
    MaxTableSizeReached,
    MaximumTableSizeTooLarge,
}

pub struct DynamicTable {
    fields: VecDeque<HeaderField>,
    curr_mem_size: usize,
    mem_limit: usize,
    vas: VirtualAddressSpace,
}

pub struct DynamicTableDecoder<'a> {
    table: &'a DynamicTable,
    base: usize,
}

impl<'a> DynamicTableDecoder<'a> {
    pub fn get_relative(&self, index: usize) -> Result<&HeaderField, Error> {
        let real_index = self.table.vas.relative_base(self.base, index)?;
        self.table
            .fields
            .get(real_index)
            .ok_or(Error::BadIndex(real_index))
    }

    pub fn get_postbase(&self, index: usize) -> Result<&HeaderField, Error> {
        let real_index = self.table.vas.post_base(self.base, index)?;
        self.table
            .fields
            .get(real_index)
            .ok_or(Error::BadIndex(real_index))
    }
}

pub struct DynamicTableInserter<'a> {
    table: &'a mut DynamicTable,
}

impl<'a> DynamicTableInserter<'a> {
    pub fn put_field(&mut self, field: HeaderField) -> Result<(), Error> {
        let at_most = if field.mem_size() <= self.table.mem_limit {
            self.table.mem_limit - field.mem_size()
        } else {
            0
        };
        let dropped = self.table.shrink_to(at_most);

        let available = self.table.mem_limit - self.table.curr_mem_size;
        let can_add = field.mem_size() <= available;
        if !can_add {
            return Err(Error::MaxTableSizeReached);
        }

        self.table.curr_mem_size += field.mem_size();
        self.table.fields.push_back(field);
        self.table.vas.add();
        self.table.vas.drop_many(dropped);

        Ok(())
    }

    pub fn get_relative(&self, index: usize) -> Result<&HeaderField, Error> {
        let real_index = self.table.vas.relative(index)?;
        self.table
            .fields
            .get(real_index)
            .ok_or(Error::BadIndex(real_index))
    }

    /**
     * @returns Number of fields removed by resizing
     */
    pub fn set_max_mem_size(&mut self, size: usize) -> Result<usize, Error> {
        if size > SETTINGS_HEADER_TABLE_SIZE_MAX {
            return Err(Error::MaximumTableSizeTooLarge);
        }

        self.table.mem_limit = size;
        Ok(self.table.shrink_to(size))
    }

    pub fn total_inserted(&self) -> usize {
        self.table.vas.total_inserted()
    }
}

impl From<vas::Error> for Error {
    fn from(e: vas::Error) -> Self {
        match e {
            vas::Error::BadRelativeIndex(e) => Error::BadRelativeIndex(e),
            vas::Error::BadPostbaseIndex(e) => Error::BadPostbaseIndex(e),
            vas::Error::BadAbsoluteIndex(e) => Error::BadIndex(e),
        }
    }
}

impl DynamicTable {
    pub fn new() -> DynamicTable {
        DynamicTable {
            fields: VecDeque::new(),
            curr_mem_size: 0,
            mem_limit: SETTINGS_HEADER_TABLE_SIZE_DEFAULT,
            vas: VirtualAddressSpace::new(),
        }
    }

    pub fn decoder<'a>(&'a self, base: usize) -> DynamicTableDecoder<'a> {
        DynamicTableDecoder { table: self, base }
    }

    pub fn inserter<'a>(&'a mut self) -> DynamicTableInserter<'a> {
        DynamicTableInserter { table: self }
    }

    pub fn total_inserted(&self) -> usize {
        self.vas.total_inserted()
    }

    /**
     * @returns Number of fields removed by resizing
     */
    pub fn set_max_mem_size(&mut self, size: usize) -> Result<usize, Error> {
        if size > SETTINGS_HEADER_TABLE_SIZE_MAX {
            return Err(Error::MaximumTableSizeTooLarge);
        }

        self.mem_limit = size;
        Ok(self.shrink_to(size))
    }

    /**
     * https://tools.ietf.org/html/rfc7541
     * 4.4.  Entry Eviction When Adding New Entries
     *
     * @returns Number of fields removed
     */
    fn shrink_to(&mut self, lower_bound: usize) -> usize {
        let initial = self.fields.len();

        while !self.fields.is_empty() && self.curr_mem_size > lower_bound {
            let field = self
                .fields
                .pop_front()
                .expect("there is at least one field");
            self.curr_mem_size -= field.mem_size();
        }

        initial - self.fields.len()
    }

    pub fn max_mem_size(&self) -> usize {
        self.mem_limit
    }

    pub fn get(&self, index: usize) -> Result<&HeaderField, Error> {
        match self.fields.get(index) {
            Some(f) => Ok(f),
            None => Err(Error::BadIndex(index)),
        }
    }

    pub fn count(&self) -> usize {
        self.fields.len()
    }
}

// pub enum DynamicNameLookup {
//     Relative(usize),
//     PostBase(usize),
//     NotFound,
// }

// pub enum DynamicInsertionResult {
//     Inserted { postbase: usize, absolute: usize },
//     InsertedWithNameRef { postbase: usize, absolute: usize },
// }

#[cfg(test)]
mod tests {
    use super::*;

    // Test on table size

    /**
     * https://tools.ietf.org/html/rfc7541#section-4.1
     * "The size of the dynamic table is the sum of the size of its entries."
     */
    #[test]
    fn test_table_size_is_sum_of_its_entries() {
        let mut table = DynamicTable::new();

        let fields: [(&'static str, &'static str); 2] = [
            ("Name", "Value"),
            ("Another-Name", ""), // no value
        ];
        let table_size = 4 + 5 + 12 + 0 + /* ESTIMATED_OVERHEAD_BYTES */ 32 * 2;

        for pair in fields.iter() {
            let field = HeaderField::new(pair.0, pair.1);
            table.inserter().put_field(field).unwrap();
        }

        assert_eq!(table.curr_mem_size, table_size);
    }

    // Test on maximum table size

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-01#section-2.2
     * "The decoder determines the maximum size that the encoder is permitted
     *  to use for the dynamic table.  In HTTP/QUIC, this value is determined
     *  by the SETTINGS_HEADER_TABLE_SIZE setting (see Section 4.2.5.2 of
     *  [QUIC-HTTP])."
     *
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-01#section-4
     * "SETTINGS_HEADER_TABLE_SIZE (0x1):  An integer with a maximum value of
     *   2^30 - 1.  The default value is 4,096 bytes.  See (todo: reference
     *   PR#1357) for usage."
     */
    #[test]
    fn test_maximum_table_size_is_not_null_nor_max_by_default() {
        let table = DynamicTable::new();
        assert_eq!(table.max_mem_size(), SETTINGS_HEADER_TABLE_SIZE_DEFAULT);
    }

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-01#section-2.2
     * "The decoder determines the maximum size that the encoder is permitted
     *  to use for the dynamic table.  In HTTP/QUIC, this value is determined
     *  by the SETTINGS_HEADER_TABLE_SIZE setting (see Section 4.2.5.2 of
     *  [QUIC-HTTP])."
     */
    #[test]
    fn test_try_set_too_large_maximum_table_size() {
        let mut table = DynamicTable::new();
        let invalid_size = SETTINGS_HEADER_TABLE_SIZE_MAX + 10;
        let res_change = table.set_max_mem_size(invalid_size);
        assert_eq!(res_change, Err(Error::MaximumTableSizeTooLarge));
    }

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-01#section-2.2
     * "This mechanism can be used to completely clear entries from the
     *  dynamic table by setting a maximum size of 0, which can subsequently
     *  be restored."
     */
    #[test]
    fn test_maximum_table_size_can_reach_zero() {
        let mut table = DynamicTable::new();
        let res_change = table.set_max_mem_size(0);
        assert!(res_change.is_ok());
        assert_eq!(table.max_mem_size(), 0);
    }

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-01#section-2.2
     * "The decoder determines the maximum size that the encoder is permitted
     *  to use for the dynamic table.  In HTTP/QUIC, this value is determined
     *  by the SETTINGS_HEADER_TABLE_SIZE setting (see Section 4.2.5.2 of
     *  [QUIC-HTTP])."
     */
    #[test]
    fn test_maximum_table_size_can_reach_maximum() {
        let mut table = DynamicTable::new();
        let res_change = table.set_max_mem_size(SETTINGS_HEADER_TABLE_SIZE_MAX);
        assert!(res_change.is_ok());
        assert_eq!(table.max_mem_size(), SETTINGS_HEADER_TABLE_SIZE_MAX);
    }

    // Test duplicated fields

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-01#section-2.2
     * "The dynamic table can contain duplicate entries (i.e., entries with
     *  the same name and same value).  Therefore, duplicate entries MUST NOT
     *  be treated as an error by a decoder."
     */
    #[test]
    fn test_table_supports_duplicated_entries() {
        let mut table = DynamicTable::new();
        table
            .inserter()
            .put_field(HeaderField::new("Name", "Value"))
            .unwrap();
        table
            .inserter()
            .put_field(HeaderField::new("Name", "Value"))
            .unwrap();
        assert_eq!(table.count(), 2);
    }

    // Test adding fields

    /** functional test */
    #[test]
    fn test_add_field_fitting_free_space() {
        let mut table = DynamicTable::new();

        table
            .inserter()
            .put_field(HeaderField::new("Name", "Value"))
            .unwrap();
        assert_eq!(table.fields.len(), 1);
    }

    /** functional test */
    #[test]
    fn test_add_field_reduce_free_space() {
        let mut table = DynamicTable::new();

        let field = HeaderField::new("Name", "Value");
        table.inserter().put_field(field.clone()).unwrap();
        assert_eq!(table.curr_mem_size, field.mem_size());
    }

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-01#section-2.2
     * "Before a new entry is added to the dynamic table, entries are evicted
     *  from the end of the dynamic table until the size of the dynamic table
     *  is less than or equal to (maximum size - new entry size) or until the
     *  table is empty."
     */
    #[test]
    fn test_add_field_drop_older_fields_to_have_enough_space() {
        let mut table = DynamicTable::new();

        table
            .inserter()
            .put_field(HeaderField::new("Name-A", "Value-A"))
            .unwrap();
        table
            .inserter()
            .put_field(HeaderField::new("Name-B", "Value-B"))
            .unwrap();
        let perfect_size = table.curr_mem_size;
        assert!(table.set_max_mem_size(perfect_size).is_ok());

        let field = HeaderField::new("Name-Large", "Value-Large");
        table.inserter().put_field(field).unwrap();

        assert_eq!(table.fields.len(), 1);
        assert_eq!(
            table.fields.get(0),
            Some(&HeaderField::new("Name-Large", "Value-Large"))
        );
    }

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-01#section-2.2
     * "If the size of the new entry is less than or equal to the maximum
     *  size, that entry is added to the table.  It is an error to attempt to
     *  add an entry that is larger than the maximum size;"
     */
    #[test]
    fn test_try_add_field_larger_than_maximum_size() {
        let mut table = DynamicTable::new();

        table
            .inserter()
            .put_field(HeaderField::new("Name-A", "Value-A"))
            .unwrap();
        let perfect_size = table.curr_mem_size;
        assert!(table.set_max_mem_size(perfect_size).is_ok());

        let field = HeaderField::new("Name-Large", "Value-Large");
        assert_eq!(
            table.inserter().put_field(field),
            Err(Error::MaxTableSizeReached)
        );
    }

    // Test on entry eviction

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-01#section-2.2
     * "This mechanism can be used to completely clear entries from the
     *  dynamic table by setting a maximum size of 0, which can subsequently
     *  be restored."
     */
    #[test]
    fn test_set_maximum_table_size_to_zero_clear_entries() {
        let mut table = DynamicTable::new();

        table
            .inserter()
            .put_field(HeaderField::new("Name", "Value"))
            .unwrap();
        table
            .inserter()
            .put_field(HeaderField::new("Name", "Value"))
            .unwrap();
        assert_eq!(table.count(), 2);

        let were_dropped = table.set_max_mem_size(0);
        assert_eq!(were_dropped, Ok(2));
        assert_eq!(table.count(), 0);
    }

    /** functional test */
    #[test]
    fn test_eviction_is_fifo() {
        let mut table = DynamicTable::new();

        table
            .inserter()
            .put_field(HeaderField::new("Name-A", "Value-A"))
            .unwrap();
        table
            .inserter()
            .put_field(HeaderField::new("Name-B", "Value-B"))
            .unwrap();
        let perfect_size = table.curr_mem_size;
        assert!(table.set_max_mem_size(perfect_size).is_ok());

        table
            .inserter()
            .put_field(HeaderField::new("Name-C", "Value-C"))
            .unwrap();

        assert_eq!(table.get(0), Ok(&HeaderField::new("Name-B", "Value-B")));
        assert_eq!(table.get(1), Ok(&HeaderField::new("Name-C", "Value-C")));
        assert_eq!(table.get(2), Err(Error::BadIndex(2)));
    }

}
