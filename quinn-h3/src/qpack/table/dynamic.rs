// This is only here because qpack is new and quinn no uses it yet.
// TODO remove allow dead code
#![allow(dead_code)]

use std::borrow::Cow;
use std::collections::hash_map::Entry;
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
        self.table.put_field(field)?;
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

pub struct DynamicTableEncoder<'a> {
    table: &'a mut DynamicTable,
    base: usize,
}

impl<'a> DynamicTableEncoder<'a> {
    pub fn find(&self, field: &HeaderField) -> DynamicLookupResult {
        self.lookup_result(
            self.table
                .field_map
                .as_ref()
                .unwrap()
                .get(field)
                .map(|x| *x),
        )
    }

    fn find_name(&self, name: &[u8]) -> DynamicLookupResult {
        self.lookup_result(self.table.name_map.as_ref().unwrap().get(name).map(|x| *x))
    }

    fn lookup_result(&self, abolute: Option<usize>) -> DynamicLookupResult {
        match abolute {
            Some(absolute) if absolute <= self.base => DynamicLookupResult::Relative {
                index: self.base - absolute,
                absolute,
            },
            Some(absolute) if absolute > self.base => DynamicLookupResult::PostBase {
                index: absolute - self.base,
                absolute,
            },
            _ => DynamicLookupResult::NotFound,
        }
    }

    fn can_insert(&mut self, field: &HeaderField) -> bool {
        let lower_bound = if field.mem_size() <= self.table.mem_limit {
            self.table.mem_limit - field.mem_size()
        } else {
            0
        };
        let mut hypothetic_mem_size = self.table.curr_mem_size;

        while !self.table.fields.is_empty() && self.table.curr_mem_size > lower_bound {
            hypothetic_mem_size -= field.mem_size();
        }

        field.mem_size() <= self.table.mem_limit - hypothetic_mem_size
    }

    fn insert(&mut self, field: &HeaderField) -> Result<DynamicInsertionResult, Error> {
        let index = self.table.put_field(field.clone())?;

        let name_map = self.table.name_map.as_mut().unwrap();
        let field_map = self.table.field_map.as_mut().unwrap();

        match field_map.entry(field.clone()) {
            Entry::Occupied(mut e) => {
                let ref_index = e.insert(index);
                name_map
                    .entry(field.name.clone())
                    .and_modify(|i| *i = index);

                return Ok(DynamicInsertionResult::Duplicated {
                    relative: index - ref_index - 1,
                    postbase: index - self.base - 1,
                    absolute: index,
                });
            }
            Entry::Vacant(e) => {
                e.insert(index);
            }
        }

        let result = match name_map.entry(field.name.clone()) {
            Entry::Occupied(mut e) => {
                let ref_index = e.insert(index);
                DynamicInsertionResult::InsertedWithNameRef {
                    postbase: index - self.base - 1,
                    relative: index - ref_index - 1,
                    absolute: index,
                }
            }
            Entry::Vacant(e) => {
                e.insert(index);
                DynamicInsertionResult::Inserted {
                    postbase: index - self.base - 1,
                    absolute: index,
                }
            }
        };
        Ok(result)
    }
}

#[derive(Debug, PartialEq)]
pub enum DynamicLookupResult {
    Relative { index: usize, absolute: usize },
    PostBase { index: usize, absolute: usize },
    NotFound,
}

#[derive(Debug, PartialEq)]
pub enum DynamicInsertionResult {
    Inserted {
        postbase: usize,
        absolute: usize,
    },
    Duplicated {
        relative: usize,
        postbase: usize,
        absolute: usize,
    },
    InsertedWithNameRef {
        postbase: usize,
        relative: usize,
        absolute: usize,
    },
}

pub struct DynamicTable {
    fields: VecDeque<HeaderField>,
    curr_mem_size: usize,
    mem_limit: usize,
    vas: VirtualAddressSpace,
    field_map: Option<HashMap<HeaderField, usize>>,
    name_map: Option<HashMap<Cow<'static, [u8]>, usize>>,
}

impl DynamicTable {
    pub fn new() -> DynamicTable {
        DynamicTable {
            fields: VecDeque::new(),
            curr_mem_size: 0,
            mem_limit: SETTINGS_HEADER_TABLE_SIZE_DEFAULT,
            vas: VirtualAddressSpace::new(),
            name_map: None,
            field_map: None,
        }
    }

    pub fn decoder<'a>(&'a self, base: usize) -> DynamicTableDecoder<'a> {
        DynamicTableDecoder { table: self, base }
    }

    pub fn inserter<'a>(&'a mut self) -> DynamicTableInserter<'a> {
        DynamicTableInserter { table: self }
    }

    pub fn encoder<'a>(&'a mut self) -> DynamicTableEncoder<'a> {
        // TODO maintain tracking data and update maps instead of recontructing them
        if self.name_map.is_none() {
            self.name_map = Some(
                self.fields
                    .iter()
                    .enumerate()
                    .map(|(idx, field)| (field.name.clone(), idx + 1))
                    .collect(),
            );
        }

        if self.field_map.is_none() {
            // TODO here Rc<HeaderField> might be useful ?
            self.field_map = Some(
                self.fields
                    .iter()
                    .enumerate()
                    .map(|(idx, field)| (field.clone(), idx + 1))
                    .collect(),
            );
        }
        DynamicTableEncoder {
            base: self.vas.largest_ref(),
            table: self,
        }
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

    fn put_field(&mut self, field: HeaderField) -> Result<usize, Error> {
        let at_most = if field.mem_size() <= self.mem_limit {
            self.mem_limit - field.mem_size()
        } else {
            0
        };
        let dropped = self.shrink_to(at_most);

        let available = self.mem_limit - self.curr_mem_size;
        let can_add = field.mem_size() <= available;
        if !can_add {
            return Err(Error::MaxTableSizeReached);
        }

        self.curr_mem_size += field.mem_size();
        self.fields.push_back(field);
        let absolute = self.vas.add();
        self.vas.drop_many(dropped);

        Ok(absolute)
    }

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

impl From<vas::Error> for Error {
    fn from(e: vas::Error) -> Self {
        match e {
            vas::Error::BadRelativeIndex(e) => Error::BadRelativeIndex(e),
            vas::Error::BadPostbaseIndex(e) => Error::BadPostbaseIndex(e),
            vas::Error::BadAbsoluteIndex(e) => Error::BadIndex(e),
        }
    }
}

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

    fn insert_fields(table: &mut DynamicTable, fields: Vec<HeaderField>) {
        let mut inserter = table.inserter();
        for field in fields {
            inserter.put_field(field).unwrap();
        }
    }

    /**
     * https://tools.ietf.org/html/draft-ietf-quic-qpack-01#section-2.2
     * "This mechanism can be used to completely clear entries from the
     *  dynamic table by setting a maximum size of 0, which can subsequently
     *  be restored."
     */
    #[test]
    fn test_set_maximum_table_size_to_zero_clear_entries() {
        let mut table = DynamicTable::new();
        insert_fields(
            &mut table,
            vec![
                HeaderField::new("Name", "Value"),
                HeaderField::new("Name", "Value"),
            ],
        );
        assert_eq!(table.count(), 2);

        let were_dropped = table.set_max_mem_size(0);
        assert_eq!(were_dropped, Ok(2));
        assert_eq!(table.count(), 0);
    }

    /** functional test */
    #[test]
    fn test_eviction_is_fifo() {
        let mut table = DynamicTable::new();

        insert_fields(
            &mut table,
            vec![
                HeaderField::new("Name-A", "Value-A"),
                HeaderField::new("Name-B", "Value-B"),
            ],
        );
        let perfect_size = table.curr_mem_size;
        assert!(table.set_max_mem_size(perfect_size).is_ok());

        insert_fields(&mut table, vec![HeaderField::new("Name-C", "Value-C")]);

        assert_eq!(table.get(0), Ok(&HeaderField::new("Name-B", "Value-B")));
        assert_eq!(table.get(1), Ok(&HeaderField::new("Name-C", "Value-C")));
        assert_eq!(table.get(2), Err(Error::BadIndex(2)));
    }

    #[test]
    fn encoder_build() {
        let mut table = DynamicTable::new();
        let field_a = HeaderField::new("Name-A", "Value-A");
        let field_b = HeaderField::new("Name-B", "Value-B");
        insert_fields(&mut table, vec![field_a.clone(), field_b.clone()]);

        let encoder = table.encoder();
        assert_eq!(encoder.base, 2);
        let name_map = encoder.table.name_map.as_ref().unwrap();
        let field_map = encoder.table.field_map.as_ref().unwrap();
        assert_eq!(name_map.len(), 2);
        assert_eq!(field_map.len(), 2);
        assert_eq!(name_map.get(&field_a.name).map(|x| *x), Some(1));
        assert_eq!(name_map.get(&field_b.name).map(|x| *x), Some(2));
        assert_eq!(field_map.get(&field_a).map(|x| *x), Some(1));
        assert_eq!(field_map.get(&field_b).map(|x| *x), Some(2));
    }

    #[test]
    fn encoder_find_relative() {
        let mut table = DynamicTable::new();
        let field_a = HeaderField::new("Name-A", "Value-A");
        let field_b = HeaderField::new("Name-B", "Value-B");
        insert_fields(&mut table, vec![field_a.clone(), field_b.clone()]);

        let encoder = table.encoder();
        assert_eq!(
            encoder.find(&field_a),
            DynamicLookupResult::Relative {
                index: 1,
                absolute: 1
            }
        );
        assert_eq!(
            encoder.find(&field_b),
            DynamicLookupResult::Relative {
                index: 0,
                absolute: 2
            }
        );
        assert_eq!(
            encoder.find(&HeaderField::new("Name-C", "Value-C")),
            DynamicLookupResult::NotFound
        );
        assert_eq!(
            encoder.find_name(&field_a.name),
            DynamicLookupResult::Relative {
                index: 1,
                absolute: 1
            }
        );
        assert_eq!(
            encoder.find_name(&field_b.name),
            DynamicLookupResult::Relative {
                index: 0,
                absolute: 2
            }
        );
        assert_eq!(
            encoder.find_name(&b"Name-C"[..]),
            DynamicLookupResult::NotFound
        );
    }

    #[test]
    fn encoder_insert() {
        let mut table = DynamicTable::new();
        let field_a = HeaderField::new("Name-A", "Value-A");
        let field_b = HeaderField::new("Name-B", "Value-B");
        insert_fields(&mut table, vec![field_a.clone(), field_b.clone()]);

        let mut encoder = table.encoder();
        assert_eq!(
            encoder.insert(&field_a),
            Ok(DynamicInsertionResult::Duplicated {
                postbase: 0,
                relative: 1,
                absolute: 3
            })
        );
        assert_eq!(
            encoder.insert(&field_b.with_value("New Value-B")),
            Ok(DynamicInsertionResult::InsertedWithNameRef {
                postbase: 1,
                relative: 1,
                absolute: 4,
            })
        );
        assert_eq!(
            encoder.insert(&field_b.with_value("Newer Value-B")),
            Ok(DynamicInsertionResult::InsertedWithNameRef {
                postbase: 2,
                relative: 0,
                absolute: 5,
            })
        );

        let field_c = HeaderField::new("Name-C", "Value-C");
        assert_eq!(
            encoder.insert(&field_c),
            Ok(DynamicInsertionResult::Inserted {
                postbase: 3,
                absolute: 6,
            })
        );

        assert_eq!(encoder.table.fields.len(), 6);
        let name_map = encoder.table.name_map.as_ref().unwrap();
        let field_map = encoder.table.field_map.as_ref().unwrap();

        assert_eq!(
            encoder.table.fields,
            &[
                field_a.clone(),
                field_b.clone(),
                field_a.clone(),
                field_b.with_value("New Value-B"),
                field_b.with_value("Newer Value-B"),
                field_c
            ]
        );
        assert_eq!(name_map.get(&field_a.name).map(|x| *x), Some(3));
        assert_eq!(name_map.get(&field_b.name).map(|x| *x), Some(5));
        assert_eq!(field_map.get(&field_a).map(|x| *x), Some(3));
        assert_eq!(field_map.get(&field_b).map(|x| *x), Some(2));
    }

    #[test]
    fn encode_insert_in_empty() {
        let mut table = DynamicTable::new();
        let field_a = HeaderField::new("Name-A", "Value-A");

        let mut encoder = table.encoder();
        assert_eq!(
            encoder.insert(&field_a),
            Ok(DynamicInsertionResult::Inserted {
                postbase: 0,
                absolute: 1,
            })
        );

        assert_eq!(encoder.table.fields.len(), 1);
        let name_map = encoder.table.name_map.as_ref().unwrap();
        let field_map = encoder.table.field_map.as_ref().unwrap();
        assert_eq!(encoder.table.fields, &[field_a.clone()]);
        assert_eq!(name_map.get(&field_a.name).map(|x| *x), Some(1));
        assert_eq!(field_map.get(&field_a).map(|x| *x), Some(1));
    }

    #[test]
    fn encode_cannot_insert() {
        let mut table = DynamicTable::new();
        table.set_max_mem_size(31).unwrap();
        let field = HeaderField::new("Name-A", "Value-A");

        let mut encoder = table.encoder();
        assert!(!encoder.can_insert(&field));
        assert_eq!(encoder.insert(&field), Err(Error::MaxTableSizeReached));

        assert_eq!(encoder.table.fields.len(), 0);
    }
}
