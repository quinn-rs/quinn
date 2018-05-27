// This is only here because qpack is new and quinn no uses it yet.
// TODO remove allow dead code
#![allow(dead_code)]

use std::collections::VecDeque;

pub struct HeaderField {
    // TODO use Cow to avoid copy when possible
    name: String,
    value: String,
}


impl HeaderField {
    pub fn mem_size(&self) -> usize {
        self.name.len() + self.value.len()
    }
}


/**
 * https://tools.ietf.org/html/rfc7541
 * 4.1.  Calculating Table Size
 */
pub const ESTIMATED_OVERHEAD_BYTES: usize = 32;

/**
 * https://www.rfc-editor.org/rfc/rfc7540.txt
 * 6.5.2.  Defined SETTINGS Parameters
 */
pub const SETTINGS_HEADER_TABLE_SIZE: usize = 4096;


#[derive(Debug, PartialEq)]
pub enum ErrorKind {
    MaximumTableSizeTooLarge
}


pub struct DynamicTable {
    fields: VecDeque<HeaderField>,
    curr_mem_size: usize,
    mem_limit: usize,
}


impl DynamicTable {
    pub fn new() -> DynamicTable {
        DynamicTable {
            fields: VecDeque::new(),
            curr_mem_size: ESTIMATED_OVERHEAD_BYTES,
            mem_limit: SETTINGS_HEADER_TABLE_SIZE,
        }
    }

    /**
     * Adding field into the table cannot fails, but it doesn't mean the header
     * field will be put inside the table.
     */
    pub fn put_field(&mut self, name: &'static str, value: &'static str) {
        let field = HeaderField { name: name.into(), value: value.into() };

        if field.mem_size() <= self.mem_limit {
            let at_most = self.mem_limit - field.mem_size();
            self.shrink_to_fit(at_most);
        }

        let available = self.mem_limit - self.curr_mem_size;
        if field.mem_size() <= available {
            self.curr_mem_size += field.mem_size();
            self.fields.push_back(field);
        }
    }

    pub fn field_count(&self) -> usize {
        self.fields.len()
    }

    pub fn set_max_mem_size(&mut self, size: usize) -> Result<(), ErrorKind> {
        if size > SETTINGS_HEADER_TABLE_SIZE {
            return Err(ErrorKind::MaximumTableSizeTooLarge);
        }
        self.shrink_to_fit(size);
        self.mem_limit = size;
        Ok(())
    }

    /**
     * https://tools.ietf.org/html/rfc7541
     * 4.4.  Entry Eviction When Adding New Entries
     */
    fn shrink_to_fit(&mut self, lower_bound: usize) {
        while !self.fields.is_empty() && self.curr_mem_size > lower_bound {
            let field = self.fields.pop_front()
                .expect("there is at least one field");
            self.curr_mem_size -= field.mem_size();
        }
    }

    pub fn max_mem_size(&self) -> usize {
        self.mem_limit
    }

    pub fn mem_size(&self) -> usize {
        self.curr_mem_size
    }
}


#[cfg(test)]
mod table_tests {
    use super::*;

    /**
     * https://tools.ietf.org/html/rfc7541
     * 4.1.  Calculating Table Size
     */
    #[test]
    fn test_dynamic_table_size() {
        let mut table = DynamicTable::new();

        let fields: [(&'static str, &'static str); 2] = [
            ("Name", "Value"),
            ("Another-Name", ""), // no value
        ];
        let table_size = 4 + 5 + 12 + 0 + ESTIMATED_OVERHEAD_BYTES;

        for pair in fields.iter() {
            table.put_field(pair.0, pair.1);
        }

        assert_eq!(table.mem_size(), table_size);
    }

    /**
     * https://tools.ietf.org/html/rfc7541
     * 4.1.  Calculating Table Size
     */
    #[test]
    fn test_minimum_table_size_is_not_null() {
        let table = DynamicTable::new();
        assert_eq!(table.mem_size(), ESTIMATED_OVERHEAD_BYTES);
    }

    /**
     * https://tools.ietf.org/html/rfc7541#section-4.4
     * 4.2.  Maximum Table Size
     */
    #[test]
    fn test_set_too_large_maximum_table_size() {
        let mut table = DynamicTable::new();
        let invalid_size = SETTINGS_HEADER_TABLE_SIZE + 10;
        let res_change = table.set_max_mem_size(invalid_size);
        assert_eq!(res_change, Err(ErrorKind::MaximumTableSizeTooLarge));
    }

    /**
     * https://tools.ietf.org/html/rfc7541#section-4.4
     * 4.2.  Maximum Table Size
     */
    #[test]
    fn test_maximum_table_size_can_be_lower_than_table_size() {
        let mut table = DynamicTable::new();
        let res_change = table.set_max_mem_size(0);
        assert_eq!(res_change, Ok(()));
        assert_eq!(table.mem_size(), ESTIMATED_OVERHEAD_BYTES);
    }

    /**
     * https://tools.ietf.org/html/rfc7541#section-4.4
     * 4.2.  Maximum Table Size
     */
    #[test]
    fn test_set_maximum_table_size() {
        let mut table = DynamicTable::new();
        let valid_size = SETTINGS_HEADER_TABLE_SIZE / 2 + 1;
        let res_change = table.set_max_mem_size(valid_size);
        assert_eq!(res_change, Ok(()));
    }

    /**
     * https://tools.ietf.org/html/rfc7541#section-4.4
     * 4.2.  Maximum Table Size
     */
    #[test]
    fn test_fields_can_fit_up_to_the_last_byte() {
        let mut table = DynamicTable::new();
        assert_eq!(table.set_max_mem_size(200), Ok(()));

        table.put_field("Name", "Value");
        assert_eq!(table.field_count(), 1);

        let size = table.mem_size();
        assert_eq!(table.set_max_mem_size(size), Ok(()));
        assert_eq!(table.field_count(), 1);
    }

    /**
     * https://tools.ietf.org/html/rfc7541#section-4.4
     * 4.2.  Maximum Table Size
     */
    #[test]
    fn test_null_maximum_table_size_purge_all_fields() {
        let mut table = DynamicTable::new();
        assert_eq!(table.set_max_mem_size(200), Ok(()));

        table.put_field("Name", "Value");
        assert_eq!(table.field_count(), 1);

        assert_eq!(table.set_max_mem_size(0), Ok(()));
        assert_eq!(table.field_count(), 0);
    }

    /**
     * https://tools.ietf.org/html/rfc7541#section-4.4
     * 4.3.  Entry Eviction When Dynamic Table Size Changes
     */
    #[test]
    fn test_set_narrow_maximum_table_size_drop_fields_to_fit() {
        let mut table = DynamicTable::new();
        assert_eq!(table.set_max_mem_size(200), Ok(()));

        table.put_field("Name", "Value");
        table.put_field("Name", "Value");
        table.put_field("Name", "Value");
        assert_eq!(table.field_count(), 3);

        let size_to_drop_one_field = table.mem_size() - 1;
        assert_eq!(table.set_max_mem_size(size_to_drop_one_field), Ok(()));
        assert_eq!(table.field_count(), 2);
    }

    /**
     * https://tools.ietf.org/html/rfc7541#section-4.4
     * 4.4.  Entry Eviction When Adding New Entries
     */
    #[test]
    fn test_put_field_drop_previous_fields_to_fit() {
        let mut table = DynamicTable::new();
        assert_eq!(table.set_max_mem_size(200), Ok(()));

        table.put_field("Name", "Value");
        table.put_field("Name", "Value");
        table.put_field("Name", "Value");

        let size = table.mem_size();
        assert_eq!(table.set_max_mem_size(size), Ok(()));
        assert_eq!(table.field_count(), 3);

        // header field that take two of the previous fields
        table.put_field("NameName", "ValueValue");
        assert_eq!(table.field_count(), 2);
    }

    /**
     * https://tools.ietf.org/html/rfc7541#section-4.4
     * 4.4.  Entry Eviction When Adding New Entries
     */
    #[test]
    fn test_put_field_too_large_makes_it_evicted() {
        let mut table = DynamicTable::new();
        assert_eq!(table.set_max_mem_size(200), Ok(()));

        table.put_field("Name", "Value");

        let size = table.mem_size();
        assert_eq!(table.set_max_mem_size(size), Ok(()));
        assert_eq!(table.field_count(), 1);

        table.put_field("NameName", "ValueValue");
        assert_eq!(table.field_count(), 0);
    }
}
