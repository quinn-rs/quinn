// This is only here because qpack is new and quinn no uses it yet.
// TODO remove allow dead code
#![allow(dead_code)]

use std::collections::VecDeque;

use super::field::HeaderField;


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
     * 
     * @returns Flag to test if field is really in the table, \
     * Number of fields removed to have enough space for the field
     */
    pub fn put_field(&mut self, field: HeaderField) -> (bool, usize) {
        let dropped = 
            if field.mem_size() <= self.mem_limit {
                let at_most = self.mem_limit - field.mem_size();
                self.shrink_to_fit(at_most)
            } 
            else { 0 };

        let available = self.mem_limit - self.curr_mem_size;
        let addable = field.mem_size() <= available;
        if addable {
            self.curr_mem_size += field.mem_size();
            self.fields.push_back(field);
        }

        (addable, dropped)
    }

    /**
     * @returns Number of fields removed by resizing
     */
    pub fn set_max_mem_size(&mut self, size: usize) -> Result<usize, ErrorKind> {
        if size > SETTINGS_HEADER_TABLE_SIZE {
            return Err(ErrorKind::MaximumTableSizeTooLarge);
        }
        let dropped = self.shrink_to_fit(size);
        self.mem_limit = size;
        Ok(dropped)
    }

    /**
     * https://tools.ietf.org/html/rfc7541
     * 4.4.  Entry Eviction When Adding New Entries
     * 
     * @returns Number of fields removed
     */
    fn shrink_to_fit(&mut self, lower_bound: usize) -> usize {
        let initial = self.fields.len();
        
        while !self.fields.is_empty() && self.curr_mem_size > lower_bound {
            let field = self.fields.pop_front()
                .expect("there is at least one field");
            self.curr_mem_size -= field.mem_size();
        }
        
        initial - self.fields.len()
    }

    pub fn max_mem_size(&self) -> usize {
        self.mem_limit
    }

    pub fn mem_size(&self) -> usize {
        self.curr_mem_size
    }

    pub fn get(&self, index: usize) -> Option<&HeaderField> {
        self.fields.get(index)
    }
    
    pub fn count(&self) -> usize {
        self.fields.len()
    }
}


#[cfg(test)]
mod tests {
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
            let field = HeaderField::new(pair.0, pair.1);
            table.put_field(field);
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
        assert!(res_change.is_ok());
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
        assert!(res_change.is_ok());
    }

    /**
     * https://tools.ietf.org/html/rfc7541#section-4.4
     * 4.2.  Maximum Table Size
     */
    #[test]
    fn test_fields_can_fit_up_to_the_last_byte() {
        let mut table = DynamicTable::new();
        assert!(table.set_max_mem_size(200).is_ok());

        table.put_field(HeaderField::new("Name", "Value"));
        assert_eq!(table.count(), 1);

        let size = table.mem_size();
        assert!(table.set_max_mem_size(size).is_ok());
        assert_eq!(table.count(), 1);
    }

    /**
     * https://tools.ietf.org/html/rfc7541#section-4.4
     * 4.2.  Maximum Table Size
     */
    #[test]
    fn test_null_maximum_table_size_purge_all_fields() {
        let mut table = DynamicTable::new();
        assert!(table.set_max_mem_size(200).is_ok());

        table.put_field(HeaderField::new("Name", "Value"));
        assert_eq!(table.count(), 1);

        assert!(table.set_max_mem_size(0).is_ok());
        assert_eq!(table.count(), 0);
    }

    /**
     * https://tools.ietf.org/html/rfc7541#section-4.4
     * 4.3.  Entry Eviction When Dynamic Table Size Changes
     */
    #[test]
    fn test_set_narrow_maximum_table_size_drop_fields_to_fit() {
        let mut table = DynamicTable::new();
        assert!(table.set_max_mem_size(200).is_ok());

        table.put_field(HeaderField::new("Name-1", "Value-1"));
        table.put_field(HeaderField::new("Name-2", "Value-2"));
        table.put_field(HeaderField::new("Name-3", "Value-3"));
        assert_eq!(table.count(), 3);

        let size_to_drop_first_field = table.mem_size() - 1;
        assert!(table.set_max_mem_size(size_to_drop_first_field).is_ok());
        assert_eq!(table.count(), 2);
    }
    
    /**
     * https://tools.ietf.org/html/rfc7541#section-4.4
     * 4.3.  Entry Eviction When Dynamic Table Size Changes
     */
    #[test]
    fn test_drop_fields_are_in_fifo() {
        let mut table = DynamicTable::new();
        assert!(table.set_max_mem_size(200).is_ok());

        let second_field = HeaderField::new("Name-2", "Value-2");

        table.put_field(HeaderField::new("Name-1", "Value-1"));
        table.put_field(second_field.clone());
        table.put_field(HeaderField::new("Name-3", "Value-3"));
        assert_eq!(table.count(), 3);

        let size_to_drop_first_field = table.mem_size() - 1;
        assert!(table.set_max_mem_size(size_to_drop_first_field).is_ok());
        assert_eq!(table.get(0), Some(&second_field));
    }
    
    /**
     * https://tools.ietf.org/html/rfc7541#section-4.4
     * 4.4.  Entry Eviction When Adding New Entries
     */
    #[test]
    fn test_put_field_drop_previous_fields_to_fit() {
        let mut table = DynamicTable::new();
        assert!(table.set_max_mem_size(200).is_ok());

        table.put_field(HeaderField::new("Name", "Value"));
        table.put_field(HeaderField::new("Name", "Value"));
        table.put_field(HeaderField::new("Name", "Value"));

        let size = table.mem_size();
        assert!(table.set_max_mem_size(size).is_ok());
        assert_eq!(table.count(), 3);

        // header field that take two of the previous fields
        table.put_field(HeaderField::new("NameName", "ValueValue"));
        assert_eq!(table.count(), 2);
    }

    /**
     * https://tools.ietf.org/html/rfc7541#section-4.4
     * 4.4.  Entry Eviction When Adding New Entries
     */
    #[test]
    fn test_put_field_too_large_makes_it_evicted() {
        let mut table = DynamicTable::new();
        assert!(table.set_max_mem_size(200).is_ok());

        table.put_field(HeaderField::new("Name", "Value"));

        let size = table.mem_size();
        assert!(table.set_max_mem_size(size).is_ok());
        assert_eq!(table.count(), 1);

        table.put_field(HeaderField::new("NameName", "ValueValue"));
        assert_eq!(table.count(), 0);
    }
}
