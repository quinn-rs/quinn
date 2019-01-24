use std::borrow::Cow;
use std::collections::btree_map::Entry as BTEntry;
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap, VecDeque};

use super::field::HeaderField;
use super::static_::StaticTable;
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
const SETTINGS_HEADER_TABLE_SIZE_MAX: usize = 1073741823; // 2^30 -1

#[derive(Debug, PartialEq)]
pub enum Error {
    BadRelativeIndex(usize),
    BadPostbaseIndex(usize),
    BadIndex(usize),
    MaxTableSizeReached,
    MaximumTableSizeTooLarge,
    UnknownStreamId(u64),
    NoTrackingData,
    InvalidTrackingCount,
}

pub struct DynamicTableDecoder<'a> {
    table: &'a DynamicTable,
    base: usize,
}

impl<'a> DynamicTableDecoder<'a> {
    pub(super) fn get_relative(&self, index: usize) -> Result<&HeaderField, Error> {
        let real_index = self.table.vas.relative_base(self.base, index)?;
        self.table
            .fields
            .get(real_index)
            .ok_or(Error::BadIndex(real_index))
    }

    pub(super) fn get_postbase(&self, index: usize) -> Result<&HeaderField, Error> {
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
    pub(super) fn put_field(&mut self, field: HeaderField) -> Result<(), Error> {
        let index = if let Some(index) = self.table.put_field(field.clone())? {
            index
        } else {
            return Ok(());
        };

        if self.table.name_map.is_none() {
            return Ok(());
        }

        let name_map = self.table.name_map.as_mut().unwrap();
        let field_map = self.table.field_map.as_mut().unwrap();

        field_map
            .entry(field.clone())
            .and_modify(|e| *e = index)
            .or_insert(index);

        if StaticTable::find_name(&field.name).is_some() {
            return Ok(());
        }

        name_map
            .entry(field.name.clone())
            .and_modify(|e| *e = index)
            .or_insert(index);
        Ok(())
    }

    pub(super) fn get_relative(&self, index: usize) -> Result<&HeaderField, Error> {
        let real_index = self.table.vas.relative(index)?;
        self.table
            .fields
            .get(real_index)
            .ok_or(Error::BadIndex(real_index))
    }

    pub fn set_max_mem_size(&mut self, size: usize) -> Result<(), Error> {
        if size > SETTINGS_HEADER_TABLE_SIZE_MAX {
            return Err(Error::MaximumTableSizeTooLarge);
        }

        if size >= self.table.mem_limit {
            self.table.mem_limit = size;
            return Ok(());
        }

        let required = self.table.mem_limit - size;

        if let Some(to_evict) = self.table.can_free(required)? {
            self.table.evict(to_evict)?;
        }

        self.table.mem_limit = size;
        Ok(())
    }

    pub(super) fn total_inserted(&self) -> usize {
        self.table.vas.total_inserted()
    }
}

pub struct DynamicTableEncoder<'a> {
    table: &'a mut DynamicTable,
    base: usize,
    commited: bool,
    stream_id: u64,
    block_refs: HashMap<usize, usize>,
}

impl<'a> Drop for DynamicTableEncoder<'a> {
    fn drop(&mut self) {
        if !self.commited {
            // TODO maybe possible to replace and not clone here?
            // HOW Err should be handled?
            self.table
                .track_cancel(self.block_refs.iter().map(|(x, y)| (*x, *y)))
                .ok();
            return;
        }

        self.table
            .track_block(self.stream_id, self.block_refs.clone());
    }
}

impl<'a> DynamicTableEncoder<'a> {
    pub(super) fn commit(&mut self) {
        self.commited = true;
    }

    pub(super) fn find(&mut self, field: &HeaderField) -> DynamicLookupResult {
        self.lookup_result(
            self.table
                .field_map
                .as_ref()
                .unwrap()
                .get(field)
                .map(|x| *x),
        )
    }

    fn lookup_result(&mut self, abolute: Option<usize>) -> DynamicLookupResult {
        match abolute {
            Some(absolute) if absolute <= self.base => {
                self.track_ref(absolute);
                DynamicLookupResult::Relative {
                    index: self.base - absolute,
                    absolute,
                }
            }
            Some(absolute) if absolute > self.base => {
                self.track_ref(absolute);
                DynamicLookupResult::PostBase {
                    index: absolute - self.base - 1,
                    absolute,
                }
            }
            _ => DynamicLookupResult::NotFound,
        }
    }

    pub(super) fn insert(&mut self, field: &HeaderField) -> Result<DynamicInsertionResult, Error> {
        let index = if let Some(index) = self.table.put_field(field.clone())? {
            index
        } else {
            return Ok(DynamicInsertionResult::NotInserted(
                self.find_name(&field.name),
            ));
        };
        self.track_ref(index);

        let name_map = self.table.name_map.as_mut().unwrap();
        let field_map = self.table.field_map.as_mut().unwrap();

        let field_index = match field_map.entry(field.clone()) {
            Entry::Occupied(mut e) => {
                let ref_index = e.insert(index);
                name_map
                    .entry(field.name.clone())
                    .and_modify(|i| *i = index);

                Some((
                    ref_index,
                    DynamicInsertionResult::Duplicated {
                        relative: index - ref_index - 1,
                        postbase: index - self.base - 1,
                        absolute: index,
                    },
                ))
            }
            Entry::Vacant(e) => {
                e.insert(index);
                None
            }
        };

        if let Some((ref_index, result)) = field_index {
            self.track_ref(ref_index);
            return Ok(result);
        }

        if let Some(static_idx) = StaticTable::find_name(&field.name) {
            return Ok(DynamicInsertionResult::InsertedWithStaticNameRef {
                postbase: index - self.base - 1,
                index: static_idx,
                absolute: index,
            });
        }

        let result = match name_map.entry(field.name.clone()) {
            Entry::Occupied(mut e) => {
                let ref_index = e.insert(index);
                self.track_ref(ref_index);

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

    fn find_name(&mut self, name: &[u8]) -> DynamicLookupResult {
        if let Some(index) = StaticTable::find_name(name) {
            return DynamicLookupResult::Static(index);
        }

        self.lookup_result(self.table.name_map.as_ref().unwrap().get(name).map(|x| *x))
    }

    fn track_ref(&mut self, reference: usize) {
        self.block_refs
            .entry(reference)
            .and_modify(|c| *c += 1)
            .or_insert(1);
        self.table.track_ref(reference);
    }

    pub(super) fn max_mem_size(&self) -> usize {
        self.table.mem_limit
    }

    pub(super) fn base(&self) -> usize {
        self.base
    }

    pub(super) fn total_inserted(&self) -> usize {
        self.table.total_inserted()
    }
}

#[derive(Debug, PartialEq)]
pub enum DynamicLookupResult {
    Static(usize),
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
    InsertedWithStaticNameRef {
        postbase: usize,
        index: usize,
        absolute: usize,
    },
    NotInserted(DynamicLookupResult),
}

pub struct DynamicTable {
    fields: VecDeque<HeaderField>,
    curr_mem_size: usize,
    mem_limit: usize,
    vas: VirtualAddressSpace,
    field_map: Option<HashMap<HeaderField, usize>>,
    name_map: Option<HashMap<Cow<'static, [u8]>, usize>>,
    track_map: Option<BTreeMap<usize, usize>>,
    track_blocks: Option<HashMap<u64, HashMap<usize, usize>>>,
    largest_known_recieved: usize,
}

#[allow(dead_code)]
impl DynamicTable {
    pub fn new() -> DynamicTable {
        DynamicTable {
            fields: VecDeque::new(),
            curr_mem_size: 0,
            mem_limit: SETTINGS_HEADER_TABLE_SIZE_DEFAULT,
            vas: VirtualAddressSpace::new(),
            name_map: None,
            field_map: None,
            track_map: None,
            track_blocks: None,
            largest_known_recieved: 0,
        }
    }

    pub fn decoder<'a>(&'a self, base: usize) -> DynamicTableDecoder<'a> {
        DynamicTableDecoder { table: self, base }
    }

    pub fn inserter<'a>(&'a mut self) -> DynamicTableInserter<'a> {
        DynamicTableInserter { table: self }
    }

    pub fn encoder<'a>(&'a mut self, stream_id: u64) -> DynamicTableEncoder<'a> {
        if self.name_map.is_none() {
            self.name_map = Some(HashMap::new());
            self.field_map = Some(HashMap::new());

            for (idx, field) in self.fields.iter().enumerate() {
                self.name_map
                    .as_mut()
                    .unwrap()
                    .insert(field.name.clone(), self.vas.index(idx).unwrap()); // XXX
                self.field_map
                    .as_mut()
                    .unwrap()
                    .insert(field.clone(), self.vas.index(idx).unwrap());
            }
        }

        DynamicTableEncoder {
            base: self.vas.largest_ref(),
            table: self,
            block_refs: HashMap::new(),
            commited: false,
            stream_id,
        }
    }

    pub(super) fn total_inserted(&self) -> usize {
        self.vas.total_inserted()
    }

    pub(super) fn untrack_block(&mut self, stream_id: u64) -> Result<(), Error> {
        if self.track_blocks.is_none() || self.track_map.is_none() {
            return Err(Error::NoTrackingData);
        }

        if let Some(bloc_entry) = self.track_blocks.as_mut().unwrap().remove(&stream_id) {
            self.track_cancel(bloc_entry.iter().map(|(x, y)| (*x, *y)))?;
            Ok(())
        } else {
            Err(Error::UnknownStreamId(stream_id))
        }
    }

    fn put_field(&mut self, field: HeaderField) -> Result<Option<usize>, Error> {
        if self.mem_limit == 0 {
            return Ok(None);
        }

        match self.can_free(field.mem_size())? {
            None => return Ok(None),
            Some(x) if x <= 0 => (),
            Some(to_evict) => {
                self.evict(to_evict)?;
            }
        }

        self.curr_mem_size += field.mem_size();
        self.fields.push_back(field);
        let absolute = self.vas.add();

        Ok(Some(absolute))
    }

    fn evict(&mut self, to_evict: usize) -> Result<(), Error> {
        for _ in 0..to_evict {
            let field = self.fields.pop_front().ok_or(Error::MaxTableSizeReached)?; //TODO better type
            self.curr_mem_size -= field.mem_size();
        }
        self.vas.drop_many(to_evict);
        Ok(())
    }

    fn can_free(&mut self, required: usize) -> Result<Option<usize>, Error> {
        if required > self.mem_limit {
            return Err(Error::MaxTableSizeReached);
        }

        if self.mem_limit - self.curr_mem_size >= required {
            return Ok(Some(0));
        }
        let lower_bound = self.mem_limit - required;

        let mut hypothetic_mem_size = self.curr_mem_size;
        let mut evictable = 0;

        for (idx, to_evict) in self.fields.iter().enumerate() {
            if hypothetic_mem_size <= lower_bound {
                break;
            }

            if self.is_tracked(self.vas.index(idx).unwrap()) {
                // TODO handle out of bounds error
                break;
            }

            evictable += 1;
            hypothetic_mem_size -= to_evict.mem_size();
        }

        if required <= self.mem_limit - hypothetic_mem_size {
            Ok(Some(evictable))
        } else {
            Ok(None)
        }
    }

    fn track_ref(&mut self, reference: usize) {
        if self.track_map.is_none() {
            self.track_map = Some(BTreeMap::new());
        }

        self.track_map
            .as_mut()
            .unwrap()
            .entry(reference)
            .and_modify(|c| *c += 1)
            .or_insert(1);
    }

    fn is_tracked(&self, reference: usize) -> bool {
        if self.track_map.is_none() {
            return false;
        }
        match self.track_map.as_ref().unwrap().get(&reference) {
            Some(count) if *count > 0 => true,
            _ => false,
        }
    }

    fn track_block(&mut self, stream_id: u64, refs: HashMap<usize, usize>) {
        if self.track_blocks.is_none() {
            self.track_blocks = Some(HashMap::new());
        }

        if self.track_blocks.as_ref().unwrap().contains_key(&stream_id) {
            self.untrack_block(stream_id).ok();
        }

        match self.track_blocks.as_mut().unwrap().entry(stream_id) {
            Entry::Occupied(mut e) => {
                e.insert(refs);
            }
            Entry::Vacant(e) => {
                e.insert(refs);
            }
        }
    }

    fn track_cancel<T>(&mut self, refs: T) -> Result<(), Error>
    where
        T: IntoIterator<Item = (usize, usize)>,
    {
        if self.track_map.is_none() {
            return Err(Error::NoTrackingData);
        }

        for (reference, count) in refs {
            match self.track_map.as_mut().unwrap().entry(reference) {
                BTEntry::Occupied(mut e) => {
                    if *e.get() < count {
                        return Err(Error::InvalidTrackingCount);
                    } else if *e.get() == count {
                        e.remove(); // TODO just pu 0 ?
                    } else {
                        let entry = e.get_mut();
                        *entry -= count;
                    }
                }
                BTEntry::Vacant(_) => return Err(Error::InvalidTrackingCount),
            }
        }
        Ok(())
    }

    pub fn update_largest_recieved(&mut self, index: usize) {
        self.largest_known_recieved = std::cmp::max(index, self.largest_known_recieved);
    }

    pub(super) fn max_mem_size(&self) -> usize {
        self.mem_limit
    }

    fn get(&self, index: usize) -> Result<&HeaderField, Error> {
        match self.fields.get(index) {
            Some(f) => Ok(f),
            None => Err(Error::BadIndex(index)),
        }
    }
}

impl From<vas::Error> for Error {
    fn from(e: vas::Error) -> Self {
        match e {
            vas::Error::BadRelativeIndex(e) => Error::BadRelativeIndex(e),
            vas::Error::BadPostbaseIndex(e) => Error::BadPostbaseIndex(e),
            vas::Error::BadIndex(e) => Error::BadIndex(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qpack::static_::StaticTable;

    const STREAM_ID: u64 = 0x4;

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
        let res_change = table.inserter().set_max_mem_size(invalid_size);
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
        let res_change = table.inserter().set_max_mem_size(0);
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
        let res_change = table
            .inserter()
            .set_max_mem_size(SETTINGS_HEADER_TABLE_SIZE_MAX);
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
        assert_eq!(table.fields.len(), 2);
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
        assert!(table.inserter().set_max_mem_size(perfect_size).is_ok());

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
        assert!(table.inserter().set_max_mem_size(perfect_size).is_ok());

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
        assert_eq!(table.fields.len(), 2);

        table.inserter().set_max_mem_size(0).unwrap();
        assert_eq!(table.fields.len(), 0);
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
        assert!(table.inserter().set_max_mem_size(perfect_size).is_ok());

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

        let encoder = table.encoder(STREAM_ID);
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

        let mut encoder = table.encoder(STREAM_ID);
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

        let mut encoder = table.encoder(STREAM_ID);
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
        assert_eq!(
            field_map
                .get(&field_b.with_value("New Value-B"))
                .map(|x| *x),
            Some(4)
        );
        assert_eq!(
            field_map
                .get(&field_b.with_value("Newer Value-B"))
                .map(|x| *x),
            Some(5)
        );
    }

    #[test]
    fn encode_insert_in_empty() {
        let mut table = DynamicTable::new();
        let field_a = HeaderField::new("Name-A", "Value-A");

        let mut encoder = table.encoder(STREAM_ID);
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
    fn insert_static() {
        let mut table = DynamicTable::new();
        let field = HeaderField::new(":method", "Value-A");
        table.inserter().put_field(field.clone()).unwrap();

        assert_eq!(StaticTable::find_name(&field.name), Some(21));
        let mut encoder = table.encoder(STREAM_ID);
        assert_eq!(
            encoder.insert(&field),
            Ok(DynamicInsertionResult::Duplicated {
                relative: 0,
                postbase: 0,
                absolute: 2
            })
        );
        assert_eq!(
            encoder.insert(&field.with_value("Value-B")),
            Ok(DynamicInsertionResult::InsertedWithStaticNameRef {
                postbase: 1,
                index: 21,
                absolute: 3
            })
        );
        assert_eq!(
            encoder.insert(&HeaderField::new(":path", "/baz")),
            Ok(DynamicInsertionResult::InsertedWithStaticNameRef {
                postbase: 2,
                index: 1,
                absolute: 4,
            })
        );
        assert_eq!(encoder.table.fields.len(), 4);
    }

    #[test]
    fn cannot_insert_field_greater_than_total_size() {
        let mut table = DynamicTable::new();
        table.inserter().set_max_mem_size(33).unwrap();
        let mut encoder = table.encoder(4);
        assert_eq!(
            encoder.insert(&HeaderField::new("foo", "bar")),
            Err(Error::MaxTableSizeReached)
        );
    }

    #[test]
    fn encoder_can_evict_unreferenced() {
        let mut table = DynamicTable::new();
        table.inserter().set_max_mem_size(63).unwrap();
        table.put_field(HeaderField::new("foo", "bar")).unwrap();

        assert_eq!(table.fields.len(), 1);
        assert_eq!(
            table.encoder(4).insert(&HeaderField::new("baz", "quxx")),
            Ok(DynamicInsertionResult::Inserted {
                postbase: 0,
                absolute: 2,
            })
        );
        assert_eq!(table.fields.len(), 1);
    }

    #[test]
    fn encoder_insertion_tracks_ref() {
        let mut table = DynamicTable::new();
        let mut encoder = table.encoder(4);
        assert_eq!(
            encoder.insert(&HeaderField::new("baz", "quxx")),
            Ok(DynamicInsertionResult::Inserted {
                postbase: 0,
                absolute: 1,
            })
        );
        assert_eq!(
            encoder
                .table
                .track_map
                .as_ref()
                .unwrap()
                .get(&1)
                .map(|x| *x),
            Some(1)
        );
        assert_eq!(encoder.block_refs.get(&1).map(|x| *x), Some(1));
    }

    #[test]
    fn encoder_insertion_refs_commited() {
        let mut table = DynamicTable::new();
        let stream_id = 42;
        {
            let mut encoder = table.encoder(stream_id);
            for idx in 1..4 {
                encoder
                    .insert(&HeaderField::new(format!("foo{}", idx), "quxx"))
                    .unwrap();
            }
            assert_eq!(encoder.block_refs.len(), 3);
            encoder.commit();
        }

        let track_map = table.track_map.as_ref().unwrap();
        for idx in 1..4 {
            assert_eq!(table.is_tracked(idx), true);
            assert_eq!(track_map.get(&1), Some(&1));
        }
        let track_blocks = table.track_blocks.as_ref().unwrap();
        let block = track_blocks.get(&stream_id).unwrap();
        assert_eq!(block.get(&1), Some(&1));
        assert_eq!(block.get(&2), Some(&1));
        assert_eq!(block.get(&3), Some(&1));
    }

    #[test]
    fn encoder_insertion_refs_not_commited() {
        let mut table = DynamicTable::new();
        table.track_blocks = Some(HashMap::new());
        let stream_id = 42;
        {
            let mut encoder = table.encoder(stream_id);
            for idx in 1..4 {
                encoder
                    .insert(&HeaderField::new(format!("foo{}", idx), "quxx"))
                    .unwrap();
            }
            assert_eq!(encoder.block_refs.len(), 3);
        } // dropped without ::commit()

        let track_map = table.track_map.as_ref().unwrap();
        assert_eq!(track_map.len(), 0);
        let track_blocks = table.track_blocks.as_ref().unwrap();
        assert_eq!(track_blocks.len(), 0);
    }

    #[test]
    fn encoder_insertion_with_ref_tracks_both() {
        let mut table = DynamicTable::new();
        table.put_field(HeaderField::new("foo", "bar")).unwrap();
        table.track_blocks = Some(HashMap::new());

        let stream_id = 42;
        let mut encoder = table.encoder(stream_id);
        assert_eq!(
            encoder.insert(&HeaderField::new("foo", "quxx")),
            Ok(DynamicInsertionResult::InsertedWithNameRef {
                postbase: 0,
                relative: 0,
                absolute: 2,
            })
        );

        let track_map = encoder.table.track_map.as_ref().unwrap();
        assert_eq!(track_map.get(&1), Some(&1));
        assert_eq!(track_map.get(&2), Some(&1));
        assert_eq!(encoder.block_refs.get(&1), Some(&1));
        assert_eq!(encoder.block_refs.get(&2), Some(&1));
    }

    #[test]
    fn encoder_ref_count_are_incremented() {
        let mut table = DynamicTable::new();
        table.put_field(HeaderField::new("foo", "bar")).unwrap();
        table.track_blocks = Some(HashMap::new());
        table.track_ref(1);

        let stream_id = 42;
        {
            let mut encoder = table.encoder(stream_id);
            encoder.track_ref(1);
            encoder.track_ref(2);
            encoder.track_ref(2);

            let track_map = encoder.table.track_map.as_ref().unwrap();
            assert_eq!(track_map.get(&1), Some(&2));
            assert_eq!(track_map.get(&2), Some(&2));
            assert_eq!(encoder.block_refs.get(&1), Some(&1));
            assert_eq!(encoder.block_refs.get(&2), Some(&2));
        }

        // check ref count is correctly decremented after uncommited drop()
        let track_map = table.track_map.as_ref().unwrap();
        assert_eq!(track_map.get(&1), Some(&1));
        assert_eq!(track_map.get(&2), None);
    }

    #[test]
    fn encoder_does_not_evict_referenced() {
        let mut table = DynamicTable::new();
        table.inserter().set_max_mem_size(95).unwrap();
        table.put_field(HeaderField::new("foo", "bar")).unwrap();

        let stream_id = 42;
        let mut encoder = table.encoder(stream_id);
        assert_eq!(
            encoder.insert(&HeaderField::new("foo", "quxx")),
            Ok(DynamicInsertionResult::InsertedWithNameRef {
                postbase: 0,
                relative: 0,
                absolute: 2,
            })
        );
        assert!(encoder.table.is_tracked(1));
        assert_eq!(
            encoder.insert(&HeaderField::new("foo", "baz")),
            Ok(DynamicInsertionResult::NotInserted(
                DynamicLookupResult::PostBase {
                    index: 0,
                    absolute: 2,
                }
            ))
        );
        assert_eq!(encoder.table.fields.len(), 2);
    }

    fn tracked_table(stream_id: u64) -> DynamicTable {
        let mut table = DynamicTable::new();
        table.track_blocks = Some(HashMap::new());
        {
            let mut encoder = table.encoder(stream_id);
            for idx in 1..4 {
                encoder
                    .insert(&HeaderField::new(format!("foo{}", idx), "quxx"))
                    .unwrap();
            }
            assert_eq!(encoder.block_refs.len(), 3);
            encoder.commit();
        }
        table
    }

    #[test]
    fn untrack_block() {
        let mut table = tracked_table(42);
        assert_eq!(table.track_map.as_ref().unwrap().len(), 3);
        assert_eq!(table.track_blocks.as_ref().unwrap().len(), 1);
        table.untrack_block(42).unwrap();
        assert_eq!(table.track_map.as_ref().unwrap().len(), 0);
        assert_eq!(table.track_blocks.as_ref().unwrap().len(), 0);
    }

    #[test]
    fn untrack_block_not_in_map() {
        let mut table = tracked_table(42);
        table.track_map.as_mut().unwrap().remove(&2);
        assert_eq!(table.untrack_block(42), Err(Error::InvalidTrackingCount));
    }

    #[test]
    fn untrack_block_wrong_count() {
        let mut table = tracked_table(42);
        table
            .track_blocks
            .as_mut()
            .unwrap()
            .entry(42)
            .and_modify(|x| {
                x.entry(2).and_modify(|c| *c += 1);
            });
        assert_eq!(table.untrack_block(42), Err(Error::InvalidTrackingCount));
    }

    #[test]
    fn untrack_bloc_wrong_stream() {
        let mut table = tracked_table(41);
        assert_eq!(table.untrack_block(42), Err(Error::UnknownStreamId(42)));
    }

    #[test]
    fn inserter_updates_maps() {
        let mut table = tracked_table(42);
        assert_eq!(table.name_map.as_ref().unwrap().len(), 3);
        assert_eq!(table.field_map.as_ref().unwrap().len(), 3);

        table
            .inserter()
            .put_field(HeaderField::new("foo", "bar"))
            .unwrap();
        assert_eq!(table.name_map.as_ref().unwrap().len(), 4);
        assert_eq!(table.field_map.as_ref().unwrap().len(), 4);

        let field = HeaderField::new("foo1", "quxx");
        table.inserter().put_field(field.clone()).unwrap();
        assert_eq!(table.name_map.as_ref().unwrap().len(), 4);
        assert_eq!(table.field_map.as_ref().unwrap().len(), 4);
        assert_eq!(
            table.name_map.as_ref().unwrap().get(&b"foo1"[..]),
            Some(&5usize)
        );
        assert_eq!(table.field_map.as_ref().unwrap().get(&field), Some(&5usize));
    }
}
