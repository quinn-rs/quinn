use std::{
    borrow::Cow,
    collections::{btree_map::Entry as BTEntry, hash_map::Entry, BTreeMap, HashMap, VecDeque},
};

use err_derive::Error;

use super::{field::HeaderField, static_::StaticTable};
use crate::qpack::vas::{self, VirtualAddressSpace};

/**
 * https://quicwg.org/base-drafts/draft-ietf-quic-qpack.html#maximum-dynamic-table-capacity
 */
const SETTINGS_MAX_TABLE_CAPACITY_MAX: usize = 1_073_741_823; // 2^30 -1
const SETTINGS_MAX_BLOCKED_STREAMS_MAX: usize = 65_535; // 2^16 - 1

#[derive(Debug, PartialEq, Error)]
pub enum Error {
    #[error(display = "bad relative index: {}", _0)]
    BadRelativeIndex(usize),
    #[error(display = "bad post base index: {}", _0)]
    BadPostbaseIndex(usize),
    #[error(display = "decoded index out of bounds: {}", _0)]
    BadIndex(usize),
    #[error(display = "tried to insert a field greater than dynamic table available size")]
    MaxTableSizeReached,
    #[error(display = "table size setting is greater than maximum authorized")]
    MaximumTableSizeTooLarge,
    #[error(display = "max blocked stream setting is greater than maximum authorized")]
    MaxBlockedStreamsTooLarge,
    #[error(
        display = "stream id '{}' is unknown or has already been acknowledged or canceled",
        _0
    )]
    UnknownStreamId(u64),
    #[error(display = "tried to acknowledge encoder stream but no encoder data has been sent")]
    NoTrackingData,
    #[error(display = "internal reference tracking error")]
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
            .ok_or_else(|| Error::BadIndex(real_index))
    }

    pub(super) fn get_postbase(&self, index: usize) -> Result<&HeaderField, Error> {
        let real_index = self.table.vas.post_base(self.base, index)?;
        self.table
            .fields
            .get(real_index)
            .ok_or_else(|| Error::BadIndex(real_index))
    }
}

pub struct DynamicTableInserter<'a> {
    table: &'a mut DynamicTable,
}

impl<'a> DynamicTableInserter<'a> {
    pub fn set_max_size(&mut self, size: usize) -> Result<(), Error> {
        self.table.set_max_size(size)
    }

    pub(super) fn put_field(&mut self, field: HeaderField) -> Result<(), Error> {
        let index = match self.table.put_field(field.clone())? {
            Some(index) => index,
            None => return Ok(()),
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
            .ok_or_else(|| Error::BadIndex(real_index))
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
        }
    }
}

impl<'a> DynamicTableEncoder<'a> {
    pub(super) fn max_size(&self) -> usize {
        self.table.max_size
    }

    pub(super) fn base(&self) -> usize {
        self.base
    }

    pub(super) fn total_inserted(&self) -> usize {
        self.table.total_inserted()
    }

    pub(super) fn commit(&mut self, largest_ref: usize) {
        self.table
            .track_block(self.stream_id, self.block_refs.clone());
        self.table.register_blocked(largest_ref);
        self.commited = true;
    }

    pub(super) fn find(&mut self, field: &HeaderField) -> DynamicLookupResult {
        self.lookup_result(self.table.field_map.as_ref().unwrap().get(field).cloned())
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
        if self.table.blocked_count >= self.table.blocked_max {
            return Ok(DynamicInsertionResult::NotInserted(
                self.find_name(&field.name),
            ));
        }

        let index = match self.table.put_field(field.clone()) {
            Ok(Some(index)) => index,
            Err(Error::MaxTableSizeReached) | Ok(None) => {
                return Ok(DynamicInsertionResult::NotInserted(
                    self.find_name(&field.name),
                ));
            }
            Err(e) => return Err(e),
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

        self.lookup_result(self.table.name_map.as_ref().unwrap().get(name).cloned())
    }

    fn track_ref(&mut self, reference: usize) {
        self.block_refs
            .entry(reference)
            .and_modify(|c| *c += 1)
            .or_insert(1);
        self.table.track_ref(reference);
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

#[derive(Default)]
pub struct DynamicTable {
    fields: VecDeque<HeaderField>,
    curr_size: usize,
    max_size: usize,
    vas: VirtualAddressSpace,
    field_map: Option<HashMap<HeaderField, usize>>,
    name_map: Option<HashMap<Cow<'static, [u8]>, usize>>,
    track_map: Option<BTreeMap<usize, usize>>,
    track_blocks: Option<HashMap<u64, HashMap<usize, usize>>>,
    largest_known_received: usize,
    blocked_max: usize,
    blocked_count: usize,
    blocked_streams: Option<BTreeMap<usize, usize>>, // <required_ref, blocked_count>
}

impl DynamicTable {
    pub fn new() -> DynamicTable {
        DynamicTable::default()
    }

    pub fn decoder(&self, base: usize) -> DynamicTableDecoder {
        DynamicTableDecoder { table: self, base }
    }

    pub fn inserter(&mut self) -> DynamicTableInserter {
        DynamicTableInserter { table: self }
    }

    pub fn encoder(&mut self, stream_id: u64) -> DynamicTableEncoder {
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

    pub fn set_max_blocked(&mut self, max: usize) -> Result<(), Error> {
        // TODO handle existing data
        if max >= SETTINGS_MAX_BLOCKED_STREAMS_MAX {
            return Err(Error::MaxBlockedStreamsTooLarge);
        }
        self.blocked_max = max;
        Ok(())
    }

    pub fn set_max_size(&mut self, size: usize) -> Result<(), Error> {
        if size > SETTINGS_MAX_TABLE_CAPACITY_MAX {
            return Err(Error::MaximumTableSizeTooLarge);
        }

        if size >= self.max_size {
            self.max_size = size;
            return Ok(());
        }

        let required = self.max_size - size;

        if let Some(to_evict) = self.can_free(required)? {
            self.evict(to_evict)?;
        }

        self.max_size = size;
        Ok(())
    }

    pub(super) fn total_inserted(&self) -> usize {
        self.vas.total_inserted()
    }

    pub(super) fn untrack_block(&mut self, stream_id: u64) -> Result<(), Error> {
        if self.track_blocks.is_none() || self.track_map.is_none() {
            return Ok(());
        }

        if let Some(bloc_entry) = self.track_blocks.as_mut().unwrap().remove(&stream_id) {
            self.track_cancel(bloc_entry.iter().map(|(x, y)| (*x, *y)))?;
            Ok(())
        } else {
            Err(Error::UnknownStreamId(stream_id))
        }
    }

    fn put_field(&mut self, field: HeaderField) -> Result<Option<usize>, Error> {
        if self.max_size == 0 {
            return Ok(None);
        }

        match self.can_free(field.mem_size())? {
            None => return Ok(None),
            Some(to_evict) => {
                self.evict(to_evict)?;
            }
        }

        self.curr_size += field.mem_size();
        self.fields.push_back(field);
        let absolute = self.vas.add();

        Ok(Some(absolute))
    }

    fn evict(&mut self, to_evict: usize) -> Result<(), Error> {
        for _ in 0..to_evict {
            let field = self.fields.pop_front().ok_or(Error::MaxTableSizeReached)?; //TODO better type
            self.curr_size -= field.mem_size();

            self.vas.drop();

            if let Some(map) = self.name_map.as_mut() {
                if let Entry::Occupied(e) = map.entry(field.name.clone()) {
                    if self.vas.evicted(*e.get()) {
                        e.remove();
                    }
                }
            }

            if let Some(map) = self.field_map.as_mut() {
                if let Entry::Occupied(e) = map.entry(field) {
                    if self.vas.evicted(*e.get()) {
                        e.remove();
                    }
                }
            }
        }
        Ok(())
    }

    fn can_free(&mut self, required: usize) -> Result<Option<usize>, Error> {
        if required > self.max_size {
            return Err(Error::MaxTableSizeReached);
        }

        if self.max_size - self.curr_size >= required {
            return Ok(Some(0));
        }
        let lower_bound = self.max_size - required;

        let mut hypothetic_mem_size = self.curr_size;
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

        if required <= self.max_size - hypothetic_mem_size {
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

    fn register_blocked(&mut self, largest: usize) {
        if largest <= self.largest_known_received {
            return;
        }

        self.blocked_count += 1;

        let map = self.blocked_streams.get_or_insert(BTreeMap::new());
        match map.entry(largest) {
            BTEntry::Occupied(mut e) => {
                let entry = e.get_mut();
                *entry += 1;
            }
            BTEntry::Vacant(e) => {
                e.insert(1);
            }
        }
    }

    pub fn update_largest_received(&mut self, increment: usize) {
        self.largest_known_received += increment;

        if self.blocked_streams.is_none() || self.blocked_count == 0 {
            return;
        }

        let acked = self.blocked_streams.as_mut().unwrap();
        let blocked = acked.split_off(&(self.largest_known_received + 1));

        if !acked.is_empty() {
            let total_acked = acked.iter().fold(0usize, |t, (_, v)| t + v);
            self.blocked_count -= total_acked;
        }
        self.blocked_streams = Some(blocked);
    }

    pub(super) fn max_mem_size(&self) -> usize {
        self.max_size
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
    use crate::qpack::{static_::StaticTable, tests::helpers::build_table};

    const STREAM_ID: u64 = 0x4;

    // Test on table size
    /**
     * https://tools.ietf.org/html/rfc7541#section-4.1
     * "The size of the dynamic table is the sum of the size of its entries."
     */
    #[test]
    fn test_table_size_is_sum_of_its_entries() {
        let mut table = build_table();

        let fields: [(&'static str, &'static str); 2] = [
            ("Name", "Value"),
            ("Another-Name", ""), // no value
        ];
        let table_size = 4 + 5 + 12 + 0 + /* ESTIMATED_OVERHEAD_BYTES */ 32 * 2;

        for pair in fields.iter() {
            let field = HeaderField::new(pair.0, pair.1);
            table.inserter().put_field(field).unwrap();
        }

        assert_eq!(table.curr_size, table_size);
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
        let mut table = build_table();
        let invalid_size = SETTINGS_MAX_TABLE_CAPACITY_MAX + 10;
        let res_change = table.set_max_size(invalid_size);
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
        let mut table = build_table();
        let res_change = table.set_max_size(0);
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
        let mut table = build_table();
        let res_change = table.set_max_size(SETTINGS_MAX_TABLE_CAPACITY_MAX);
        assert!(res_change.is_ok());
        assert_eq!(table.max_mem_size(), SETTINGS_MAX_TABLE_CAPACITY_MAX);
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
        let mut table = build_table();
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
        let mut table = build_table();

        table
            .inserter()
            .put_field(HeaderField::new("Name", "Value"))
            .unwrap();
        assert_eq!(table.fields.len(), 1);
    }

    /** functional test */
    #[test]
    fn test_add_field_reduce_free_space() {
        let mut table = build_table();

        let field = HeaderField::new("Name", "Value");
        table.put_field(field.clone()).unwrap();
        assert_eq!(table.curr_size, field.mem_size());
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
        let mut table = build_table();

        table
            .inserter()
            .put_field(HeaderField::new("Name-A", "Value-A"))
            .unwrap();
        table
            .inserter()
            .put_field(HeaderField::new("Name-B", "Value-B"))
            .unwrap();
        let perfect_size = table.curr_size;
        assert!(table.set_max_size(perfect_size).is_ok());

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
        let mut table = build_table();

        table
            .inserter()
            .put_field(HeaderField::new("Name-A", "Value-A"))
            .unwrap();
        let perfect_size = table.curr_size;
        assert!(table.set_max_size(perfect_size).is_ok());

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
        let mut table = build_table();
        insert_fields(
            &mut table,
            vec![
                HeaderField::new("Name", "Value"),
                HeaderField::new("Name", "Value"),
            ],
        );
        assert_eq!(table.fields.len(), 2);

        table.set_max_size(0).unwrap();
        assert_eq!(table.fields.len(), 0);
    }

    /** functional test */
    #[test]
    fn test_eviction_is_fifo() {
        let mut table = build_table();

        insert_fields(
            &mut table,
            vec![
                HeaderField::new("Name-A", "Value-A"),
                HeaderField::new("Name-B", "Value-B"),
            ],
        );
        let perfect_size = table.curr_size;
        assert!(table.set_max_size(perfect_size).is_ok());

        insert_fields(&mut table, vec![HeaderField::new("Name-C", "Value-C")]);

        assert_eq!(
            table.fields.get(0),
            Some(&HeaderField::new("Name-B", "Value-B"))
        );
        assert_eq!(
            table.fields.get(1),
            Some(&HeaderField::new("Name-C", "Value-C"))
        );
        assert_eq!(table.fields.get(2), None);
    }

    #[test]
    fn encoder_build() {
        let mut table = build_table();
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
        let mut table = build_table();
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
        let mut table = build_table();
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
        let mut table = build_table();
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
        let mut table = build_table();
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
        let mut table = build_table();
        table.set_max_size(33).unwrap();
        let mut encoder = table.encoder(4);
        assert_eq!(
            encoder.insert(&HeaderField::new("foo", "bar")),
            Ok(DynamicInsertionResult::NotInserted(
                DynamicLookupResult::NotFound
            ))
        );
    }

    #[test]
    fn encoder_maps_are_cleaned_on_eviction() {
        let mut table = build_table();
        table.set_max_size(64).unwrap();

        {
            let mut encoder = table.encoder(4);
            assert_eq!(
                encoder.insert(&HeaderField::new("foo", "bar")),
                Ok(DynamicInsertionResult::Inserted {
                    postbase: 0,
                    absolute: 1
                })
            );
            encoder.commit(1);
        }
        table.untrack_block(4).unwrap();

        {
            let mut encoder = table.encoder(4);
            assert_eq!(
                encoder.insert(&HeaderField::new("foo2", "bar")),
                Ok(DynamicInsertionResult::Inserted {
                    postbase: 0,
                    absolute: 2
                })
            );
            assert_eq!(
                encoder.find(&HeaderField::new("foo", "bar")),
                DynamicLookupResult::NotFound
            );
            assert_eq!(encoder.find_name(b"foo"), DynamicLookupResult::NotFound);
            encoder.commit(2);
        }
    }

    #[test]
    fn encoder_can_evict_unreferenced() {
        let mut table = build_table();
        table.set_max_size(63).unwrap();
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
        let mut table = build_table();
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
        let mut table = build_table();
        let stream_id = 42;
        {
            let mut encoder = table.encoder(stream_id);
            for idx in 1..4 {
                encoder
                    .insert(&HeaderField::new(format!("foo{}", idx), "quxx"))
                    .unwrap();
            }
            assert_eq!(encoder.block_refs.len(), 3);
            encoder.commit(2);
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
        let mut table = build_table();
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
        let mut table = build_table();
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
        let mut table = build_table();
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
        let mut table = build_table();
        table.set_max_size(95).unwrap();
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
        let mut table = build_table();
        table.track_blocks = Some(HashMap::new());
        {
            let mut encoder = table.encoder(stream_id);
            for idx in 1..4 {
                encoder
                    .insert(&HeaderField::new(format!("foo{}", idx), "quxx"))
                    .unwrap();
            }
            assert_eq!(encoder.block_refs.len(), 3);
            encoder.commit(3);
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

    #[test]
    fn blocked_stream_registered() {
        let mut table = tracked_table(42);
        table.set_max_blocked(100).unwrap();

        assert_eq!(table.blocked_count, 1);
        assert_eq!(table.blocked_streams.unwrap().get(&3), Some(&1usize))
    }

    #[test]
    fn blocked_stream_not_registered() {
        let mut table = tracked_table(42);
        table.set_max_blocked(100).unwrap();

        table
            .encoder(44)
            .insert(&HeaderField::new("foo", "bar"))
            .unwrap();
        // encoder dropped without commit

        assert_eq!(table.blocked_count, 1);
        assert_eq!(table.blocked_streams.unwrap().get(&5), None);
    }

    #[test]
    fn blocked_stream_register_accumulate() {
        let mut table = tracked_table(42);
        table.set_max_blocked(100).unwrap();

        {
            let mut encoder = table.encoder(44);

            assert_eq!(
                encoder.find(&HeaderField::new("foo3", "quxx")),
                DynamicLookupResult::Relative {
                    index: 0,
                    absolute: 3,
                }
            );
            // the encoder inserts a reference to foo3 in a block (absolte index = 3)
            encoder.commit(3);
        }

        assert_eq!(table.blocked_count, 2);
        assert_eq!(table.blocked_streams.as_ref().unwrap().get(&3), Some(&2));
    }

    #[test]
    fn blocked_stream_register_put_smaller() {
        let mut table = tracked_table(42);
        table.set_max_blocked(100).unwrap();

        {
            let mut encoder = table.encoder(44);
            encoder.commit(2);
        }

        assert_eq!(table.blocked_count, 2);
        assert_eq!(table.blocked_streams.as_ref().unwrap().get(&2), Some(&1));
    }

    #[test]
    fn blocked_stream_register_put_larger() {
        let mut table = tracked_table(42);
        table.set_max_blocked(100).unwrap();

        {
            let mut encoder = table.encoder(44);
            encoder.commit(5);
        }

        assert_eq!(table.blocked_count, 2);
        assert_eq!(table.blocked_streams.as_ref().unwrap().get(&5), Some(&1));
    }

    #[test]
    fn unblock_stream_smaller() {
        let mut table = tracked_table(42);
        table.set_max_blocked(100).unwrap();

        {
            let mut encoder = table.encoder(44);
            encoder.commit(2);
        }

        assert_eq!(table.blocked_count, 2);
        assert_eq!(table.blocked_streams.as_ref().unwrap().get(&2), Some(&1));

        table.update_largest_received(2);

        assert_eq!(table.blocked_count, 1);
        assert_eq!(table.blocked_streams.as_ref().unwrap().get(&2), None);
        assert_eq!(table.blocked_streams.as_ref().unwrap().get(&3), Some(&1));
    }

    #[test]
    fn unblock_stream_larger() {
        let mut table = tracked_table(42);
        table.set_max_blocked(100).unwrap();

        table.encoder(44).commit(2);
        table.encoder(46).commit(5);

        assert_eq!(table.blocked_count, 3);
        assert_eq!(table.blocked_streams.as_ref().unwrap().get(&2), Some(&1));
        assert_eq!(table.blocked_streams.as_ref().unwrap().get(&3), Some(&1));

        table.update_largest_received(5);

        assert_eq!(table.blocked_count, 0);
        assert_eq!(table.blocked_streams.as_ref().unwrap().len(), 0);
    }

    #[test]
    fn unblock_stream_decrement() {
        let mut table = tracked_table(42);
        table.set_max_blocked(100).unwrap();

        table.encoder(44).commit(3);

        assert_eq!(table.blocked_count, 2);
        assert_eq!(table.blocked_streams.as_ref().unwrap().get(&3), Some(&2));

        table.update_largest_received(5);

        assert_eq!(table.blocked_count, 0);
        assert_eq!(table.blocked_streams.as_ref().unwrap().len(), 0);
    }

    #[test]
    fn no_insert_when_max_blocked_0() {
        let mut table = tracked_table(42);
        table.set_max_blocked(0).unwrap();

        assert_eq!(
            table.encoder(44).insert(&HeaderField::new("foo", "bar")),
            Ok(DynamicInsertionResult::NotInserted(
                DynamicLookupResult::NotFound
            ))
        );
    }

    #[test]
    fn no_insert_after_max_blocked_reached() {
        let mut table = tracked_table(42);
        table.set_max_blocked(2).unwrap();

        {
            let mut encoder = table.encoder(44);
            assert_eq!(
                encoder.insert(&HeaderField::new("foo", "bar")),
                Ok(DynamicInsertionResult::Inserted {
                    postbase: 0,
                    absolute: 4
                })
            );
            encoder.commit(4);
        }

        assert_eq!(table.blocked_count, 2);

        let mut encoder = table.encoder(46);
        assert_eq!(
            encoder.insert(&HeaderField::new("foo99", "bar")),
            Ok(DynamicInsertionResult::NotInserted(
                DynamicLookupResult::NotFound
            ))
        );
    }

    #[test]
    fn insert_again_after_encoder_ack() {
        let mut table = tracked_table(42);
        table.set_max_blocked(1).unwrap();

        assert_eq!(table.blocked_count, 1);

        {
            let mut encoder = table.encoder(44);
            assert_eq!(
                encoder.insert(&HeaderField::new("foo99", "bar")),
                Ok(DynamicInsertionResult::NotInserted(
                    DynamicLookupResult::NotFound
                ))
            );
            encoder.commit(0);
        }

        table.update_largest_received(3);
        assert_eq!(table.blocked_count, 0);

        let mut encoder = table.encoder(46);
        assert_eq!(
            encoder.insert(&HeaderField::new("foo", "bar")),
            Ok(DynamicInsertionResult::Inserted {
                postbase: 0,
                absolute: 4
            })
        );
    }
}
