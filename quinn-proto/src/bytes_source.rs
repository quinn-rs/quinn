//! Defines types which can be lazily converted into `Bytes` chunks

use bytes::Bytes;

/// A source of one or more buffers which can be converted into `Bytes` buffers on demand
///
/// The purpose of this data type is to defer conversion as long as possible,
/// so that no heap allocation is required in case no data is writable.
pub trait BytesSource {
    /// Returns the next chunk from the source of owned chunks.
    ///
    /// This method will consume parts of the source.
    /// Calling it will yield `Bytes` elements up to the configured `limit`.
    ///
    /// The method returns a tuple:
    /// - The first item is the yielded `Bytes` element. The element will be
    ///   empty if the limit is zero or no more data is available.
    /// - The second item returns how many complete chunks inside the source had
    ///   had been consumed. This can be less than 1, if a chunk inside the
    ///   source had been truncated in order to adhere to the limit. It can also
    ///   be more than 1, if zero-length chunks had been skipped.
    fn pop_chunk(&mut self, limit: usize) -> (Bytes, usize);
}

/// Indicates how many bytes and chunks had been transferred in a write operation
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub struct Written {
    /// The amount of bytes which had been written
    pub bytes: usize,
    /// The amount of full chunks which had been written
    ///
    /// If a chunk was only partially written, it will not be counted by this field.
    pub chunks: usize,
}

/// A [`BytesSource`] implementation for `&'a mut [Bytes]`
///
/// The type allows to dequeue [`Bytes`] chunks from an array of chunks, up to
/// a configured limit.
pub struct BytesArray<'a> {
    /// The wrapped slice of `Bytes`
    chunks: &'a mut [Bytes],
    /// The amount of chunks consumed from this source
    consumed: usize,
}

impl<'a> BytesArray<'a> {
    pub fn from_chunks(chunks: &'a mut [Bytes]) -> Self {
        Self {
            chunks,
            consumed: 0,
        }
    }
}

impl<'a> BytesSource for BytesArray<'a> {
    fn pop_chunk(&mut self, limit: usize) -> (Bytes, usize) {
        // The loop exists to skip empty chunks while still marking them as
        // consumed
        let mut chunks_consumed = 0;

        while self.consumed < self.chunks.len() {
            let chunk = &mut self.chunks[self.consumed];

            if chunk.len() <= limit {
                let chunk = std::mem::take(chunk);
                self.consumed += 1;
                chunks_consumed += 1;
                if chunk.is_empty() {
                    continue;
                }
                return (chunk, chunks_consumed);
            } else if limit > 0 {
                let chunk = chunk.split_to(limit);
                return (chunk, chunks_consumed);
            } else {
                break;
            }
        }

        (Bytes::new(), chunks_consumed)
    }
}

/// A [`BytesSource`] implementation for `&[u8]`
///
/// The type allows to dequeue a single [`Bytes`] chunk, which will be lazily
/// created from a reference. This allows to defer the allocation until it is
/// known how much data needs to be copied.
pub struct ByteSlice<'a> {
    /// The wrapped byte slice
    data: &'a [u8],
}

impl<'a> ByteSlice<'a> {
    pub fn from_slice(data: &'a [u8]) -> Self {
        Self { data }
    }
}

impl<'a> BytesSource for ByteSlice<'a> {
    fn pop_chunk(&mut self, limit: usize) -> (Bytes, usize) {
        let limit = limit.min(self.data.len());
        if limit == 0 {
            return (Bytes::new(), 0);
        }

        let chunk = Bytes::from(self.data[..limit].to_owned());
        self.data = &self.data[chunk.len()..];

        let chunks_consumed = if self.data.is_empty() { 1 } else { 0 };
        (chunk, chunks_consumed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_array() {
        let full = b"Hello World 123456789 ABCDEFGHJIJKLMNOPQRSTUVWXYZ".to_owned();
        for limit in 0..full.len() {
            let mut chunks = [
                Bytes::from_static(b""),
                Bytes::from_static(b"Hello "),
                Bytes::from_static(b"Wo"),
                Bytes::from_static(b""),
                Bytes::from_static(b"r"),
                Bytes::from_static(b"ld"),
                Bytes::from_static(b""),
                Bytes::from_static(b" 12345678"),
                Bytes::from_static(b"9 ABCDE"),
                Bytes::from_static(b"F"),
                Bytes::from_static(b"GHJIJKLMNOPQRSTUVWXYZ"),
            ];
            let num_chunks = chunks.len();
            let last_chunk_len = chunks[chunks.len() - 1].len();

            let mut array = BytesArray::from_chunks(&mut chunks);

            let mut buf = Vec::new();
            let mut chunks_popped = 0;
            let mut chunks_consumed = 0;
            let mut remaining = limit;
            loop {
                let (chunk, consumed) = array.pop_chunk(remaining);
                chunks_consumed += consumed;

                if !chunk.is_empty() {
                    buf.extend_from_slice(&chunk);
                    remaining -= chunk.len();
                    chunks_popped += 1;
                } else {
                    break;
                }
            }

            assert_eq!(&buf[..], &full[..limit]);

            if limit == full.len() {
                // Full consumption of the last chunk
                assert_eq!(chunks_consumed, num_chunks);
                // Since there are empty chunks, we consume more than there are popped
                assert_eq!(chunks_consumed, chunks_popped + 3);
            } else if limit > full.len() - last_chunk_len {
                // Partial consumption of the last chunk
                assert_eq!(chunks_consumed, num_chunks - 1);
                assert_eq!(chunks_consumed, chunks_popped + 2);
            }
        }
    }

    #[test]
    fn byte_slice() {
        let full = b"Hello World 123456789 ABCDEFGHJIJKLMNOPQRSTUVWXYZ".to_owned();
        for limit in 0..full.len() {
            let mut array = ByteSlice::from_slice(&full[..]);

            let mut buf = Vec::new();
            let mut chunks_popped = 0;
            let mut chunks_consumed = 0;
            let mut remaining = limit;
            loop {
                let (chunk, consumed) = array.pop_chunk(remaining);
                chunks_consumed += consumed;

                if !chunk.is_empty() {
                    buf.extend_from_slice(&chunk);
                    remaining -= chunk.len();
                    chunks_popped += 1;
                } else {
                    break;
                }
            }

            assert_eq!(&buf[..], &full[..limit]);
            if limit != 0 {
                assert_eq!(chunks_popped, 1);
            } else {
                assert_eq!(chunks_popped, 0);
            }

            if limit == full.len() {
                assert_eq!(chunks_consumed, 1);
            } else {
                assert_eq!(chunks_consumed, 0);
            }
        }
    }
}
