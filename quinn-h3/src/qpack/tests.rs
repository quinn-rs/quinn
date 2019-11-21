use crate::qpack::{
    decode_header, encode, on_decoder_recv, on_encoder_recv, DecoderError, DynamicTable,
    HeaderField,
};
use std::io::Cursor;

pub mod helpers {
    use crate::qpack::{DynamicTable, HeaderField};

    pub const TABLE_SIZE: usize = 4096;

    pub fn build_table() -> DynamicTable {
        let mut table = DynamicTable::new();
        table.set_max_size(TABLE_SIZE).unwrap();
        table.set_max_blocked(100).unwrap();
        table
    }

    pub fn build_table_with_size(n_field: usize) -> DynamicTable {
        let mut table = DynamicTable::new();
        table.set_max_size(TABLE_SIZE).unwrap();
        table.set_max_blocked(100).unwrap();

        let mut inserter = table.inserter();
        for i in 0..n_field {
            inserter
                .put_field(HeaderField::new(format!("foo{}", i + 1), "bar"))
                .unwrap();
        }

        table
    }
}

#[test]
fn codec_basic_get() {
    let mut enc_table = DynamicTable::new();
    let mut dec_table = DynamicTable::new();

    let mut block_buf = vec![];
    let mut enc_buf = vec![];
    let mut dec_buf = vec![];

    let header = vec![
        HeaderField::new(":method", "GET"),
        HeaderField::new(":path", "/"),
        HeaderField::new("foo", "bar"),
    ];

    encode(
        &mut enc_table.encoder(42),
        &mut block_buf,
        &mut enc_buf,
        header.clone().into_iter(),
    )
    .unwrap();

    let mut enc_cur = Cursor::new(&mut enc_buf);
    on_encoder_recv(&mut dec_table.inserter(), &mut enc_cur, &mut dec_buf).unwrap();

    let mut block_cur = Cursor::new(&mut block_buf);
    let (decoded, _) = decode_header(&dec_table, &mut block_cur).unwrap();
    assert_eq!(decoded, header);

    let mut dec_cur = Cursor::new(&mut dec_buf);
    on_decoder_recv(&mut enc_table, &mut dec_cur).unwrap();
}

const TABLE_SIZE: usize = 4096;
#[test]
fn blocked_header() {
    let mut enc_table = DynamicTable::new();
    enc_table.set_max_size(TABLE_SIZE).unwrap();
    enc_table.set_max_blocked(100).unwrap();
    let mut dec_table = DynamicTable::new();
    dec_table.set_max_size(TABLE_SIZE).unwrap();
    dec_table.set_max_blocked(100).unwrap();

    let mut block_buf = vec![];
    let mut enc_buf = vec![];

    encode(
        &mut enc_table.encoder(42),
        &mut block_buf,
        &mut enc_buf,
        &[HeaderField::new("foo", "bar")],
    )
    .unwrap();

    let mut block_cur = Cursor::new(&mut block_buf);
    assert_eq!(
        decode_header(&dec_table, &mut block_cur),
        Err(DecoderError::MissingRefs(1))
    );
}

#[test]
fn codec_table_size_0() {
    let mut enc_table = DynamicTable::new();
    let mut dec_table = DynamicTable::new();

    let mut block_buf = vec![];
    let mut enc_buf = vec![];
    let mut dec_buf = vec![];

    let header = vec![
        HeaderField::new(":method", "GET"),
        HeaderField::new(":path", "/"),
        HeaderField::new("foo", "bar"),
    ];

    dec_table.set_max_size(0).unwrap();
    enc_table.set_max_size(0).unwrap();

    encode(
        &mut enc_table.encoder(42),
        &mut block_buf,
        &mut enc_buf,
        header.clone().into_iter(),
    )
    .unwrap();

    let mut enc_cur = Cursor::new(&mut enc_buf);
    on_encoder_recv(&mut dec_table.inserter(), &mut enc_cur, &mut dec_buf).unwrap();

    let mut block_cur = Cursor::new(&mut block_buf);
    let (decoded, _) = decode_header(&dec_table, &mut block_cur).unwrap();
    assert_eq!(decoded, header);

    let mut dec_cur = Cursor::new(&mut dec_buf);
    on_decoder_recv(&mut enc_table, &mut dec_cur).unwrap();
}

#[test]
fn codec_table_full() {
    let mut enc_table = DynamicTable::new();
    let mut dec_table = DynamicTable::new();

    let mut block_buf = vec![];
    let mut enc_buf = vec![];
    let mut dec_buf = vec![];

    let header = vec![
        HeaderField::new("foo", "bar"),
        HeaderField::new("foo1", "bar1"),
    ];

    dec_table.set_max_size(42).unwrap();
    enc_table.set_max_size(42).unwrap();

    encode(
        &mut enc_table.encoder(42),
        &mut block_buf,
        &mut enc_buf,
        header.clone().into_iter(),
    )
    .unwrap();

    let mut enc_cur = Cursor::new(&mut enc_buf);
    let mut block_cur = Cursor::new(&mut block_buf);

    on_encoder_recv(&mut dec_table.inserter(), &mut enc_cur, &mut dec_buf).unwrap();
    let (decoded, _) = decode_header(&dec_table, &mut block_cur).unwrap();
    assert_eq!(decoded, header);

    let mut dec_cur = Cursor::new(&mut dec_buf);
    on_decoder_recv(&mut enc_table, &mut dec_cur).unwrap();
}
