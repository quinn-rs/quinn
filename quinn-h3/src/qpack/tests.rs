use crate::qpack::{
    decode_header, encode, on_decoder_recv, on_encoder_recv, DecoderError, DynamicTable,
    HeaderField,
};
use std::io::Cursor;

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
        &header,
    )
    .unwrap();

    let mut enc_cur = Cursor::new(&mut enc_buf);
    on_encoder_recv(&mut dec_table.inserter(), &mut enc_cur, &mut dec_buf).unwrap();

    let mut block_cur = Cursor::new(&mut block_buf);
    assert_eq!(decode_header(&dec_table, &mut block_cur), Ok(header));

    let mut dec_cur = Cursor::new(&mut dec_buf);
    on_decoder_recv(&mut enc_table, &mut dec_cur).unwrap();
}

#[test]
fn blocked_header() {
    let mut enc_table = DynamicTable::new();
    let dec_table = DynamicTable::new();

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
        Err(DecoderError::MissingRefs)
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

    dec_table.inserter().set_max_mem_size(0).unwrap();
    enc_table.inserter().set_max_mem_size(0).unwrap();

    encode(
        &mut enc_table.encoder(42),
        &mut block_buf,
        &mut enc_buf,
        &header,
    )
    .unwrap();

    let mut enc_cur = Cursor::new(&mut enc_buf);
    on_encoder_recv(&mut dec_table.inserter(), &mut enc_cur, &mut dec_buf).unwrap();

    let mut block_cur = Cursor::new(&mut block_buf);
    assert_eq!(decode_header(&dec_table, &mut block_cur), Ok(header));

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

    dec_table.inserter().set_max_mem_size(42).unwrap();
    enc_table.inserter().set_max_mem_size(42).unwrap();

    encode(
        &mut enc_table.encoder(42),
        &mut block_buf,
        &mut enc_buf,
        &header,
    )
    .unwrap();

    let mut enc_cur = Cursor::new(&mut enc_buf);
    let mut block_cur = Cursor::new(&mut block_buf);

    on_encoder_recv(&mut dec_table.inserter(), &mut enc_cur, &mut dec_buf).unwrap();

    assert_eq!(decode_header(&dec_table, &mut block_cur), Ok(header));

    let mut dec_cur = Cursor::new(&mut dec_buf);
    on_decoder_recv(&mut enc_table, &mut dec_cur).unwrap();
}
