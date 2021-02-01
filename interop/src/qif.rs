/// Offline QPACK interop test tool
///
/// QIF - Quic Interop File
///
/// # usage:
///
/// Clone the interop files from other implementations:
///
/// ```sh
/// git clone git@github.com:qpackers/qifs.git
/// ```
///
/// Run this tool against those:
///
/// ```sh
/// cargo run --bin qif /where/qifs/encoded/
/// ```
///
/// The tool will guess what's in the path given as an argument and run the appropriate
/// test:
///
/// ```
/// # Decode one file and check result
/// cargo run --bin qif /where/qifs/encoded/qpack-05/f5/netbsd-hq.out.256.0.1
/// # Decode all files and check result
/// cargo run --bin qif /where/qifs/encoded/qpack-05/f5/
/// cargo run --bin qif /where/qifs/encoded/
/// # Encode one file
/// cargo run --bin qif /home/jc/code/perso/qifs/qifs/netbsd.qif
/// # Encode all files
/// cargo run --bin qif /home/jc/code/perso/qifs/qifs/
/// ```
///
/// See https://github.com/quicwg/base-drafts/wiki/QPACK-Offline-Interop to know more about
/// file name formats and codec parameters.
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::{fs, mem};

use anyhow::{anyhow, Result};
use bytes::{Buf, Bytes};
use structopt::StructOpt;

use quinn_h3::qpack;
use quinn_proto::coding::Codec;

#[derive(StructOpt, Debug)]
#[structopt(name = "interop")]
struct Opt {
    path: String,
    #[structopt(short = "t", long = "table_size")]
    table_size: Option<String>,
    #[structopt(short = "b", long = "max_blocked")]
    max_blocked: Option<String>,
    #[structopt(short = "a", long = "ack_mode")]
    ack_mode: Option<String>,
}

fn main() -> Result<()> {
    let opt = Opt::from_args();
    let input = &opt.path;

    let mut failures = vec![];
    let mut success = vec![];

    fn parse_usizes(s: String) -> Vec<usize> {
        s.split(',')
            .map(|e| str::parse::<usize>(e).unwrap_or_default())
            .collect()
    }

    let table_size = opt
        .table_size
        .map_or_else(|| vec![4096, 512, 256, 0], parse_usizes);
    let max_blocked = opt.max_blocked.map_or_else(|| vec![100, 0], parse_usizes);
    let ack_mode = opt.ack_mode.map_or_else(|| vec![1, 0], parse_usizes);

    match InputType::what_is(Path::new(input))? {
        InputType::EncodedFile(file, qif) => match file.decode() {
            Err(e) => failures.push((file.file, e)),
            Ok(ref mut v) => {
                let mut fields = v.iter().flatten();
                qif.compare(&mut fields)?;
                success.push(file.file);
            }
        },
        InputType::ImplEncodedDir(dir) => {
            for (file, qif) in dir.iter()? {
                match file.decode() {
                    Err(e) => failures.push((file.file, e)),
                    Ok(ref mut v) if qif.is_some() => {
                        let mut fields = v.iter().flatten();
                        qif.unwrap().compare(&mut fields)?;
                        success.push(file.file);
                    }
                    Ok(_) => failures.push((file.file, anyhow!("Could not find qif"))),
                }
            }
        }
        InputType::EncodedDir(dir) => {
            for impl_dir in dir.iter()? {
                for (file, qif) in impl_dir.iter()? {
                    match file.decode() {
                        Err(e) => failures.push((file.file, e)),
                        Ok(ref mut v) if qif.is_some() => {
                            let mut fields = v.iter().flatten();
                            qif.unwrap().compare(&mut fields)?;
                            success.push(file.file);
                        }
                        Ok(_) => failures.push((file.file, anyhow!("Could not find qif"))),
                    }
                }
            }
        }
        InputType::QifFile(qif) => {
            for size in &table_size {
                for blocked in &max_blocked {
                    for ack in &ack_mode {
                        let enc_file = EncodedFile::from_qif(&qif.0, *size, *blocked, *ack)?;
                        match enc_file.encode(qif.blocks()?) {
                            Err(e) => failures.push((enc_file.file, e)),
                            Ok(_) => success.push(enc_file.file),
                        }
                    }
                }
            }
        }
        InputType::QifDir(qif_dir) => {
            for qif in qif_dir.iter()? {
                for size in &table_size {
                    for blocked in &max_blocked {
                        for ack in &ack_mode {
                            let enc_file = EncodedFile::from_qif(&qif.0, *size, *blocked, *ack)?;
                            match enc_file.encode(qif.blocks()?) {
                                Err(e) => failures.push((enc_file.file, e)),
                                Ok(_) => success.push(enc_file.file),
                            }
                        }
                    }
                }
            }
        }
        _ => return Err(anyhow!("Could not guess a dir type for '{}'", input)),
    }

    for failure in &failures {
        let mut name = failure
            .0
            .ancestors()
            .take(2)
            .map(|a| {
                a.file_name()
                    .unwrap_or_else(|| OsStr::new("ERR"))
                    .to_str()
                    .unwrap_or("ERR")
            })
            .map(String::from)
            .collect::<Vec<String>>();

        name.reverse();
        let name = name.join("/");

        println!("{: <42}: {:?}", name, failure.1);
    }

    println!("\nSuccess: {}, Failures: {}", success.len(), failures.len());

    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(
            "Got some errors: \n{}",
            failures
                .iter()
                .map(|(f, e)| format!("{:?}: {}\n", f, e))
                .fold(String::new(), |acc, ref p| acc + p)
        ))
    }
}

struct Block(std::io::Cursor<Bytes>, u64);

struct BlockIterator<R: Buf> {
    buf: R,
    last_block_len: usize,
}

impl<R: Buf> BlockIterator<R> {
    fn new(buf: R) -> Self {
        Self {
            buf,
            last_block_len: 0,
        }
    }

    fn next(&mut self) -> Result<Option<Block>> {
        self.buf.advance(self.last_block_len);
        if self.buf.remaining() < mem::size_of::<u64>() + mem::size_of::<u32>() {
            if self.buf.remaining() > 0 {
                return Err(anyhow!(
                    "Found trailing data after decoding: {} bytes",
                    self.buf.remaining()
                ));
            }
            return Ok(None);
        }

        let current = u64::decode(&mut self.buf)?;
        let length = u32::decode(&mut self.buf)? as usize;

        if self.buf.remaining() < length {
            Err(anyhow!("Unexpectedly reached end"))
        } else {
            self.last_block_len = length;
            let block = std::io::Cursor::new(self.buf.copy_to_bytes(length));

            Ok(Some(Block(block, current)))
        }
    }
}

#[derive(Debug)]
struct EncodedFile {
    file: PathBuf,
    table_size: usize,
    max_blocked: usize,
    ack_mode: usize,
}

impl EncodedFile {
    pub fn new(file: PathBuf) -> Self {
        let numbers = file
            .file_name()
            .unwrap_or_default()
            .to_str()
            .unwrap_or("")
            .rsplit('.')
            .take(3)
            .map(|n| str::parse::<usize>(n).unwrap_or_default())
            .collect::<Vec<_>>();

        let (ack_mode, max_blocked, table_size) = if numbers.len() >= 3 {
            (numbers[0], numbers[1], numbers[2])
        } else {
            (0, 0, 0)
        };

        Self {
            file,
            table_size,
            max_blocked,
            ack_mode,
        }
    }

    fn from_qif(
        qif: &Path,
        table_size: usize,
        max_blocked: usize,
        ack_mode: usize,
    ) -> Result<EncodedFile> {
        let enc_dir = qif
            .ancestors()
            .skip(2)
            .take(1)
            .collect::<PathBuf>()
            .join("encoded")
            .join("qpack-05")
            .join("quinn");

        if !enc_dir.is_dir() {
            fs::create_dir(&enc_dir)?;
        }

        let name = qif
            .file_stem()
            .ok_or_else(|| anyhow!("Could not find stem in {:?}", qif))?;
        let enc_file = enc_dir.join(format!(
            "{}.out.{}.{}.{}",
            name.to_str()
                .ok_or_else(|| anyhow!("Could not parse {:?} as utf8 str", qif))?,
            table_size,
            max_blocked,
            ack_mode
        ));

        Ok(Self {
            file: enc_file,
            table_size,
            max_blocked,
            ack_mode,
        })
    }

    pub fn decode(&self) -> Result<Vec<Vec<qpack::HeaderField>>> {
        let encoded = fs::read(&self.file)?;
        let mut table = qpack::DynamicTable::new();
        table.inserter().set_max_size(self.table_size)?;
        let mut blocks = BlockIterator::new(std::io::Cursor::new(&encoded));
        let mut count = 0;
        let mut blocked = vec![];
        let mut decoder = vec![];
        let mut decoded = vec![];

        while let Some(Block(mut buf, current)) = blocks.next().expect("next block") {
            if current == 0 {
                // encoder stream
                qpack::on_encoder_recv(&mut table.inserter(), &mut buf, &mut decoder)?;

                let mut unblocked = vec![];

                for (i, block) in blocked.iter_mut().enumerate() {
                    let mut cur = std::io::Cursor::new(&block);
                    match qpack::decode_header(&table, &mut cur) {
                        Ok((d, _)) => {
                            decoded.push(d);
                            unblocked.push(i);
                        }
                        Err(qpack::DecoderError::MissingRefs { .. }) => (),
                        Err(e) => return Err(e.into()),
                    }
                }

                for i in unblocked {
                    blocked.remove(i);
                }

                continue;
            }

            if current != count + 1 {
                eprintln!("got wrong stream ID: {}", current);
                break;
            }

            let mut cur = std::io::Cursor::new(buf.copy_to_bytes(buf.remaining()));
            match qpack::decode_header(&table, &mut cur) {
                Ok((d, _)) => decoded.push(d),
                Err(qpack::DecoderError::MissingRefs { .. }) => {
                    if blocked.len() >= self.max_blocked {
                        return Err(anyhow!("Max blocked streams exceeded"));
                    }
                    blocked.push(buf.copy_to_bytes(buf.remaining()));
                }
                Err(e) => return Err(e.into()),
            }
            count += 1;
        }
        Ok(decoded)
    }

    pub fn encode(&self, blocks: Vec<Vec<u8>>) -> Result<()> {
        let mut table = qpack::DynamicTable::new();
        table.inserter().set_max_size(self.table_size)?;
        table.set_max_blocked(self.max_blocked)?;

        let mut buf = vec![];
        let mut stream_count = 1;

        for block in blocks {
            let block_str = String::from_utf8_lossy(&block);
            let fields = block_str
                .split('\n')
                .map(|f| f.split('\t'))
                .filter_map(|s| {
                    let f = s.collect::<Vec<&str>>();
                    if f.len() >= 2 {
                        Some((f[0], f[1]))
                    } else {
                        None
                    }
                })
                .map(|(k, v)| qpack::HeaderField::new(k, v));

            let mut block_chunk = vec![];
            let mut encoder_chunk = vec![];

            qpack::encode(
                &mut table.encoder(stream_count),
                &mut block_chunk,
                &mut encoder_chunk,
                fields,
            )?;

            if self.ack_mode == 1 && self.table_size > 0 {
                let mut decoder_stream = vec![];
                qpack::ack_header(stream_count, &mut decoder_stream);
                let mut cur = std::io::Cursor::new(&decoder_stream);
                qpack::on_decoder_recv(&mut table, &mut cur)?;
            }

            stream_count.encode(&mut buf);
            (block_chunk.len() as u32).encode(&mut buf);
            buf.append(&mut block_chunk);

            if !encoder_chunk.is_empty() {
                0u64.encode(&mut buf);
                (encoder_chunk.len() as u32).encode(&mut buf);
                buf.append(&mut encoder_chunk);
            }

            stream_count += 1;
        }
        fs::write(&self.file, buf)?;
        println!("encoded in {:?}", self.file);
        Ok(())
    }
}

struct ImplEncodedDir(PathBuf, String);

impl ImplEncodedDir {
    pub fn iter(&self) -> Result<impl Iterator<Item = (EncodedFile, Option<QifFile>)>> {
        Ok(self
            .0
            .read_dir()?
            .filter_map(Result::ok)
            .filter(|e| e.path().is_file())
            .map(|e| {
                (
                    EncodedFile::new(e.path()),
                    find_qif(&Path::new(&e.path())).unwrap_or(None),
                )
            }))
    }
}

struct EncodedDir(PathBuf);

impl EncodedDir {
    pub fn iter(&self) -> Result<impl Iterator<Item = ImplEncodedDir>> {
        let path = if self.0.file_name().unwrap_or_default() == OsStr::new("encoded") {
            self.0.join("qpack-05")
        } else {
            self.0.clone()
        };

        Ok(path
            .read_dir()?
            .filter_map(Result::ok)
            .filter(|e| e.path().is_dir())
            .map(|e| {
                ImplEncodedDir(
                    e.path(),
                    e.file_name().to_str().unwrap_or_default().to_string(),
                )
            }))
    }
}

struct QifFile(PathBuf);

impl QifFile {
    fn compare(&self, other: &mut dyn Iterator<Item = &qpack::HeaderField>) -> Result<()> {
        let value = String::from_utf8_lossy(&fs::read(&self.0)?)
            .split('\n')
            .filter(|l| !l.is_empty())
            .map(Vec::from)
            .collect::<Vec<Vec<u8>>>();

        for field in value.iter() {
            let field_str = String::from_utf8_lossy(&field.to_owned()).to_string();
            let other_field = String::from(
                other
                    .next()
                    .cloned()
                    .ok_or_else(|| anyhow!("Could not find field {} in other block", field_str))?,
            );

            if field_str != other_field {
                return Err(anyhow!(
                    "Fields differ: '{}' != '{}'",
                    field_str,
                    other_field
                ));
            }
        }

        Ok(())
    }

    fn blocks(&self) -> Result<Vec<Vec<u8>>> {
        let content = fs::read_to_string(&self.0)?;

        let blocks = content
            .split("\n\n")
            .filter(|l| !l.is_empty())
            .map(Vec::from)
            .collect::<Vec<Vec<u8>>>();
        Ok(blocks)
    }
}

struct QifDir(PathBuf);

impl QifDir {
    pub fn iter(&self) -> Result<impl Iterator<Item = QifFile>> {
        Ok(self
            .0
            .read_dir()?
            .filter_map(Result::ok)
            .filter(|e| e.path().is_file() && e.path().extension() == Some(OsStr::new("qif")))
            .map(|f| QifFile(f.path())))
    }
}

enum InputType {
    EncodedFile(EncodedFile, QifFile),
    ImplEncodedDir(ImplEncodedDir),
    EncodedDir(EncodedDir),
    QifFile(QifFile),
    QifDir(QifDir),
    Unknown,
}

impl InputType {
    fn is_impl_encoded_dir(path: &Path) -> bool {
        if !path.is_dir() {
            return false;
        }
        let ancestors = path
            .ancestors()
            .map(Path::file_name)
            .filter_map(|e| e)
            .take(3)
            .collect::<Vec<_>>();

        ancestors.len() >= 3
            && ancestors[1] == OsStr::new("qpack-05")
            && ancestors[2] == OsStr::new("encoded")
    }

    fn is_encoded_dir(path: &Path) -> Result<bool> {
        if !path.is_dir() {
            return Ok(false);
        }

        Ok(
            path.file_name().unwrap_or_default() == OsStr::new("encoded")
                || path.file_name().unwrap_or_default() == OsStr::new("qpack-05"),
        )
    }

    fn is_qif_dir(path: &Path) -> Result<bool> {
        if !path.is_dir() {
            return Ok(false);
        }

        Ok(path
            .read_dir()?
            .filter_map(Result::ok)
            .any(|f| f.path().extension() == Some(OsStr::new("qif"))))
    }

    pub fn what_is(path: &Path) -> Result<Self> {
        let input_type = if !path.exists() {
            return Err(anyhow!("no such file or directory: {:?}", path));
        } else if path.is_file() {
            let file_name = path
                .file_name()
                .and_then(OsStr::to_str)
                .ok_or_else(|| anyhow!("No file name found in {:?}", path))?;

            if file_name.contains(".out") {
                let qif = find_qif(&Path::new(path))?
                    .ok_or_else(|| anyhow!("Couldn't find qif file for {:?}", path))?;
                InputType::EncodedFile(EncodedFile::new(PathBuf::from(path)), qif)
            } else if file_name.ends_with(".qif") {
                InputType::QifFile(QifFile(PathBuf::from(path)))
            } else {
                InputType::Unknown
            }
        } else if InputType::is_impl_encoded_dir(path) {
            InputType::ImplEncodedDir(ImplEncodedDir(
                path.to_path_buf(),
                path.parent()
                    .unwrap()
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .into(),
            ))
        } else if InputType::is_encoded_dir(path)? {
            println!("encoder dir");
            InputType::EncodedDir(EncodedDir(path.to_path_buf()))
        } else if InputType::is_qif_dir(path)? {
            InputType::QifDir(QifDir(path.to_path_buf()))
        } else {
            InputType::Unknown
        };
        Ok(input_type)
    }
}

fn find_qif(path: &Path) -> Result<Option<QifFile>> {
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .map(|s| s.split('.').take(1).collect::<String>())
        .ok_or_else(|| anyhow!("Could not parse {:?} filename", path.file_name()))?;

    Ok(find_qif_dir(path)?.map(|d| QifFile(d.join(name + ".qif"))))
}

fn find_qif_dir(path: &Path) -> Result<Option<PathBuf>> {
    let ancestors = path.ancestors().skip(1).take(5).collect::<Vec<_>>();
    for a in ancestors {
        let mut dir = a.read_dir()?;
        let found = dir.find(|ref mut e| {
            if let Ok(e) = e {
                e.path().file_name() == Some(OsStr::new("qifs"))
            } else {
                false
            }
        });

        if let Some(found) = found {
            return Ok(Some(found?.path()));
        }
    }
    Ok(None)
}
