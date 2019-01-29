use bytes::Buf;
use quinn_h3::qpack;
use quinn_proto::coding::Codec;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::{fs, mem};
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "interop")]
struct Opt {
    path: String,
}

fn main() -> Result<(), Error> {
    let opt = Opt::from_args();
    let input = &opt.path;

    let mut failures = vec![];
    let mut success = vec![];

    match InputType::what_is(Path::new(input))? {
        InputType::EncodedFile(file, qif) => match file.decode() {
            Err(e) => failures.push((file, e)),
            Ok(ref mut v) if qif.is_some() => {
                let mut fields = v.iter().flatten();
                qif.unwrap().compare(&mut fields)?;
                success.push(file);
            }
            Ok(_) => failures.push((file, Error::NoQif)),
        },
        InputType::ImplEncodedDir(dir) => {
            for (file, qif) in dir.iter()? {
                match file.decode() {
                    Err(e) => failures.push((file, e)),
                    Ok(ref mut v) if qif.is_some() => {
                        let mut fields = v.iter().flatten();
                        qif.unwrap().compare(&mut fields)?;
                        success.push(file);
                    }
                    Ok(_) => failures.push((file, Error::NoQif)),
                }
            }
        }
        _ => unimplemented!(),
    }

    for failure in &failures {
        println!(
            "{: <32}: {:?}",
            failure
                .0
                .file
                .file_name()
                .unwrap_or(OsStr::new("err"))
                .to_str()
                .unwrap(),
            failure.1
        );
    }

    println!("\nSuccess: {}, Failures: {}", success.len(), failures.len());

    if failures.len() == 0 {
        Ok(())
    } else {
        Err(Error::SomeFailures)
    }
}

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

    fn next<'a>(&'a mut self) -> Result<Option<(std::io::Cursor<&'a [u8]>, u64)>, Error> {
        self.buf.advance(self.last_block_len);
        if self.buf.remaining() < mem::size_of::<u64>() + mem::size_of::<u32>() {
            if self.buf.remaining() > 0 {
                return Err(Error::TrailingData(self.buf.remaining()));
            }
            return Ok(None);
        }

        let current = u64::decode(&mut self.buf)?;
        let length = u32::decode(&mut self.buf)? as usize;

        if self.buf.remaining() < length {
            Err(Error::UnexpectedEnd)
        } else {
            self.last_block_len = length;
            let block = std::io::Cursor::new(&self.buf.bytes()[..length]);

            Ok(Some((block, current)))
        }
    }
}

#[derive(Debug)]
struct EncodedFile {
    file: PathBuf,
    table_size: usize,
    hundred: usize,
    instance: usize,
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

        let (instance, hundred, table_size) = if numbers.len() >= 3 {
            (numbers[0], numbers[1], numbers[2])
        } else {
            (0, 0, 0)
        };

        Self {
            file,
            table_size,
            hundred,
            instance,
        }
    }

    pub fn decode(&self) -> Result<Vec<Vec<qpack::HeaderField>>, Error> {
        let encoded = fs::read(&self.file)?;
        let mut table = qpack::DynamicTable::new();
        let mut blocks = BlockIterator::new(std::io::Cursor::new(&encoded));
        let mut count = 0;
        let mut decoder = vec![];
        let mut decoded = vec![];

        while let Some((mut buf, current)) = blocks.next().expect("next block") {
            if current == 0 {
                // encoder stream
                qpack::on_encoder_recv(&mut table.inserter(), &mut buf, &mut decoder)?;
                continue;
            }

            if current != count + 1 {
                eprintln!("got wrong stream ID: {}", current);
                break;
            }

            decoded.push(qpack::decode_header(&mut table, &mut buf)?);
            count += 1;
        }
        Ok(decoded)
    }
}

struct ImplEncodedDir(PathBuf, String);

impl ImplEncodedDir {
    pub fn iter(&self) -> Result<impl Iterator<Item = (EncodedFile, Option<QifFile>)>, Error> {
        Ok(self
            .0
            .read_dir()?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .map(|e| {
                (
                    EncodedFile::new(e.path()),
                    find_qif(&Path::new(&e.path())).unwrap_or(None),
                )
            }))
    }
}

struct QifFile(PathBuf);

impl QifFile {
    fn compare(&self, other: &mut Iterator<Item = &qpack::HeaderField>) -> Result<(), Error> {
        let value = String::from_utf8_lossy(&fs::read(&self.0)?)
            .split("\n")
            .filter(|l| l.len() != 0)
            .map(|c| Vec::from(c))
            .collect::<Vec<Vec<u8>>>();

        for field in value.iter() {
            let field_str = String::from_utf8_lossy(&field.to_owned()).to_string();
            let other_field = other.next().ok_or(Error::MissingDecoded)?;

            if field_str != other_field.to_string() {
                return Err(Error::NotMatching(field_str, other_field.to_string()));
            }
        }

        Ok(())
    }
}

enum InputType {
    EncodedFile(EncodedFile, Option<QifFile>),
    ImplEncodedDir(ImplEncodedDir),
    QifFile,
    QifDir,
    Unknown,
}

impl InputType {
    fn is_encoded_dir(path: &Path) -> bool {
        if !path.is_dir() {
            return false;
        }
        let ancestors = path
            .ancestors()
            .map(|e| e.file_name())
            .filter_map(|e| e)
            .take(3)
            .collect::<Vec<_>>();

        if ancestors.len() >= 3
            && ancestors[1] == OsStr::new("qpack-05")
            && ancestors[2] == OsStr::new("encoded")
        {
            true
        } else {
            false
        }
    }

    pub fn what_is(path: &Path) -> Result<Self, Error> {
        let input_type = if path.is_file() {
            let file_name = path
                .file_name()
                .ok_or(Error::BadFilename)?
                .to_str()
                .ok_or(Error::BadFilename)?;
            if file_name.contains(".out") {
                InputType::EncodedFile(
                    EncodedFile::new(PathBuf::from(path)),
                    find_qif(&Path::new(path)).unwrap_or(None),
                )
            } else if file_name.ends_with(".qif") {
                InputType::QifFile
            } else {
                InputType::Unknown
            }
        } else if InputType::is_encoded_dir(path) {
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
        } else {
            InputType::Unknown
        };
        Ok(input_type)
    }
}

fn find_qif(path: &Path) -> Result<Option<QifFile>, Error> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.split(".").take(1).collect::<String>())
        .ok_or(Error::BadFilename)?;

    Ok(find_qif_dir(path)?.map(|d| QifFile(d.join(name + ".qif"))))
}

fn find_qif_dir(path: &Path) -> Result<Option<PathBuf>, std::io::Error> {
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

        if found.is_some() {
            return Ok(Some(found.unwrap()?.path()));
        }
    }
    Ok(None)
}

#[derive(Debug)]
enum Error {
    TrailingData(usize),
    UnexpectedEnd,
    BadFilename,
    IO(std::io::Error),
    Decode(qpack::DecoderError),
    NoQif,
    MissingDecoded,
    NotMatching(String, String),
    SomeFailures,
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::IO(e)
    }
}

impl From<qpack::DecoderError> for Error {
    fn from(e: qpack::DecoderError) -> Error {
        Error::Decode(e)
    }
}

impl From<quinn_proto::coding::UnexpectedEnd> for Error {
    fn from(_: quinn_proto::coding::UnexpectedEnd) -> Error {
        Error::UnexpectedEnd
    }
}
