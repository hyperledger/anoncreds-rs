use std::cell::RefCell;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use indy_utils::base58;
use tempfile;

use crate::error::Result;
use crate::ursa::{
    cl::{RevocationTailsAccessor, RevocationTailsGenerator, Tail},
    errors::{UrsaCryptoError, UrsaCryptoErrorKind},
    hash::{sha2::Sha256, Digest},
};

const TAILS_BLOB_TAG_SZ: u8 = 2;
const TAIL_SIZE: usize = Tail::BYTES_REPR_SIZE;

#[derive(Debug)]
pub struct TailsReader {
    inner: Box<RefCell<dyn TailsReaderImpl>>,
}

impl TailsReader {
    pub(crate) fn new<TR: TailsReaderImpl + 'static>(inner: TR) -> Self {
        Self {
            inner: Box::new(RefCell::new(inner)),
        }
    }
}

pub trait TailsReaderImpl: std::fmt::Debug + Send {
    fn hash(&mut self) -> Result<Vec<u8>>;
    fn read(&mut self, size: usize, offset: usize) -> Result<Vec<u8>>;
}

impl RevocationTailsAccessor for TailsReader {
    fn access_tail(
        &self,
        tail_id: u32,
        accessor: &mut dyn FnMut(&Tail),
    ) -> std::result::Result<(), UrsaCryptoError> {
        trace!("access_tail >>> tail_id: {:?}", tail_id);

        let tail_bytes = self
            .inner
            .borrow_mut()
            .read(
                TAIL_SIZE,
                TAIL_SIZE * tail_id as usize + TAILS_BLOB_TAG_SZ as usize,
            )
            .map_err(|_| {
                UrsaCryptoError::from_msg(
                    UrsaCryptoErrorKind::InvalidState,
                    "Can't read tail bytes from file",
                )
            })?; // FIXME: IO error should be returned

        let tail = Tail::from_bytes(tail_bytes.as_slice())?;
        accessor(&tail);

        trace!("access_tail <<< res: ()");
        Ok(())
    }
}

#[derive(Debug)]
pub struct TailsFileReader {
    path: String,
    file: Option<File>,
    hash: Option<Vec<u8>>,
}

impl TailsFileReader {
    pub fn new(path: &str) -> TailsReader {
        TailsReader::new(Self {
            path: path.to_owned(),
            file: None,
            hash: None,
        })
    }

    pub fn open(&mut self) -> Result<()> {
        if self.file.is_some() {
            Ok(())
        } else {
            let file = File::open(self.path.clone())?;
            self.file.replace(file);
            Ok(())
        }
    }

    pub fn close(&mut self) {
        self.file.take();
    }
}

impl TailsReaderImpl for TailsFileReader {
    fn hash(&mut self) -> Result<Vec<u8>> {
        if self.hash.is_some() {
            return Ok(self.hash.as_ref().unwrap().clone());
        }

        self.open()?;
        let file = self.file.as_mut().unwrap();
        file.seek(SeekFrom::Start(0))?;
        let mut hasher = Sha256::default();
        let mut buf = [0u8; 1024];

        loop {
            let sz = file.read(&mut buf)?;
            if sz == 0 {
                self.hash = Some(hasher.result().to_vec());
                return Ok(self.hash.as_ref().unwrap().clone());
            }
            hasher.input(&buf[0..sz]);
        }
    }

    fn read(&mut self, size: usize, offset: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; size];

        self.open()?;
        let file = self.file.as_mut().unwrap();
        file.seek(SeekFrom::Start(offset as u64))?;
        file.read_exact(buf.as_mut_slice())?;

        Ok(buf)
    }
}

pub trait TailsWriter: std::fmt::Debug {
    fn write(&mut self, generator: &mut RevocationTailsGenerator) -> Result<(String, String)>;
}

#[derive(Debug)]
pub struct TailsFileWriter {
    root_path: PathBuf,
}

impl TailsFileWriter {
    pub fn new(root_path: Option<String>) -> Self {
        Self {
            root_path: root_path
                .map(PathBuf::from)
                .unwrap_or_else(|| std::env::temp_dir()),
        }
    }
}

impl TailsWriter for TailsFileWriter {
    fn write(&mut self, generator: &mut RevocationTailsGenerator) -> Result<(String, String)> {
        let mut tempf = tempfile::NamedTempFile::new_in(self.root_path.clone())?;
        let file = tempf.as_file_mut();
        let mut hasher = Sha256::default();
        let version = &[0u8, 2u8];
        file.write(version)?;
        hasher.input(version);
        while let Some(tail) = generator.try_next()? {
            let tail_bytes = tail.to_bytes()?;
            file.write(tail_bytes.as_slice())?;
            hasher.input(tail_bytes);
        }
        let tails_size = &file.seek(SeekFrom::Current(0))?;
        let hash = base58::encode(hasher.result());
        let path = tempf.path().with_file_name(hash.clone());
        let _outf = match tempf.persist_noclobber(&path) {
            Ok(f) => f,
            Err(err) => {
                return Err(err_msg!(IOError, "Error persisting tails file: {}", err,));
            }
        };
        let path = path.to_string_lossy().into_owned();
        debug!(
            "TailsFileWriter: wrote tails file [size {}]: {}",
            tails_size, path
        );
        Ok((path, hash))
    }
}
