use std::time;
use std::fmt;
use std::fs::OpenOptions;
use std::io::Read;
use std::iter::FromIterator;
use std::ops;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use anyhow::Result;
use positioned_io::ReadAt;
use rayon::iter::plumbing::*;
use rayon::iter::*;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use typenum::marker_traits::Unsigned;

use log::{warn, debug};
use tempfile::tempfile;

use crate::hash::Algorithm;
use crate::merkle::{get_merkle_tree_row_count, log2_pow2, next_pow2, Element};

use s3::bucket::Bucket;
use s3::creds::Credentials;
use s3::region::Region;
use tokio::runtime::Runtime;

/// Tree size (number of nodes) used as threshold to decide which build algorithm
/// to use. Small trees (below this value) use the old build algorithm, optimized
/// for speed rather than memory, allocating as much as needed to allow multiple
/// threads to work concurrently without interrupting each other. Large trees (above)
/// use the new build algorithm, optimized for memory rather than speed, allocating
/// as less as possible with multiple threads competing to get the write lock.
pub const SMALL_TREE_BUILD: usize = 1024;

// Number of nodes to process in parallel during the `build` stage.
pub const BUILD_CHUNK_NODES: usize = 1024 * 4;

mod disk;
mod level_cache;
mod mmap;
mod vec;

pub use disk::DiskStore;
pub use level_cache::LevelCacheStore;
pub use mmap::MmapStore;
pub use vec::VecStore;

#[derive(Debug, Copy, Clone)]
pub struct Range {
    pub index: usize,
    pub offset: usize,
    pub start: usize,
    pub end: usize,
    pub buf_start: usize,
    pub buf_end: usize,
}

#[derive(Clone)]
pub struct ExternalReader<R: Read + Send + Sync> {
    pub data_path: PathBuf,
    pub offset: usize,
    pub source: R,
    pub path: String,
    pub read_fn: fn(start: usize, end: usize, buf: &mut [u8], path: String, oss: bool, oss_config: &StoreOssConfig) -> Result<usize>,
    pub read_ranges: fn(ranges: Vec<Range>, buf: &mut [u8], path: String, oss: bool, oss_config: &StoreOssConfig) -> Result<Vec<Result<usize>>>,
    pub oss: bool,
    pub oss_config: StoreOssConfig,
}

impl<R: Read + Send + Sync> ExternalReader<R> {
    pub fn read(&self, start: usize, end: usize, buf: &mut [u8]) -> Result<usize> {
        (self.read_fn)(start + self.offset, end + self.offset, buf, self.path.clone(), self.oss, &self.oss_config)
    }
    pub fn read_ranges(&self, ranges: Vec<Range>, buf: &mut [u8]) -> Result<Vec<Result<usize>>> {
        let mut off_ranges = Vec::new();
        for range in ranges {
            off_ranges.push(Range {
                index: range.index,
                start: range.offset + range.start,
                end: range.offset + range.end,
                offset: range.offset,
                buf_start: range.buf_start,
                buf_end: range.buf_end,
            });
            debug!("reader read ranges {}-{} | {} | {}",
                   range.start,
                   range.end,
                   self.offset,
                   self.path.clone());
        }
        (self.read_ranges)(off_ranges, buf, self.path.clone(), self.oss, &self.oss_config)
    }
}

pub fn read_from_oss(start: usize, end: usize, buf: &mut [u8], path: String, oss_config: &StoreOssConfig) -> Result<usize> {
    let path_buf = PathBuf::from(path);
    let obj_name = path_buf.strip_prefix(oss_config.landed_dir.clone()).unwrap();
    let credentials = Credentials::new(
        Some(&oss_config.access_key),
        Some(&oss_config.secret_key),
        None, None, None)?;

    debug!("read from oss: endpoints {:?}", oss_config.endpoints);

    let mut succ = false;
    let endpoints: Vec<&str> = oss_config.endpoints.as_str().split(",").collect();
    for url in endpoints.clone() {
        // debug!("read from oss: url {}", url.to_string().clone());
        let region = Region::Custom {
            region: oss_config.region.clone(),
            endpoint: url.to_string().clone(),
        };

        let bucket = Bucket::new_with_path_style(&oss_config.bucket_name, region, time::Duration::from_secs(5), credentials.clone())?;
        let mut rt = Runtime::new()?;

        debug!("start read from oss: start {}, end {}, path {:?}", start, end, obj_name.clone());
        let (data, code) = match rt.block_on(
            bucket.get_object_range(obj_name.to_str().unwrap(), start as u64, Some(end as u64))){
                Ok(info)=>info,
                Err(e)=>{
                    warn!("get object range from {} error {}", url.to_string().clone(), &e);
                    continue;
                }
            };
        // ensure!(code == 200 || code == 206, "Cannot get {:?} from {}", obj_name, url);
        if code != 200 && code != 206 {
            warn!( "Cannot get {:?} from {} ret code {}", obj_name, url.to_string().clone(), code);
            continue;
        }

        buf.copy_from_slice(&data[0..end - start]);
        succ = true;
        // success
        break;
    }

    if succ {
        Ok(end - start)
    }else{
        Err(anyhow!("read_from_oss cannot read info from all endpoints {:?}", endpoints.clone()))
    }
}

pub fn read_ranges_from_oss(ranges: Vec<Range>, buf: &mut [u8], path: String, oss_config: &StoreOssConfig) -> Result<Vec<Result<usize>>> {
    let ranges_len = ranges.clone().len();
    let path_buf = PathBuf::from(path);
    let obj_name = path_buf.strip_prefix(oss_config.landed_dir.clone()).unwrap();
    let credentials = Credentials::new(
        Some(&oss_config.access_key),
        Some(&oss_config.secret_key),
        None, None, None)?;
    let mut sizes = Vec::new();
    let endpoints: Vec<&str> = oss_config.endpoints.as_str().split(",").collect();
    debug!("read_ranges_from_oss for {:?}", oss_config.endpoints);

    let mut succ = false;
'outer: for url in endpoints.clone() {
            // clear the prev data
            sizes.clear();
            let region = Region::Custom {
                region: oss_config.region.clone(),
                endpoint: url.to_string().clone(),
            };
            let bucket = Bucket::new_with_path_style(&oss_config.bucket_name, region, time::Duration::from_secs(5), credentials.clone())?;
            let mut rt = Runtime::new()?;

            if oss_config.multi_ranges && 1 < ranges_len {
                let mut http_ranges = Vec::<ops::Range<usize>>::new();

                for range in ranges.clone().iter() {
                    debug!("multi ranges to oss: {}-{} | {:?}", range.start, range.end, obj_name);
                    http_ranges.push(ops::Range{ start: range.start, end: range.end });
                }

                debug!("start multi read from oss {:?}, {}/{} [{}] / {:?}", obj_name,
                    url.to_string().clone(), oss_config.bucket_name,
                oss_config.multi_ranges, http_ranges.clone());

                let (datas, code) = match rt.block_on(
                    bucket.get_object_multi_ranges(obj_name.to_str().unwrap(), http_ranges.clone())){
                        Ok(info)=>info,
                        Err(e)=>{
                            warn!("get object {:?} multi range from {} error {}", obj_name, url.to_string().clone(), &e);
                            continue 'outer;
                        }
                    };
                if code != 200 && code != 206 {
                    warn!("Cannot get {:?} from {} code {}", obj_name, url.to_string().clone(), code);
                    continue 'outer;
                }

                debug!("done multi read from oss {:?}, {}/{} [{}] / {:?}", obj_name,
                    url.to_string().clone(), oss_config.bucket_name,
                    oss_config.multi_ranges, http_ranges.clone());

                for (i, data) in datas.iter().enumerate() {
                    let mut found = false;

                    if data.data.len() == 0 {
                        warn!("Cannot get {:?} from {}", obj_name, url.to_string().clone());
                        continue 'outer;
                    }

                    for range in ranges.clone() {
                        if range.start == data.range.start &&
                            range.buf_end - range.buf_start <= data.data.len() {
                            found = true;
                            debug!("multi ranges read: {} | {}-{} | {:?}", data.range.start, range.buf_start, range.buf_end, obj_name);
                            buf[range.buf_start..range.buf_end].copy_from_slice(&data.data[0..range.buf_end - range.buf_start]);
                            sizes.push(Ok(range.end - range.start));
                        }
                    }

                    if !found {
                        warn!("Cannot get {:?} from {}", obj_name, url.to_string().clone());
                        continue 'outer;
                    }
                }
                succ = true;
                break;
            } else {
                for range in ranges.clone() {
                    debug!("start read from oss: start {}, end {}, path {:?}", range.start, range.end, obj_name.clone());
                    let (data, code) = match rt.block_on(
                        bucket.get_object_range(obj_name.to_str().unwrap(), range.start as u64, Some(range.end as u64))){
                            Ok(info)=>info,
                            Err(e)=>{
                                warn!("get object range from {} error {}",url.to_string().clone(), &e);
                                continue 'outer;
                            }
                        };
                    if code != 200 && code != 206 {
                        warn!("Cannot get {:?} from {} code {}", obj_name, url.to_string().clone(), code);
                        continue 'outer;
                    }
                    debug!("done read from oss: start {}, end {}, path {:?}", range.start, range.end, obj_name.clone());
                    buf[range.buf_start..range.buf_end].copy_from_slice(&data[0..range.end - range.start]);
                    sizes.push(Ok(range.end - range.start));
                }
                succ = true;
                break;
            }
        }
    if succ {
        Ok(sizes)
    }else{
        Err(anyhow!("read_ranges_from_oss cannot read info from all endpoints {:?}", endpoints.clone()))
    }
}

impl ExternalReader<std::fs::File> {
    pub fn new_from_config(replica_config: &ReplicaConfig, index: usize) -> Result<Self> {
        Ok(ExternalReader {
            offset: replica_config.offsets[index],
            source: tempfile()?,
            data_path: replica_config.path.clone(),
            path: replica_config.path.as_path().display().to_string(),
            read_fn: |start, end, buf: &mut [u8], path: String, oss: bool, oss_config: &StoreOssConfig| {
                if oss {
                    read_from_oss(start, end, buf, path, oss_config)?;
                } else {
                    debug!("read from local: start {}, end {}, path {}", start, end, path);
                    let reader = OpenOptions::new().read(true).open(&path)?;
                    reader.read_exact_at(start as u64, &mut buf[0..end - start])?;
                }
                Ok(end - start)
            },
            read_ranges: |ranges, buf, path: String, oss: bool, oss_config: &StoreOssConfig| {
                if oss {
                    read_ranges_from_oss(ranges, buf, path, oss_config)
                } else {
                    let mut sizes = Vec::new();
                    debug!("multi read from local {} start", path);
                    for range in ranges {
                        debug!("multi read from local: start {} / {}, end {} / {}, path {} | {} | {}",
                               range.start, range.buf_start, range.end, range.buf_end,
                               path, buf.len(), range.index);
                        let reader = OpenOptions::new().read(true).open(&path)?;
                        let read_len = range.end - range.start;
                        reader.read_exact_at(range.start as u64, &mut buf[range.buf_start..range.buf_end])?;
                        sizes.push(Ok(read_len));
                    }
                    debug!("multi read from local {} done", path);
                    Ok(sizes)
                }
            },
            oss: replica_config.oss,
            oss_config: replica_config.oss_config.clone(),
        })
    }

    pub fn new_from_path(path: &PathBuf) -> Result<Self> {
        Self::new_from_config(&ReplicaConfig::from(path), 0)
    }
}

impl<R: Read + Send + Sync> fmt::Debug for ExternalReader<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExternalReader")
            .field("source: Read + Send + Sync", &1)
            .field(
                "read_fn: callback(start: usize, end: usize, buf: &mut [u8])",
                &2,
            )
            .finish()
    }
}

// Version 1 always contained the base layer data (even after 'compact').
// Version 2 no longer contains the base layer data after compact.
#[derive(Clone, Copy, Debug)]
pub enum StoreConfigDataVersion {
    One = 1,
    Two = 2,
}

const DEFAULT_STORE_CONFIG_DATA_VERSION: u32 = StoreConfigDataVersion::Two as u32;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct StoreOssConfig {
    pub endpoints: String,
    pub landed_dir: PathBuf,
    pub access_key: String,
    pub secret_key: String,
    pub bucket_name: String,
    pub sector_name: String,
    pub region: String,
    pub multi_ranges: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ReplicaConfig {
    pub path: PathBuf,
    pub offsets: Vec<usize>,
    pub oss: bool,
    pub oss_config: StoreOssConfig,
}

impl ReplicaConfig {
    pub fn new<T: Into<PathBuf>>(path: T, offsets: Vec<usize>) -> Self {
        ReplicaConfig {
            path: path.into(),
            offsets,
            oss: false,
            oss_config: Default::default(),
        }
    }

    pub fn new_with_oss_config<T: Into<PathBuf>>(path: T, offsets: Vec<usize>, oss: bool, oss_config: &StoreOssConfig) -> Self {
        ReplicaConfig {
            path: path.into(),
            offsets,
            oss,
            oss_config: oss_config.clone(),
        }
    }

    pub fn from_oss_config(path: &PathBuf, oss: bool, oss_config: &StoreOssConfig) -> Self {
        ReplicaConfig {
            path: path.clone(),
            offsets: vec![0],
            oss,
            oss_config: oss_config.clone(),
        }
    }
}

impl From<&PathBuf> for ReplicaConfig {
    fn from(path: &PathBuf) -> Self {
        ReplicaConfig {
            path: path.clone(),
            offsets: vec![0],
            oss: false,
            oss_config: Default::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct StoreConfig {
    /// A directory in which data (a merkle tree) can be persisted.
    pub path: PathBuf,

    /// A unique identifier used to help specify the on-disk store
    /// location for this particular data.
    pub id: String,

    /// The number of elements in the DiskStore.  This field is
    /// optional, and unused internally.
    pub size: Option<usize>,

    /// The number of merkle tree rows_to_discard then cache on disk.
    pub rows_to_discard: usize,

    pub oss: bool,
    pub oss_config: StoreOssConfig,
}

impl StoreConfig {
    pub fn new<T: Into<PathBuf>, S: Into<String>>(path: T, id: S, rows_to_discard: usize) -> Self {
        StoreConfig {
            path: path.into(),
            id: id.into(),
            size: None,
            rows_to_discard,
            oss: false,
            oss_config: Default::default(),
        }
    }

    pub fn new_with_oss_config<T: Into<PathBuf>, S: Into<String>>(path: T, id: S, rows_to_discard: usize, oss: bool, oss_config: &StoreOssConfig) -> Self {
        StoreConfig {
            path: path.into(),
            id: id.into(),
            size: None,
            rows_to_discard,
            oss: oss,
            oss_config: oss_config.clone(),
        }
    }

    // If the tree is large enough to use the default value
    // (per-arity), use it.  If it's too small to cache anything
    // (i.e. not enough rows), don't discard any.
    pub fn default_rows_to_discard(leafs: usize, branches: usize) -> usize {
        let row_count = get_merkle_tree_row_count(leafs, branches);
        if row_count <= 2 {
            // If a tree only has a root row and/or base, there is
            // nothing to discard.
            return 0;
        } else if row_count == 3 {
            // If a tree only has 1 row between the base and root,
            // it's all that can be discarded.
            return 1;
        }

        // row_count - 2 discounts the base layer (1) and root (1)
        let max_rows_to_discard = row_count - 2;

        // Discard at most 'constant value' rows (coded below,
        // differing by arity) while respecting the max number that
        // the tree can support discarding.
        match branches {
            2 => std::cmp::min(max_rows_to_discard, 7),
            4 => std::cmp::min(max_rows_to_discard, 5),
            _ => std::cmp::min(max_rows_to_discard, 2),
        }
    }

    // Deterministically create the data_path on-disk location from a
    // path and specified id.
    pub fn data_path(path: &PathBuf, id: &str) -> PathBuf {
        Path::new(&path).join(format!(
            "sc-{:0>2}-data-{}.dat",
            DEFAULT_STORE_CONFIG_DATA_VERSION, id
        ))
    }

    pub fn from_config<S: Into<String>>(config: &StoreConfig, id: S, size: Option<usize>) -> Self {
        let val = if let Some(size) = size {
            Some(size)
        } else {
            config.size
        };

        StoreConfig {
            path: config.path.clone(),
            id: id.into(),
            size: val,
            rows_to_discard: config.rows_to_discard,
            oss: config.oss,
            oss_config: config.oss_config.clone(),
        }
    }
}

/// Backing store of the merkle tree.
pub trait Store<E: Element>: std::fmt::Debug + Send + Sync + Sized {
    /// Creates a new store which can store up to `size` elements.
    fn new_with_config(size: usize, branches: usize, config: StoreConfig) -> Result<Self>;
    fn new(size: usize) -> Result<Self>;

    fn new_from_slice_with_config(
        size: usize,
        branches: usize,
        data: &[u8],
        config: StoreConfig,
    ) -> Result<Self>;

    fn new_from_slice(size: usize, data: &[u8]) -> Result<Self>;

    fn new_from_disk(size: usize, branches: usize, config: &StoreConfig) -> Result<Self>;

    fn new_from_oss(size: usize, branches: usize, config: &StoreConfig) -> Result<Self>;

    fn write_at(&mut self, el: E, index: usize) -> Result<()>;

    // Used to reduce lock contention and do the `E` to `u8`
    // conversion in `build` *outside* the lock.
    // `buf` is a slice of converted `E`s and `start` is its
    // position in `E` sizes (*not* in `u8`).
    fn copy_from_slice(&mut self, buf: &[u8], start: usize) -> Result<()>;

    // compact/shrink resources used where possible.
    fn compact(&mut self, branches: usize, config: StoreConfig, store_version: u32)
        -> Result<bool>;

    // re-instate resource usage where needed.
    fn reinit(&mut self) -> Result<()> {
        Ok(())
    }

    // Removes the store backing (does not require a mutable reference
    // since the config should provide stateless context to what's
    // needed to be removed -- with the exception of in memory stores,
    // where this is arguably not important/needed).
    fn delete(config: StoreConfig) -> Result<()>;

    fn read_at(&self, index: usize) -> Result<E>;
    fn read_range(&self, r: ops::Range<usize>) -> Result<Vec<E>>;
    fn read_into(&self, pos: usize, buf: &mut [u8]) -> Result<()>;
    fn read_range_into(&self, start: usize, end: usize, buf: &mut [u8]) -> Result<()>;
    fn read_ranges_into(&self, ranges: Vec<Range>, buf: &mut [u8]) -> Result<Vec<Result<usize>>>;

    fn path(&self) -> Option<&PathBuf>;
    fn path_by_range(&self, range: Range) -> Option<&PathBuf>;
    fn offset_by_range(&self, range: Range) -> usize;

    fn len(&self) -> usize;
    fn loaded_from_disk(&self) -> bool;
    fn is_empty(&self) -> bool;
    fn push(&mut self, el: E) -> Result<()>;
    fn last(&self) -> Result<E> {
        self.read_at(self.len() - 1)
    }

    // Sync contents to disk (if it exists). This function is used to avoid
    // unnecessary flush calls at the cost of added code complexity.
    fn sync(&self) -> Result<()> {
        Ok(())
    }

    #[inline]
    fn build_small_tree<A: Algorithm<E>, U: Unsigned>(
        &mut self,
        leafs: usize,
        row_count: usize,
    ) -> Result<E> {
        ensure!(leafs % 2 == 0, "Leafs must be a power of two");

        let mut level: usize = 0;
        let mut width = leafs;
        let mut level_node_index = 0;
        let branches = U::to_usize();
        let shift = log2_pow2(branches);

        while width > 1 {
            // Same indexing logic as `build`.
            let (layer, write_start) = {
                let (read_start, write_start) = if level == 0 {
                    // Note that we previously asserted that data.len() == leafs.
                    (0, Store::len(self))
                } else {
                    (level_node_index, level_node_index + width)
                };

                let layer: Vec<_> = self
                    .read_range(read_start..read_start + width)?
                    .par_chunks(branches)
                    .map(|nodes| A::default().multi_node(&nodes, level))
                    .collect();

                (layer, write_start)
            };

            for (i, node) in layer.into_iter().enumerate() {
                self.write_at(node, write_start + i)?;
            }

            level_node_index += width;
            level += 1;
            width >>= shift; // width /= branches;
        }

        ensure!(row_count == level + 1, "Invalid tree row_count");
        // The root isn't part of the previous loop so `row_count` is
        // missing one level.

        self.last()
    }

    fn process_layer<A: Algorithm<E>, U: Unsigned>(
        &mut self,
        width: usize,
        level: usize,
        read_start: usize,
        write_start: usize,
    ) -> Result<()> {
        let branches = U::to_usize();
        let data_lock = Arc::new(RwLock::new(self));

        // Allocate `width` indexes during operation (which is a negligible memory bloat
        // compared to the 32-bytes size of the nodes stored in the `Store`s) and hash each
        // pair of nodes to write them to the next level in concurrent threads.
        // Process `BUILD_CHUNK_NODES` nodes in each thread at a time to reduce contention,
        // optimized for big sector sizes (small ones will just have one thread doing all
        // the work).
        ensure!(BUILD_CHUNK_NODES % branches == 0, "Invalid chunk size");
        Vec::from_iter((read_start..read_start + width).step_by(BUILD_CHUNK_NODES))
            .par_iter()
            .try_for_each(|&chunk_index| -> Result<()> {
                let chunk_size = std::cmp::min(BUILD_CHUNK_NODES, read_start + width - chunk_index);

                let chunk_nodes = {
                    // Read everything taking the lock once.
                    data_lock
                        .read()
                        .unwrap()
                        .read_range(chunk_index..chunk_index + chunk_size)?
                };

                // We write the hashed nodes to the next level in the
                // position that would be "in the middle" of the
                // previous pair (dividing by branches).
                let write_delta = (chunk_index - read_start) / branches;

                let nodes_size = (chunk_nodes.len() / branches) * E::byte_len();
                let hashed_nodes_as_bytes = chunk_nodes.chunks(branches).fold(
                    Vec::with_capacity(nodes_size),
                    |mut acc, nodes| {
                        let h = A::default().multi_node(&nodes, level);
                        acc.extend_from_slice(h.as_ref());
                        acc
                    },
                );

                // Check that we correctly pre-allocated the space.
                ensure!(
                    hashed_nodes_as_bytes.len() == chunk_size / branches * E::byte_len(),
                    "Invalid hashed node length"
                );

                // Write the data into the store.
                data_lock
                    .write()
                    .unwrap()
                    .copy_from_slice(&hashed_nodes_as_bytes, write_start + write_delta)
            })
    }

    // Default merkle-tree build, based on store type.
    fn build<A: Algorithm<E>, U: Unsigned>(
        &mut self,
        leafs: usize,
        row_count: usize,
        _config: Option<StoreConfig>,
    ) -> Result<E> {
        let branches = U::to_usize();
        ensure!(
            next_pow2(branches) == branches,
            "branches MUST be a power of 2"
        );
        ensure!(Store::len(self) == leafs, "Inconsistent data");
        ensure!(leafs % 2 == 0, "Leafs must be a power of two");

        if leafs <= SMALL_TREE_BUILD {
            return self.build_small_tree::<A, U>(leafs, row_count);
        }

        let shift = log2_pow2(branches);

        // Process one `level` at a time of `width` nodes. Each level has half the nodes
        // as the previous one; the first level, completely stored in `data`, has `leafs`
        // nodes. We guarantee an even number of nodes per `level`, duplicating the last
        // node if necessary.
        let mut level: usize = 0;
        let mut width = leafs;
        let mut level_node_index = 0;
        while width > 1 {
            // Start reading at the beginning of the current level, and writing the next
            // level immediate after.  `level_node_index` keeps track of the current read
            // starts, and width is updated accordingly at each level so that we know where
            // to start writing.
            let (read_start, write_start) = if level == 0 {
                // Note that we previously asserted that data.len() == leafs.
                //(0, data_lock.read().unwrap().len())
                (0, Store::len(self))
            } else {
                (level_node_index, level_node_index + width)
            };

            self.process_layer::<A, U>(width, level, read_start, write_start)?;

            level_node_index += width;
            level += 1;
            width >>= shift; // width /= branches;
        }

        ensure!(row_count == level + 1, "Invalid tree row_count");
        // The root isn't part of the previous loop so `row_count` is
        // missing one level.

        // Return the root
        self.last()
    }
}

// Using a macro as it is not possible to do a generic implementation for all stores.

macro_rules! impl_parallel_iter {
    ($name:ident, $producer:ident, $iter:ident) => {
        impl<E: Element> ParallelIterator for $name<E> {
            type Item = E;

            fn drive_unindexed<C>(self, consumer: C) -> C::Result
            where
                C: UnindexedConsumer<Self::Item>,
            {
                bridge(self, consumer)
            }

            fn opt_len(&self) -> Option<usize> {
                Some(Store::len(self))
            }
        }
        impl<'a, E: Element> ParallelIterator for &'a $name<E> {
            type Item = E;

            fn drive_unindexed<C>(self, consumer: C) -> C::Result
            where
                C: UnindexedConsumer<Self::Item>,
            {
                bridge(self, consumer)
            }

            fn opt_len(&self) -> Option<usize> {
                Some(Store::len(*self))
            }
        }

        impl<E: Element> IndexedParallelIterator for $name<E> {
            fn drive<C>(self, consumer: C) -> C::Result
            where
                C: Consumer<Self::Item>,
            {
                bridge(self, consumer)
            }

            fn len(&self) -> usize {
                Store::len(self)
            }

            fn with_producer<CB>(self, callback: CB) -> CB::Output
            where
                CB: ProducerCallback<Self::Item>,
            {
                callback.callback(<$producer<E>>::new(0, Store::len(&self), &self))
            }
        }

        impl<'a, E: Element> IndexedParallelIterator for &'a $name<E> {
            fn drive<C>(self, consumer: C) -> C::Result
            where
                C: Consumer<Self::Item>,
            {
                bridge(self, consumer)
            }

            fn len(&self) -> usize {
                Store::len(*self)
            }

            fn with_producer<CB>(self, callback: CB) -> CB::Output
            where
                CB: ProducerCallback<Self::Item>,
            {
                callback.callback(<$producer<E>>::new(0, Store::len(self), self))
            }
        }

        #[derive(Debug, Clone)]
        pub struct $producer<'data, E: 'data + Element> {
            pub(crate) current: usize,
            pub(crate) end: usize,
            pub(crate) store: &'data $name<E>,
        }

        impl<'data, E: 'data + Element> $producer<'data, E> {
            pub fn new(current: usize, end: usize, store: &'data $name<E>) -> Self {
                Self {
                    current,
                    end,
                    store,
                }
            }

            pub fn len(&self) -> usize {
                self.end - self.current
            }

            pub fn is_empty(&self) -> bool {
                self.len() == 0
            }
        }

        impl<'data, E: 'data + Element> Producer for $producer<'data, E> {
            type Item = E;
            type IntoIter = $iter<'data, E>;

            fn into_iter(self) -> Self::IntoIter {
                let $producer {
                    current,
                    end,
                    store,
                } = self;

                $iter {
                    current,
                    end,
                    store,
                    err: false,
                }
            }

            fn split_at(self, index: usize) -> (Self, Self) {
                let len = self.len();

                if len == 0 {
                    return (
                        <$producer<E>>::new(0, 0, &self.store),
                        <$producer<E>>::new(0, 0, &self.store),
                    );
                }

                let current = self.current;
                let first_end = current + std::cmp::min(len, index);

                debug_assert!(first_end >= current);
                debug_assert!(current + len >= first_end);

                (
                    <$producer<E>>::new(current, first_end, &self.store),
                    <$producer<E>>::new(first_end, current + len, &self.store),
                )
            }
        }
        #[derive(Debug)]
        pub struct $iter<'data, E: 'data + Element> {
            current: usize,
            end: usize,
            err: bool,
            store: &'data $name<E>,
        }

        impl<'data, E: 'data + Element> $iter<'data, E> {
            fn is_done(&self) -> bool {
                !self.err && self.len() == 0
            }
        }

        impl<'data, E: 'data + Element> Iterator for $iter<'data, E> {
            type Item = E;

            fn next(&mut self) -> Option<Self::Item> {
                if self.is_done() {
                    return None;
                }

                match self.store.read_at(self.current) {
                    Ok(el) => {
                        self.current += 1;
                        Some(el)
                    }
                    _ => {
                        self.err = true;
                        None
                    }
                }
            }
        }

        impl<'data, E: 'data + Element> ExactSizeIterator for $iter<'data, E> {
            fn len(&self) -> usize {
                debug_assert!(self.current <= self.end);
                self.end - self.current
            }
        }

        impl<'data, E: 'data + Element> DoubleEndedIterator for $iter<'data, E> {
            fn next_back(&mut self) -> Option<Self::Item> {
                if self.is_done() {
                    return None;
                }

                match self.store.read_at(self.end - 1) {
                    Ok(el) => {
                        self.end -= 1;
                        Some(el)
                    }
                    _ => {
                        self.err = true;
                        None
                    }
                }
            }
        }
    };
}

impl_parallel_iter!(VecStore, VecStoreProducer, VecStoreIter);
impl_parallel_iter!(DiskStore, DiskStoreProducer, DiskIter);
//impl_parallel_iter!(LevelCacheStore, LevelCacheStoreProducer, LevelCacheIter);
