use crate::resolver::DataPtr;
use findshlibs::{SharedLibrary, TargetSharedLibrary};
use hashbrown::{
    hash_map::{DefaultHashBuilder, Entry, VacantEntry},
    HashMap,
};
use memmap::Mmap;
use object::{Object, ObjectSymbol, SymbolKind};
use snafu::{OptionExt, ResultExt, Snafu};
use std::{
    alloc::{Allocator, Global},
    fmt::Debug,
    fs, io,
    ops::Range,
    path::Path,
    result,
};

type SymbolKey<A> = (Vec<u8, A>, usize);

pub struct ReversedSymbolsMap<A: Allocator + Clone> {
    map: HashMap<SymbolKey<A>, Range<DataPtr>, DefaultHashBuilder, A>,
    allocator: A,
}

impl<A: Allocator + Clone> ReversedSymbolsMap<A> {
    pub fn get_range_for_symbol(&self, name: &str, idx: usize) -> Option<&Range<DataPtr>> {
        let symbol_bytes = name.as_bytes().to_vec_in(self.allocator.clone());
        self.map.get(&(symbol_bytes, idx))
    }
}

#[derive(Default)]
pub struct ReversedSymbolsCache<A: Allocator + Clone = Global> {
    cache: HashMap<Vec<u8, A>, ReversedSymbolsMap<A>, DefaultHashBuilder, A>,
    allocator: A,
}

impl<A: Allocator + Clone> ReversedSymbolsCache<A> {
    pub fn new_in(alloc: A) -> Self {
        Self {
            cache: HashMap::new_in(alloc.clone()),
            allocator: alloc,
        }
    }

    fn add_missing_symbols_map(
        vacant_entry: VacantEntry<Vec<u8, A>, ReversedSymbolsMap<A>, DefaultHashBuilder, A>,
        allocator: A,
    ) -> Result<&ReversedSymbolsMap<A>> {
        // The key comes from a Path, so turn it back without checking.
        let path_bytes = vacant_entry.key();
        let path = Path::new(unsafe { std::str::from_utf8_unchecked(path_bytes) });

        log::debug!(
            "Loading symbols for: {}",
            path.file_name().unwrap().to_string_lossy()
        );

        let mut binary_bias = None;
        TargetSharedLibrary::each(|shlib| {
            if shlib.name() == path.as_os_str() {
                binary_bias = Some(shlib.virtual_memory_bias());
            }
        });
        let binary_bias: usize = binary_bias.context(SharedLibraryNotFound)?.into();
        log::trace!("Binary bias: {:#x}", binary_bias);

        let binary_file = fs::File::open(&path).context(BinaryFileNotFound)?;
        let file_map = unsafe { Mmap::map(&binary_file).context(MmapFailed)? };
        let object = object::File::parse(&file_map).context(ParseFailed)?;

        let mut symbol_counts = HashMap::new_in(allocator.clone());
        let mut symbols_map = HashMap::new_in(allocator.clone());
        object
            .symbols()
            .filter(|obj_symbol| {
                if !(obj_symbol.is_definition()
                    && obj_symbol.size() > 0
                    && obj_symbol.kind() == SymbolKind::Data
                    && obj_symbol.name().is_ok())
                {
                    return false;
                }

                let name = obj_symbol.name().unwrap();
                !name.contains("__sanitizer")
                    && !name.contains("__xray")
                    && !name.contains(".llvm.")
            })
            .for_each(|obj_symbol| {
                let name = obj_symbol.name().unwrap();
                let base_address = obj_symbol.address() as usize + binary_bias;
                let end_address = base_address + obj_symbol.size() as usize;
                let range = Range {
                    start: DataPtr::from(base_address as *const u8),
                    end: DataPtr::from(end_address as *const u8),
                };

                let count = symbol_counts.entry(name).or_insert(0usize);
                let current_count = *count;
                *count += 1;

                symbols_map.insert(
                    (name.as_bytes().to_vec_in(allocator.clone()), current_count),
                    range,
                );
            });

        log::debug!(
            "Cached {} symbols for: {}",
            symbols_map.len(),
            path.file_name().unwrap().to_string_lossy()
        );

        Ok(vacant_entry.insert(ReversedSymbolsMap {
            map: symbols_map,
            allocator,
        }))
    }

    pub fn get_symbols_for_binary(
        &mut self,
        path: impl AsRef<Path>,
    ) -> Result<&ReversedSymbolsMap<A>> {
        let path_bytes = path
            .as_ref()
            .to_str()
            .expect("Path is not valid UTF-8")
            .as_bytes()
            .to_vec_in(self.allocator.clone());

        match self.cache.entry(path_bytes) {
            Entry::Occupied(occupied) => Ok(occupied.into_mut()),
            Entry::Vacant(vacant) => Self::add_missing_symbols_map(vacant, self.allocator.clone()),
        }
    }
}

type Result<T> = result::Result<T, Error>;
#[derive(Debug, Snafu)]
pub enum Error {
    BinaryFileNotFound { source: io::Error },
    MmapFailed { source: io::Error },
    ParseFailed { source: object::Error },
    SharedLibraryNotFound,
}
