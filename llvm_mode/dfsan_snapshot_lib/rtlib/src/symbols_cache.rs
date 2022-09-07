use crate::tracer::DataPtr;
use findshlibs::{SharedLibrary, TargetSharedLibrary};
use memmap::Mmap;
use object::{Object, ObjectSymbol, SymbolKind};
use rangemap::RangeMap;
use snafu::{OptionExt, ResultExt, Snafu};
use std::{
    collections::{
        btree_map::{Entry, VacantEntry},
        BTreeMap,
    },
    fmt::Debug,
    fs, io,
    ops::Range,
    path::{Path, PathBuf},
    result,
};

pub type SymbolsMap = RangeMap<DataPtr, (String, usize)>;

#[derive(Default)]
pub struct SymbolsCache {
    cache: BTreeMap<PathBuf, SymbolsMap>,
}

impl SymbolsCache {
    fn add_missing_symbols_map(
        vacant_entry: VacantEntry<PathBuf, SymbolsMap>,
    ) -> Result<&SymbolsMap> {
        let path = vacant_entry.key();

        log::debug!("Loading symbols for: {}", path.display());

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

        let mut symbol_counts = BTreeMap::new();
        let symbols_map: SymbolsMap = object
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
            .map(|obj_symbol| {
                let name = obj_symbol.name().unwrap_or_default();
                let base_address = obj_symbol.address() as usize + binary_bias;
                let end_address = base_address + obj_symbol.size() as usize;
                let range = Range {
                    start: DataPtr::from(base_address as *const u8),
                    end: DataPtr::from(end_address as *const u8),
                };

                let count = symbol_counts.entry(name).or_insert(0usize);
                let current_count = *count;
                *count += 1;

                (range, (name.to_string(), current_count))
            })
            .collect();

        log::debug!(
            "Cached {} symbols for: {}",
            symbols_map.iter().count(),
            path.file_name().unwrap().to_string_lossy()
        );

        Ok(vacant_entry.insert(symbols_map))
    }

    pub fn get_symbols_for_binary(&mut self, path: impl AsRef<Path>) -> Result<&SymbolsMap> {
        match self.cache.entry(path.as_ref().to_path_buf()) {
            Entry::Occupied(occupied) => Ok(occupied.into_mut()),
            Entry::Vacant(vacant) => Self::add_missing_symbols_map(vacant),
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
