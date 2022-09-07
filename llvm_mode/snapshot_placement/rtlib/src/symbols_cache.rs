use crate::tracer::CodePtr;
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

pub type SymbolsMap = RangeMap<CodePtr, String>;

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

        let symbols_map: SymbolsMap = object
            .symbols()
            .filter(|obj_symbol| {
                obj_symbol.is_definition()
                    && obj_symbol.size() > 0
                    && obj_symbol.kind() == SymbolKind::Text
                    && obj_symbol.name().is_ok()
            })
            .map(|obj_symbol| {
                let mut name = obj_symbol.name().unwrap();
                let base_address = obj_symbol.address() as usize + binary_bias;
                let end_address = base_address + obj_symbol.size() as usize;
                let range = Range {
                    start: CodePtr::from(base_address as *const u8),
                    end: CodePtr::from(end_address as *const u8),
                };

                // dfsw$ should not be stripped because it identifies functions that
                // simply wrap the plain symbol. Stripping it would cause a double
                // count.
                if let Some(stripped_name) = name.strip_prefix("dfs$") {
                    name = stripped_name;
                }

                (range, name.to_string())
            })
            .collect();

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
