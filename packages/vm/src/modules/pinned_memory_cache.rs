use cosmwasm_std::Checksum;
use std::collections::HashMap;

use super::cached_module::CachedModule;
use crate::VmResult;

/// Struct storing some additional metadata, which is only of interest for the pinned cache,
/// alongside the cached module.
pub struct InstrumentedModule {
    /// Number of loads from memory this module received
    pub hits: u32,
    /// The actual cached module
    pub module: CachedModule,
}
/// Struct storing some additional metadata, which is only of interest for the pinned cache,
/// alongside the cached module.
pub struct InstrumentedCircuit {
    /// Number of loads from memory this module received
    pub hits: u32,
    /// The actual cached module
    pub circuit: zk_cosmwasm::PinnedCircuit,
}

/// An pinned in memory module cache
pub struct PinnedMemoryCache {
    modules: HashMap<Checksum, InstrumentedModule>,
    circuits: HashMap<Checksum, InstrumentedCircuit>,
}

impl PinnedMemoryCache {
    /// Creates a new cache
    pub fn new() -> Self {
        PinnedMemoryCache {
            modules: HashMap::new(),
            circuits: HashMap::new(),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Checksum, &InstrumentedModule)> {
        self.modules.iter()
    }

    pub fn store(&mut self, checksum: &Checksum, cached_module: CachedModule) -> VmResult<()> {
        self.modules.insert(
            *checksum,
            InstrumentedModule {
                hits: 0,
                module: cached_module,
            },
        );

        Ok(())
    }

    pub fn store_circuit(
        &mut self,
        checksum: &Checksum,
        circuit: zk_cosmwasm::PinnedCircuit,
    ) -> VmResult<()> {
        self.circuits
            .insert(*checksum, InstrumentedCircuit { hits: 0, circuit });
        Ok(())
    }

    /// Removes a module from the cache
    /// Not found modules are silently ignored. Potential integrity errors (wrong checksum) are not checked / enforced
    pub fn remove(&mut self, checksum: &Checksum, zk: bool) -> VmResult<()> {
        match zk {
            true => {
                self.circuits.remove(checksum);
            }
            false => {
                self.modules.remove(checksum);
            }
        };
        Ok(())
    }

    /// Looks up a module in the cache and creates a new module
    pub fn load(&mut self, checksum: &Checksum) -> VmResult<Option<CachedModule>> {
        match self.modules.get_mut(checksum) {
            Some(cached) => {
                cached.hits = cached.hits.saturating_add(1);
                Ok(Some(cached.module.clone()))
            }
            None => Ok(None),
        }
    }
    /// Looks up a module in the cache and creates a new module
    pub fn load_circuit(
        &mut self,
        checksum: &Checksum,
    ) -> VmResult<Option<zk_cosmwasm::PinnedCircuit>> {
        match self.circuits.get_mut(checksum) {
            Some(cached) => {
                cached.hits = cached.hits.saturating_add(1);
                Ok(Some(cached.circuit.clone()))
            }
            None => Ok(None),
        }
    }

    /// Returns true if and only if this cache has an entry identified by the given checksum
    pub fn has(&self, checksum: &Checksum, zk: bool) -> bool {
        match zk {
            true => self.circuits.contains_key(checksum),
            false => self.modules.contains_key(checksum),
        }
    }

    /// Returns the number of elements in the cache.
    pub fn len(&self) -> usize {
        self.circuits.len() + self.modules.len()
    }
    /// Returns cumulative size of all elements in the cache.
    ///
    /// This is based on the values provided with `store`. No actual
    /// memory size is measured here.
    pub fn size(&self) -> usize {
        // Sum module sizes: key (address) + module size estimate
        let module_size: usize = self
            .modules
            .iter()
            .map(|(key, module)| std::mem::size_of_val(key) + module.module.size_estimate)
            .sum();

        // Sum circuit sizes: key (address) + circuit actual size
        let circuit_size: usize = self
            .circuits
            .iter()
            .map(|(key, zk)| std::mem::size_of_val(key) + zk.circuit.actual_size_bytes())
            .sum();

        module_size + circuit_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        wasm_backend::{compile, make_compiling_engine, make_runtime_engine},
        Size,
    };
    use wasmer::{imports, Instance as WasmerInstance, Store};
    use wasmer_middlewares::metering::set_remaining_points;

    const TESTING_MEMORY_LIMIT: Option<Size> = Some(Size::mebi(16));
    const TESTING_GAS_LIMIT: u64 = 500_000;

    #[test]
    fn pinned_memory_cache_run() {
        let mut cache = PinnedMemoryCache::new();

        // Create module
        let wasm = wat::parse_str(
            r#"(module
            (type $t0 (func (param i32) (result i32)))
            (func $add_one (export "add_one") (type $t0) (param $p0 i32) (result i32)
                local.get $p0
                i32.const 1
                i32.add)
            )"#,
        )
        .unwrap();
        let checksum = Checksum::generate(&wasm);

        // Module does not exist
        let cache_entry = cache.load(&checksum).unwrap();
        assert!(cache_entry.is_none());

        // Compile module
        let engine = make_compiling_engine(TESTING_MEMORY_LIMIT);
        let original = compile(&engine, &wasm).unwrap();

        // Ensure original module can be executed
        {
            let mut store = Store::new(engine.clone());
            let instance = WasmerInstance::new(&mut store, &original, &imports! {}).unwrap();
            set_remaining_points(&mut store, &instance, TESTING_GAS_LIMIT);
            let add_one = instance.exports.get_function("add_one").unwrap();
            let result = add_one.call(&mut store, &[42.into()]).unwrap();
            assert_eq!(result[0].unwrap_i32(), 43);
        }

        // Store module
        let module = CachedModule {
            module: original,
            engine: make_runtime_engine(TESTING_MEMORY_LIMIT),
            size_estimate: 0,
        };
        cache.store(&checksum, module).unwrap();

        // Load module
        let cached = cache.load(&checksum).unwrap().unwrap();

        // Ensure cached module can be executed
        {
            let mut store = Store::new(engine);
            let instance = WasmerInstance::new(&mut store, &cached.module, &imports! {}).unwrap();
            set_remaining_points(&mut store, &instance, TESTING_GAS_LIMIT);
            let add_one = instance.exports.get_function("add_one").unwrap();
            let result = add_one.call(&mut store, &[42.into()]).unwrap();
            assert_eq!(result[0].unwrap_i32(), 43);
        }
    }

    #[test]
    fn has_works() {
        let mut cache = PinnedMemoryCache::new();

        // Create module
        let wasm = wat::parse_str(
            r#"(module
            (type $t0 (func (param i32) (result i32)))
            (func $add_one (export "add_one") (type $t0) (param $p0 i32) (result i32)
                local.get $p0
                i32.const 1
                i32.add)
            )"#,
        )
        .unwrap();
        let checksum = Checksum::generate(&wasm);

        assert!(!cache.has(&checksum, false));

        // Add
        let engine = make_compiling_engine(TESTING_MEMORY_LIMIT);
        let original = compile(&engine, &wasm).unwrap();
        let module = CachedModule {
            module: original,
            engine: make_runtime_engine(TESTING_MEMORY_LIMIT),
            size_estimate: 0,
        };
        cache.store(&checksum, module).unwrap();

        assert!(cache.has(&checksum, false));

        // Remove
        cache.remove(&checksum, false).unwrap();

        assert!(!cache.has(&checksum, false));
    }

    #[test]
    fn hit_metric_works() {
        let mut cache = PinnedMemoryCache::new();

        // Create module
        let wasm = wat::parse_str(
            r#"(module
            (type $t0 (func (param i32) (result i32)))
            (func $add_one (export "add_one") (type $t0) (param $p0 i32) (result i32)
                local.get $p0
                i32.const 1
                i32.add)
            )"#,
        )
        .unwrap();
        let checksum = Checksum::generate(&wasm);

        assert!(!cache.has(&checksum, false));

        // Add
        let engine = make_compiling_engine(TESTING_MEMORY_LIMIT);
        let original = compile(&engine, &wasm).unwrap();
        let module = CachedModule {
            module: original,
            engine: make_runtime_engine(TESTING_MEMORY_LIMIT),
            size_estimate: 0,
        };
        cache.store(&checksum, module).unwrap();

        let (_checksum, module) = cache
            .iter()
            .find(|(iter_checksum, _module)| **iter_checksum == checksum)
            .unwrap();

        assert_eq!(module.hits, 0);

        let _ = cache.load(&checksum).unwrap();
        let (_checksum, module) = cache
            .iter()
            .find(|(iter_checksum, _module)| **iter_checksum == checksum)
            .unwrap();

        assert_eq!(module.hits, 1);
    }

    #[test]
    fn len_works() {
        let mut cache = PinnedMemoryCache::new();

        // Create module
        let wasm = wat::parse_str(
            r#"(module
            (type $t0 (func (param i32) (result i32)))
            (func $add_one (export "add_one") (type $t0) (param $p0 i32) (result i32)
                local.get $p0
                i32.const 1
                i32.add)
            )"#,
        )
        .unwrap();
        let checksum = Checksum::generate(&wasm);

        assert_eq!(cache.len(), 0);

        // Add
        let engine = make_compiling_engine(TESTING_MEMORY_LIMIT);
        let original = compile(&engine, &wasm).unwrap();
        let module = CachedModule {
            module: original,
            engine: make_runtime_engine(TESTING_MEMORY_LIMIT),
            size_estimate: 0,
        };
        cache.store(&checksum, module).unwrap();

        assert_eq!(cache.len(), 1);

        // Remove
        cache.remove(&checksum, false).unwrap();

        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn size_works() {
        let mut cache = PinnedMemoryCache::new();

        // Create module
        let wasm1 = wat::parse_str(
            r#"(module
            (type $t0 (func (param i32) (result i32)))
            (func $add_one (export "add_one") (type $t0) (param $p0 i32) (result i32)
                local.get $p0
                i32.const 1
                i32.add)
            )"#,
        )
        .unwrap();
        let checksum1 = Checksum::generate(&wasm1);
        let wasm2 = wat::parse_str(
            r#"(module
            (type $t0 (func (param i32) (result i32)))
            (func $add_one (export "add_two") (type $t0) (param $p0 i32) (result i32)
                local.get $p0
                i32.const 2
                i32.add)
            )"#,
        )
        .unwrap();
        let checksum2 = Checksum::generate(&wasm2);

        assert_eq!(cache.size(), 0);

        // Add 1
        let engine1 = make_compiling_engine(TESTING_MEMORY_LIMIT);
        let module = CachedModule {
            module: compile(&engine1, &wasm1).unwrap(),
            engine: make_runtime_engine(TESTING_MEMORY_LIMIT),
            size_estimate: 500,
        };
        cache.store(&checksum1, module).unwrap();
        assert_eq!(cache.size(), 532);

        // Add 2
        let engine2 = make_compiling_engine(TESTING_MEMORY_LIMIT);
        let module = CachedModule {
            module: compile(&engine2, &wasm2).unwrap(),
            engine: make_runtime_engine(TESTING_MEMORY_LIMIT),
            size_estimate: 300,
        };
        cache.store(&checksum2, module).unwrap();
        assert_eq!(cache.size(), 532 + 332);

        // Remove 1
        cache.remove(&checksum1, false).unwrap();
        assert_eq!(cache.size(), 332);

        // Remove 2
        cache.remove(&checksum2, false).unwrap();
        assert_eq!(cache.size(), 0);
    }
}
