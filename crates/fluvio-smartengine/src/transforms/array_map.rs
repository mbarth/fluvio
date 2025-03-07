use std::convert::TryFrom;
use std::fmt::Debug;

use anyhow::Result;
use wasmtime::{AsContextMut, Trap, TypedFunc};

use dataplane::smartmodule::{
    SmartModuleInput, SmartModuleOutput, SmartModuleInternalError, SmartModuleExtraParams,
};

use crate::{
    WasmSlice, {SmartModuleWithEngine, SmartModuleContext, SmartModuleInstance},
    error::Error,
};

const ARRAY_MAP_FN_NAME: &str = "array_map";
type OldArrayMapFn = TypedFunc<(i32, i32), i32>;
type ArrayMapFn = TypedFunc<(i32, i32, u32), i32>;

#[derive(Debug)]
pub struct SmartModuleArrayMap {
    base: SmartModuleContext,
    array_map_fn: ArrayMapFnKind,
}

enum ArrayMapFnKind {
    Old(OldArrayMapFn),
    New(ArrayMapFn),
}

impl Debug for ArrayMapFnKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Old(..) => write!(f, "OldArrayMapFn"),
            Self::New(..) => write!(f, "ArrayMapFn"),
        }
    }
}

impl ArrayMapFnKind {
    fn call(&self, store: impl AsContextMut, slice: WasmSlice) -> Result<i32, Trap> {
        match self {
            Self::Old(array_map_fn) => array_map_fn.call(store, (slice.0, slice.1)),
            Self::New(array_map_fn) => array_map_fn.call(store, slice),
        }
    }
}

impl SmartModuleArrayMap {
    pub fn new(
        module: &SmartModuleWithEngine,
        params: SmartModuleExtraParams,
        version: i16,
    ) -> Result<Self, Error> {
        let mut base = SmartModuleContext::new(module, params, version)?;
        let map_fn = if let Ok(array_map_fn) = base
            .instance
            .get_typed_func(&mut base.store, ARRAY_MAP_FN_NAME)
        {
            ArrayMapFnKind::New(array_map_fn)
        } else {
            let array_map_fn = base
                .instance
                .get_typed_func(&mut base.store, ARRAY_MAP_FN_NAME)
                .map_err(|err| Error::NotNamedExport(ARRAY_MAP_FN_NAME, err))?;
            ArrayMapFnKind::Old(array_map_fn)
        };

        Ok(Self {
            base,
            array_map_fn: map_fn,
        })
    }
}

impl SmartModuleInstance for SmartModuleArrayMap {
    fn process(&mut self, input: SmartModuleInput) -> Result<SmartModuleOutput> {
        let slice = self.base.write_input(&input)?;
        let map_output = self.array_map_fn.call(&mut self.base.store, slice)?;

        if map_output < 0 {
            let internal_error = SmartModuleInternalError::try_from(map_output)
                .unwrap_or(SmartModuleInternalError::UnknownError);
            return Err(internal_error.into());
        }

        let output: SmartModuleOutput = self.base.read_output()?;
        Ok(output)
    }

    fn params(&self) -> SmartModuleExtraParams {
        self.base.get_params().clone()
    }

    fn mut_ctx(&mut self) -> &mut SmartModuleContext {
        &mut self.base
    }
}
