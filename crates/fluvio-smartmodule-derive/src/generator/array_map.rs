use quote::quote;
use proc_macro2::TokenStream;
use crate::SmartModuleFn;

pub fn generate_array_map_smartmodule(func: &SmartModuleFn, has_params: bool) -> TokenStream {
    let user_code = &func.func;
    let user_fn = &func.name;

    let params_parsing = if has_params {
        quote!(
            use std::convert::TryInto;

            let params = match smartmodule_input.params.try_into(){
                Ok(params) => params,
                Err(err) => return SmartModuleInternalError::ParsingExtraParams as i32,
            };

        )
    } else {
        quote!()
    };

    let function_call = if has_params {
        quote!(
            super:: #user_fn(&record, &params)
        )
    } else {
        quote!(
            super:: #user_fn(&record)
        )
    };

    quote! {

        #[allow(dead_code)]
        #user_code

        #[cfg(target_arch = "wasm32")]
        mod __system {
            #[no_mangle]
            #[allow(clippy::missing_safety_doc)]
            pub unsafe fn array_map(ptr: *mut u8, len: usize, version: i16) -> i32 {
                use fluvio_smartmodule::dataplane::smartmodule::{
                    SmartModuleInput, SmartModuleInternalError,
                    SmartModuleRuntimeError, SmartModuleKind, SmartModuleOutput,
                };
                use fluvio_smartmodule::dataplane::core::{Encoder, Decoder};
                use fluvio_smartmodule::dataplane::record::{Record, RecordData, RecordKey};

                // DECODING
                extern "C" {
                    fn copy_records(putr: i32, len: i32);
                }

                let input_data = Vec::from_raw_parts(ptr, len, len);
                let mut smartmodule_input = SmartModuleInput::default();
                if let Err(_err) = Decoder::decode(&mut smartmodule_input, &mut std::io::Cursor::new(input_data), version) {
                    return SmartModuleInternalError::DecodingBaseInput as i32;
                }

                let records_input = smartmodule_input.record_data;
                let mut records: Vec<Record> = vec![];
                if let Err(_err) = Decoder::decode(&mut records, &mut std::io::Cursor::new(records_input), version) {
                    return SmartModuleInternalError::DecodingRecords as i32;
                };

                #params_parsing


                // PROCESSING
                let mut output = SmartModuleOutput {
                    successes: Vec::with_capacity(records.len()),
                    error: None,
                };

                for record in records.into_iter() {
                    let result = #function_call;
                    match result {
                        Ok(output_records) => {
                            for (output_key, output_value) in output_records {
                                let key = RecordKey::from_option(output_key);
                                let new_record = Record::new_key_value(key, output_value);
                                output.successes.push(new_record);
                            }
                        }
                        Err(err) => {
                            let error = SmartModuleRuntimeError::new(
                                &record,
                                smartmodule_input.base_offset,
                                SmartModuleKind::ArrayMap,
                                err,
                            );
                            output.error = Some(error);
                            break;
                        }
                    }
                }

                // ENCODING
                let mut out = vec![];
                if let Err(_) = Encoder::encode(&mut output, &mut out, version) {
                    return SmartModuleInternalError::EncodingOutput as i32;
                }

                let out_len = out.len();
                let ptr = out.as_mut_ptr();
                std::mem::forget(out);
                copy_records(ptr as i32, out_len as i32);
                output.successes.len() as i32
            }
        }
    }
}
