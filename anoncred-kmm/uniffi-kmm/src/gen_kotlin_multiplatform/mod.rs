use std::borrow::Borrow;
use std::collections::HashMap;

use anyhow::{Context, Result};
use askama::Template;
use heck::{ToLowerCamelCase, ToShoutySnakeCase, ToUpperCamelCase};
use uniffi_bindgen::backend::{CodeOracle, CodeType, TypeIdentifier};
use uniffi_bindgen::interface::{CallbackInterface, Enum, Error, FfiType, Object, Record, Type};
use uniffi_bindgen::ComponentInterface;

use crate::{Config, KotlinMultiplatformBindings};

mod callback_interface;
mod compounds;
mod custom;
mod enum_;
mod error;
mod external;
mod miscellany;
mod object;
mod primitives;
mod record;

macro_rules! kotlin_template {
    ($KotlinTemplate:ident, $source_file:literal) => {
        #[derive(Template)]
        #[template(syntax = "kt", escape = "none", path = $source_file)]
        pub struct $KotlinTemplate<'ci> {
            config: Config,
            ci: &'ci ComponentInterface,
        }

        impl<'ci> $KotlinTemplate<'ci> {
            pub fn new(config: Config, ci: &'ci ComponentInterface) -> Self {
                Self { config, ci }
            }

            pub fn initialization_fns(&self) -> Vec<String> {
                self.ci
                    .iter_types()
                    .filter_map(|t| t.initialization_fn(&KotlinCodeOracle))
                    .collect()
            }
        }
    };
}

macro_rules! kotlin_callback_interface_template {
    ($KotlinTemplate:ident, $source_file:literal) => {
        #[derive(Template)]
        #[template(syntax = "kt", escape = "none", path = $source_file)]
        pub struct $KotlinTemplate<'cbi> {
            cbi: &'cbi CallbackInterface,
            type_name: String,
            foreign_callback_name: String,
            ffi_converter_name: String,
        }

        impl<'cbi> $KotlinTemplate<'cbi> {
            pub fn new(
                cbi: &'cbi CallbackInterface,
                type_name: String,
                foreign_callback_name: String,
                ffi_converter_name: String,
            ) -> Self {
                Self {
                    cbi,
                    type_name,
                    foreign_callback_name,
                    ffi_converter_name,
                }
            }
        }
    };
}

#[derive(Template)]
#[template(
syntax = "kt",
escape = "none",
path = "common/CustomTypeTemplate.kt.j2"
)]
pub struct CustomTypeTemplateCommon {
    config: Config,
    name: String,
    ffi_converter_name: String,
    builtin: Box<Type>,
}

impl CustomTypeTemplateCommon {
    pub fn new(
        config: Config,
        name: String,
        ffi_converter_name: String,
        builtin: Box<Type>,
    ) -> Self {
        Self {
            config,
            ffi_converter_name,
            name,
            builtin,
        }
    }
}

#[derive(Template)]
#[template(syntax = "kt", escape = "none", path = "common/EnumTemplate.kt.j2")]
pub struct EnumTemplateCommon<'e> {
    e: &'e Enum,
    type_name: String,
    contains_object_references: bool,
}

impl<'e> EnumTemplateCommon<'e> {
    pub fn new(e: &'e Enum, type_name: String, contains_object_references: bool) -> Self {
        Self {
            e,
            type_name,
            contains_object_references,
        }
    }
}

#[derive(Template)]
#[template(syntax = "kt", escape = "none", path = "common/ErrorTemplate.kt.j2")]
pub struct ErrorTemplateCommon<'e> {
    e: &'e Error,
    type_name: String,
    contains_object_references: bool,
}

impl<'e> ErrorTemplateCommon<'e> {
    pub fn new(e: &'e Error, type_name: String, contains_object_references: bool) -> Self {
        Self {
            e,
            type_name,
            contains_object_references,
        }
    }
}

#[derive(Template)]
#[template(syntax = "kt", escape = "none", path = "common/MapTemplate.kt.j2")]
pub struct MapTemplateCommon {
    key_type: Box<Type>,
    value_type: Box<Type>,
    ffi_converter_name: String,
}

impl MapTemplateCommon {
    pub fn new(key_type: Box<Type>, value_type: Box<Type>, ffi_converter_name: String) -> Self {
        Self {
            key_type,
            value_type,
            ffi_converter_name,
        }
    }
}

#[derive(Template)]
#[template(syntax = "kt", escape = "none", path = "common/ObjectTemplate.kt.j2")]
pub struct ObjectTemplateCommon<'e> {
    obj: &'e Object,
    type_name: String,
}

impl<'e> ObjectTemplateCommon<'e> {
    pub fn new(obj: &'e Object, type_name: String) -> Self {
        Self { obj, type_name }
    }
}

#[derive(Template)]
#[template(syntax = "kt", escape = "none", path = "common/OptionalTemplate.kt.j2")]
pub struct OptionalTemplateCommon {
    ffi_converter_name: String,
    inner_type_name: String,
    inner_type: Box<Type>,
}

impl OptionalTemplateCommon {
    pub fn new(ffi_converter_name: String, inner_type_name: String, inner_type: Box<Type>) -> Self {
        Self {
            ffi_converter_name,
            inner_type_name,
            inner_type,
        }
    }
}

#[derive(Template)]
#[template(syntax = "kt", escape = "none", path = "common/RecordTemplate.kt.j2")]
pub struct RecordTemplateCommon<'rec> {
    rec: &'rec Record,
    type_name: String,
    contains_object_references: bool,
}

impl<'rec> RecordTemplateCommon<'rec> {
    pub fn new(rec: &'rec Record, type_name: String, contains_object_references: bool) -> Self {
        Self {
            rec,
            type_name,
            contains_object_references,
        }
    }
}

#[derive(Template)]
#[template(syntax = "kt", escape = "none", path = "common/SequenceTemplate.kt.j2")]
pub struct SequenceTemplateCommon {
    ffi_converter_name: String,
    inner_type_name: String,
    inner_type: Box<Type>,
}

impl SequenceTemplateCommon {
    pub fn new(ffi_converter_name: String, inner_type_name: String, inner_type: Box<Type>) -> Self {
        Self {
            ffi_converter_name,
            inner_type_name,
            inner_type,
        }
    }
}

#[derive(Template)]
#[template(
syntax = "c",
escape = "none",
path = "headers/BridgingHeaderTemplate.h.j2"
)]
pub struct BridgingHeader<'ci> {
    _config: Config,
    ci: &'ci ComponentInterface,
}

impl<'ci> BridgingHeader<'ci> {
    pub fn new(config: Config, ci: &'ci ComponentInterface) -> Self {
        Self {
            _config: config,
            ci,
        }
    }
}

macro_rules! render_kotlin_template {
    ($template:ident, $file_name:literal, $map:ident) => {
        let file_name = $file_name.to_string();
        let context = format!("failed to render kotlin binding {}", stringify!($T));
        $map.insert(file_name, $template.render().context(context).unwrap());
    };

    ($template:ident, $file_name:ident, $map:ident) => {
        let file_name = $file_name;
        let context = format!("failed to render kotlin binding {}", stringify!($T));
        $map.insert(file_name, $template.render().context(context).unwrap());
    };
}

kotlin_template!(
    TopLevelFunctionsTemplateCommon,
    "common/TopLevelFunctionsTemplate.kt.j2"
);
kotlin_template!(UniFFILibTemplateCommon, "common/UniFFILibTemplate.kt.j2");
kotlin_callback_interface_template!(
    CallbackInterfaceTemplateCommon,
    "common/CallbackInterfaceTemplate.kt.j2"
);

kotlin_template!(RustBufferTemplateJvm, "jvm/RustBufferTemplate.kt.j2");
kotlin_template!(UniFFILibTemplateJvm, "jvm/UniFFILibTemplate.kt.j2");
kotlin_callback_interface_template!(
    CallbackInterfaceTemplateJvm,
    "jvm/CallbackInterfaceTemplate.kt.j2"
);

kotlin_template!(RustBufferTemplateAndroid, "android/RustBufferTemplate.kt.j2");
kotlin_template!(UniFFILibTemplateAndroid, "android/UniFFILibTemplate.kt.j2");
kotlin_callback_interface_template!(
    CallbackInterfaceTemplateAndroid,
    "android/CallbackInterfaceTemplate.kt.j2"
);

kotlin_template!(
    ForeignBytesTemplateNative,
    "native/ForeignBytesTemplate.kt.j2"
);
kotlin_template!(RustBufferTemplateNative, "native/RustBufferTemplate.kt.j2");
kotlin_template!(
    RustCallStatusTemplateNative,
    "native/RustCallStatusTemplate.kt.j2"
);
kotlin_template!(UniFFILibTemplateNative, "native/UniFFILibTemplate.kt.j2");
kotlin_callback_interface_template!(
    CallbackInterfaceTemplateNative,
    "native/CallbackInterfaceTemplate.kt.j2"
);

pub fn generate_bindings(
    config: &Config,
    ci: &ComponentInterface,
) -> Result<KotlinMultiplatformBindings> {
    let mut common_wrapper: HashMap<String, String> = HashMap::new();
    let top_level_functions_template_common =
        TopLevelFunctionsTemplateCommon::new(config.clone(), ci);
    render_kotlin_template!(
        top_level_functions_template_common,
        "TopLevelFunctions.kt",
        common_wrapper
    );
    let uniffilib_template_common = UniFFILibTemplateCommon::new(config.clone(), ci);
    render_kotlin_template!(uniffilib_template_common, "UniFFILib.kt", common_wrapper);
    for type_ in ci.iter_types() {
        let canonical_type_name = filters::canonical_name(type_).unwrap();
        let ffi_converter_name = filters::ffi_converter_name(type_).unwrap();
        let contains_object_references = ci.item_contains_object_references(type_);
        match type_ {
            Type::CallbackInterface(name) => {
                let cbi: &CallbackInterface = ci.get_callback_interface_definition(name).unwrap();
                let type_name = filters::type_name(cbi).unwrap();
                let template = CallbackInterfaceTemplateCommon::new(
                    cbi,
                    type_name.clone(),
                    format!("ForeignCallback{}", canonical_type_name),
                    ffi_converter_name,
                );
                let file_name = format!("{}.kt", type_name);
                render_kotlin_template!(template, file_name, common_wrapper);
            }

            Type::Custom { name, builtin } => {
                let template = CustomTypeTemplateCommon::new(
                    config.clone(),
                    name.clone(),
                    ffi_converter_name,
                    builtin.clone(),
                );
                let file_name = format!("{}.kt", name);
                render_kotlin_template!(template, file_name, common_wrapper);
            }

            Type::Enum(name) => {
                let e: &Enum = ci.get_enum_definition(name).unwrap();
                let type_name = filters::type_name(type_).unwrap();
                let template =
                    EnumTemplateCommon::new(e, type_name.clone(), contains_object_references);
                let file_name = format!("{}.kt", type_name);
                render_kotlin_template!(template, file_name, common_wrapper);
            }

            Type::Error(name) => {
                let e: &Error = ci.get_error_definition(name).unwrap();
                let type_name = filters::type_name(type_).unwrap();
                let template =
                    ErrorTemplateCommon::new(e, type_name.clone(), contains_object_references);
                let file_name = format!("{}.kt", type_name);
                render_kotlin_template!(template, file_name, common_wrapper);
            }

            Type::External { name: _, crate_name: _ } => {
                // TODO this need specific imports in some classes.
            }

            Type::Map(key_type, value_type) => {
                let template = MapTemplateCommon::new(
                    key_type.clone(),
                    value_type.clone(),
                    ffi_converter_name.clone(),
                );
                let file_name = format!("{}.kt", ffi_converter_name);
                render_kotlin_template!(template, file_name, common_wrapper);
            }

            Type::Object(name) => {
                let obj: &Object = ci.get_object_definition(name).unwrap();
                let type_name = filters::type_name(type_).unwrap();
                let template = ObjectTemplateCommon::new(
                    obj, type_name.clone(),
                );
                let file_name = format!("{}.kt", type_name);
                render_kotlin_template!(template, file_name, common_wrapper);
            }

            Type::Optional(inner_type) => {
                let inner_type_name = filters::type_name(inner_type).unwrap();
                let template = OptionalTemplateCommon::new(
                    ffi_converter_name.clone(), inner_type_name, inner_type.clone(),
                );
                let file_name = format!("{}.kt", ffi_converter_name);
                render_kotlin_template!(template, file_name, common_wrapper);
            }

            Type::Record(name) => {
                let rec: &Record = ci.get_record_definition(name).unwrap();
                let type_name = filters::type_name(type_).unwrap();
                let template = RecordTemplateCommon::new(
                    rec, type_name.clone(), contains_object_references,
                );
                let file_name = format!("{}.kt", type_name);
                render_kotlin_template!(template, file_name, common_wrapper);
            }

            Type::Sequence(inner_type) => {
                let inner_type_name = filters::type_name(inner_type).unwrap();
                let template = SequenceTemplateCommon::new(
                    ffi_converter_name.clone(), inner_type_name, inner_type.clone(),
                );
                let file_name = format!("{}.kt", ffi_converter_name);
                render_kotlin_template!(template, file_name, common_wrapper);
            }
            _ => {}
        }
    }

    let mut jvm_wrapper: HashMap<String, String> = HashMap::new();
    let rust_buffer_template_jvm = RustBufferTemplateJvm::new(config.clone(), ci);
    render_kotlin_template!(rust_buffer_template_jvm, "RustBuffer.kt", jvm_wrapper);
    let uniffilib_template_jvm = UniFFILibTemplateJvm::new(config.clone(), ci);
    render_kotlin_template!(uniffilib_template_jvm, "UniFFILib.kt", jvm_wrapper);
    for type_ in ci.iter_types() {
        let canonical_type_name = filters::canonical_name(type_).unwrap();
        let ffi_converter_name = filters::ffi_converter_name(type_).unwrap();
        match type_ {
            Type::CallbackInterface(name) => {
                let cbi: &CallbackInterface = ci.get_callback_interface_definition(name).unwrap();
                let type_name = filters::type_name(cbi).unwrap();
                let template = CallbackInterfaceTemplateJvm::new(
                    cbi,
                    type_name.clone(),
                    format!("ForeignCallback{}", canonical_type_name),
                    ffi_converter_name,
                );
                let file_name = format!("{}.kt", type_name);
                render_kotlin_template!(template, file_name, jvm_wrapper);
            }

            _ => {}
        }
    }

    let mut android_wrapper: HashMap<String, String> = HashMap::new();
    let rust_buffer_template_android = RustBufferTemplateJvm::new(config.clone(), ci);
    render_kotlin_template!(rust_buffer_template_android, "RustBuffer.kt", android_wrapper);
    let uniffilib_template_android = UniFFILibTemplateAndroid::new(config.clone(), ci);
    render_kotlin_template!(uniffilib_template_android, "UniFFILib.kt", android_wrapper);
    for type_ in ci.iter_types() {
        let canonical_type_name = filters::canonical_name(type_).unwrap();
        let ffi_converter_name = filters::ffi_converter_name(type_).unwrap();
        match type_ {
            Type::CallbackInterface(name) => {
                let cbi: &CallbackInterface = ci.get_callback_interface_definition(name).unwrap();
                let type_name = filters::type_name(cbi).unwrap();
                let template = CallbackInterfaceTemplateAndroid::new(
                    cbi,
                    type_name.clone(),
                    format!("ForeignCallback{}", canonical_type_name),
                    ffi_converter_name,
                );
                let file_name = format!("{}.kt", type_name);
                render_kotlin_template!(template, file_name, android_wrapper);
            }

            _ => {}
        }
    }

    let mut native_wrapper: HashMap<String, String> = HashMap::new();
    let foreign_bytes_template_native = ForeignBytesTemplateNative::new(config.clone(), ci);
    render_kotlin_template!(
        foreign_bytes_template_native,
        "ForeignBytes.kt",
        native_wrapper
    );
    let rust_buffer_template_native = RustBufferTemplateNative::new(config.clone(), ci);
    render_kotlin_template!(rust_buffer_template_native, "RustBuffer.kt", native_wrapper);
    let rust_call_status_template_native = RustCallStatusTemplateNative::new(config.clone(), ci);
    render_kotlin_template!(
        rust_call_status_template_native,
        "RustCallStatus.kt",
        native_wrapper
    );
    let uniffilib_template_native = UniFFILibTemplateNative::new(config.clone(), ci);
    render_kotlin_template!(uniffilib_template_native, "UniFFILib.kt", native_wrapper);
    for type_ in ci.iter_types() {
        let canonical_type_name = filters::canonical_name(type_).unwrap();
        let ffi_converter_name = filters::ffi_converter_name(type_).unwrap();
        match type_ {
            Type::CallbackInterface(name) => {
                let cbi: &CallbackInterface = ci.get_callback_interface_definition(name).unwrap();
                let type_name = filters::type_name(cbi).unwrap();
                let template = CallbackInterfaceTemplateNative::new(
                    cbi,
                    type_name.clone(),
                    format!("ForeignCallback{}", canonical_type_name),
                    ffi_converter_name,
                );
                let file_name = format!("{}.kt", type_name);
                render_kotlin_template!(template, file_name, native_wrapper);
            }

            _ => {}
        }
    }

    let header = BridgingHeader::new(config.clone(), ci)
        .render()
        .context("failed to render Kotlin/Native bridging header")?;

    Ok(KotlinMultiplatformBindings {
        common: common_wrapper,
        jvm: jvm_wrapper,
        android: android_wrapper,
        native: native_wrapper,
        header,
    })
}

#[derive(Clone)]
pub struct KotlinCodeOracle;

impl KotlinCodeOracle {
    // Map `Type` instances to a `Box<dyn CodeType>` for that type.
    //
    // There is a companion match in `templates/Types.kt` which performs a similar function for the
    // template code.
    //
    //   - When adding additional types here, make sure to also add a match arm to the `Types.kt` template.
    //   - To keep things managable, let's try to limit ourselves to these 2 mega-matches
    fn create_code_type(&self, type_: TypeIdentifier) -> Box<dyn CodeType> {
        match type_ {
            Type::UInt8 => Box::new(primitives::UInt8CodeType),
            Type::Int8 => Box::new(primitives::Int8CodeType),
            Type::UInt16 => Box::new(primitives::UInt16CodeType),
            Type::Int16 => Box::new(primitives::Int16CodeType),
            Type::UInt32 => Box::new(primitives::UInt32CodeType),
            Type::Int32 => Box::new(primitives::Int32CodeType),
            Type::UInt64 => Box::new(primitives::UInt64CodeType),
            Type::Int64 => Box::new(primitives::Int64CodeType),
            Type::Float32 => Box::new(primitives::Float32CodeType),
            Type::Float64 => Box::new(primitives::Float64CodeType),
            Type::Boolean => Box::new(primitives::BooleanCodeType),
            Type::String => Box::new(primitives::StringCodeType),

            Type::Timestamp => Box::new(miscellany::TimestampCodeType),
            Type::Duration => Box::new(miscellany::DurationCodeType),

            Type::Enum(id) => Box::new(enum_::EnumCodeType::new(id)),
            Type::Object(id) => Box::new(object::ObjectCodeType::new(id)),
            Type::Record(id) => Box::new(record::RecordCodeType::new(id)),
            Type::Error(id) => Box::new(error::ErrorCodeType::new(id)),
            Type::CallbackInterface(id) => {
                Box::new(callback_interface::CallbackInterfaceCodeType::new(id))
            }
            Type::Optional(inner) => Box::new(compounds::OptionalCodeType::new(*inner)),
            Type::Sequence(inner) => Box::new(compounds::SequenceCodeType::new(*inner)),
            Type::Map(key, value) => Box::new(compounds::MapCodeType::new(*key, *value)),
            Type::External { name, .. } => Box::new(external::ExternalCodeType::new(name)),
            Type::Custom { name, .. } => Box::new(custom::CustomCodeType::new(name)),
            Type::Unresolved { name } => {
                unreachable!("Type `{name}` must be resolved before calling create_code_type")
            }
        }
    }

    fn ffi_header_type_label(&self, ffi_type: &FfiType) -> String {
        match ffi_type {
            FfiType::Int8 => "int8_t".into(),
            FfiType::UInt8 => "uint8_t".into(),
            FfiType::Int16 => "int16_t".into(),
            FfiType::UInt16 => "uint16_t".into(),
            FfiType::Int32 => "int32_t".into(),
            FfiType::UInt32 => "uint32_t".into(),
            FfiType::Int64 => "int64_t".into(),
            FfiType::UInt64 => "uint64_t".into(),
            FfiType::Float32 => "float".into(),
            FfiType::Float64 => "double".into(),
            FfiType::RustArcPtr(_) => "void*_Nonnull".into(),
            FfiType::RustBuffer(_) => "RustBuffer".into(),
            FfiType::ForeignBytes => "ForeignBytes".into(),
            FfiType::ForeignCallback => "ForeignCallback  _Nonnull".to_string(),
        }
    }
}

impl CodeOracle for KotlinCodeOracle {
    fn find(&self, type_: &TypeIdentifier) -> Box<dyn CodeType> {
        self.create_code_type(type_.clone())
    }

    /// Get the idiomatic Kotlin rendering of a class name (for enums, records, errors, etc).
    fn class_name(&self, nm: &str) -> String {
        nm.to_string().to_upper_camel_case()
    }

    /// Get the idiomatic Kotlin rendering of a function name.
    fn fn_name(&self, nm: &str) -> String {
        format!("`{}`", nm.to_string().to_lower_camel_case())
    }

    /// Get the idiomatic Kotlin rendering of a variable name.
    fn var_name(&self, nm: &str) -> String {
        format!("`{}`", nm.to_string().to_lower_camel_case())
    }

    /// Get the idiomatic Kotlin rendering of an individual enum variant.
    fn enum_variant_name(&self, nm: &str) -> String {
        nm.to_string().to_shouty_snake_case()
    }

    /// Get the idiomatic Kotlin rendering of an exception name
    ///
    /// This replaces "Error" at the end of the name with "Exception".  Rust code typically uses
    /// "Error" for any type of error but in the Java world, "Error" means a non-recoverable error
    /// and is distinguished from an "Exception".
    fn error_name(&self, nm: &str) -> String {
        // errors are a class in kotlin.
        let name = self.class_name(nm);
        match name.strip_suffix("Error") {
            None => name,
            Some(stripped) => format!("{stripped}Exception"),
        }
    }

    fn ffi_type_label(&self, ffi_type: &FfiType) -> String {
        match ffi_type {
            FfiType::Int8 => "Byte".to_string(),
            FfiType::UInt8 => "UByte".to_string(),
            FfiType::Int16 => "Short".to_string(),
            FfiType::UInt16 => "UShort".to_string(),
            FfiType::Int32 => "Int".to_string(),
            FfiType::UInt32 => "UInt".to_string(),
            FfiType::Int64 => "Long".to_string(),
            FfiType::UInt64 => "ULong".to_string(),
            FfiType::Float32 => "Float".to_string(),
            FfiType::Float64 => "Double".to_string(),
            FfiType::RustArcPtr(_) => "Pointer".to_string(),
            FfiType::RustBuffer(_) => "RustBuffer".to_string(),
            FfiType::ForeignBytes => "ForeignBytes".to_string(),
            FfiType::ForeignCallback => "ForeignCallback".to_string(),
        }
    }
}

pub mod filters {
    use uniffi_bindgen::backend::Literal;

    use super::*;

    fn oracle() -> &'static KotlinCodeOracle {
        &KotlinCodeOracle
    }

    pub fn type_name(codetype: &impl CodeType) -> Result<String, askama::Error> {
        Ok(codetype.type_label(oracle()))
    }

    pub fn canonical_name(codetype: &impl CodeType) -> Result<String, askama::Error> {
        Ok(codetype.canonical_name(oracle()))
    }

    pub fn ffi_converter_name(codetype: &impl CodeType) -> Result<String, askama::Error> {
        Ok(codetype.ffi_converter_name(oracle()))
    }

    pub fn lower_fn(codetype: &impl CodeType) -> Result<String, askama::Error> {
        Ok(format!("{}.lower", codetype.ffi_converter_name(oracle())))
    }

    pub fn allocation_size_fn(codetype: &impl CodeType) -> Result<String, askama::Error> {
        Ok(format!(
            "{}.allocationSize",
            codetype.ffi_converter_name(oracle())
        ))
    }

    pub fn write_fn(codetype: &impl CodeType) -> Result<String, askama::Error> {
        Ok(format!("{}.write", codetype.ffi_converter_name(oracle())))
    }

    pub fn lift_fn(codetype: &impl CodeType) -> Result<String, askama::Error> {
        Ok(format!("{}.lift", codetype.ffi_converter_name(oracle())))
    }

    pub fn read_fn(codetype: &impl CodeType) -> Result<String, askama::Error> {
        Ok(format!("{}.read", codetype.ffi_converter_name(oracle())))
    }

    pub fn render_literal(
        literal: &Literal,
        codetype: &impl CodeType,
    ) -> Result<String, askama::Error> {
        Ok(codetype.literal(oracle(), literal))
    }

    /// Get the Kotlin syntax for representing a given low-level `FfiType`.
    pub fn ffi_type_name(type_: &FfiType) -> Result<String, askama::Error> {
        Ok(oracle().ffi_type_label(type_))
    }

    pub fn ffi_header_type_name(type_: &FfiType) -> Result<String, askama::Error> {
        Ok(oracle().ffi_header_type_label(type_))
    }

    /// Get the idiomatic Kotlin rendering of a class name (for enums, records, errors, etc).
    pub fn class_name(nm: &str) -> Result<String, askama::Error> {
        Ok(oracle().class_name(nm))
    }

    /// Get the idiomatic Kotlin rendering of a function name.
    pub fn fn_name(nm: &str) -> Result<String, askama::Error> {
        Ok(oracle().fn_name(nm))
    }

    /// Get the idiomatic Kotlin rendering of a variable name.
    pub fn var_name(nm: &str) -> Result<String, askama::Error> {
        Ok(oracle().var_name(nm))
    }

    /// Get the idiomatic Kotlin rendering of an individual enum variant.
    pub fn enum_variant(nm: &str) -> Result<String, askama::Error> {
        Ok(oracle().enum_variant_name(nm))
    }

    /// Get the idiomatic Kotlin rendering of an exception name, replacing
    /// `Error` with `Exception`.
    pub fn exception_name(nm: &str) -> Result<String, askama::Error> {
        Ok(oracle().error_name(nm))
    }

    /// Remove the "`" chars we put around function/variable names
    ///
    /// These are used to avoid name clashes with kotlin identifiers, but sometimes you want to
    /// render the name unquoted.  One example is the message property for errors where we want to
    /// display the name for the user.
    pub fn unquote(nm: &str) -> Result<String, askama::Error> {
        Ok(nm.trim_matches('`').to_string())
    }
}
