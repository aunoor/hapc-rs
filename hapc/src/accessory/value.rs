#[derive(Clone, Debug)]
pub enum ValueType {
    Bool,
    UInt8,
    UInt16,
    UInt32,
    UInt64,
    Int,
    Float,
    String,
    Tlv8,
    Data,
}

#[derive(Clone, Debug)]
pub enum Value {
    Bool(bool),
    UInt8(u8),
    UInt16(u16),
    UInt32(u32),
    UInt64(u64),
    Int(i32),
    Float(f64),
    String(String),
    Tlv8(String),
    Data(Vec<u8>),
}

pub(crate) fn format_to_value_type(format: &str) -> Result<ValueType, ()> {
    let format = format.to_ascii_lowercase();
    match format.trim() {
        "bool" => Ok(ValueType::Bool),
        "uint8" => Ok(ValueType::UInt8),
        "uint16" => Ok(ValueType::UInt16),
        "uint32" => Ok(ValueType::UInt32),
        "uint64" => Ok(ValueType::UInt64),
        "int" => Ok(ValueType::Int),
        "float" => Ok(ValueType::Float),
        "string" => Ok(ValueType::String),
        "tlv8" => Ok(ValueType::Tlv8),
        "data" => Ok(ValueType::Data),
        _ => Err(()),
    }
}

pub(crate) fn value_to_value(value: &serde_json::Value, value_type: ValueType) -> Result<Value, ()> {
    Err(())
}