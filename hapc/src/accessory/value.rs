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
    NotDefined
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
    Tlv8(Vec<u8>),
    Data(Vec<u8>),
    NotDefined
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
    let v = match value_type {
            ValueType::Bool => {
                if !value.is_boolean() {
                    return Err(())
                }
                Value::Bool(value.as_bool().unwrap())
            },
            ValueType::UInt8 => {
                if !value.is_u64() {
                    return Err(())
                }
                Value::UInt8(value.as_u64().unwrap() as u8)
            },
            ValueType::UInt16 => {
                if !value.is_u64() {
                    return Err(())
                }
                Value::UInt16(value.as_u64().unwrap() as u16)
            },
            ValueType::UInt32 => {
                if !value.is_u64() {
                    return Err(())
                }
                Value::UInt32(value.as_u64().unwrap() as u32)
            },
            ValueType::UInt64 => {
                if !value.is_u64() {
                    return Err(())
                }
                Value::UInt64(value.as_u64().unwrap())
            },
            ValueType::Int => {
                if !value.is_i64() {
                    return Err(())
                }
                Value::Int(value.as_i64().unwrap() as i32)
            },
            ValueType::Float => {
                if !value.is_f64() {
                    return Err(())
                }
                Value::Float(value.as_f64().unwrap())
            },
            ValueType::String => {
                if !value.is_string() {
                    return Err(())
                }
                Value::String(value.as_str().unwrap().to_string())
            },
            ValueType::Tlv8 => {
                if !value.is_string() {
                    return Err(())
                }
                //todo: decode Base64
                Value::Tlv8(value.as_str().unwrap().as_bytes().to_vec())
            },
            ValueType::Data => {
                if !value.is_string() {
                    return Err(())
                }
                //todo: decode Base64
                Value::Data(value.as_str().unwrap().as_bytes().to_vec())
            },
            _ => Value::NotDefined,
        };

    Ok(v)
}