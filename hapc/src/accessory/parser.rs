use serde_json::{Value};
use super::{service_type::{string_to_service_type}, permissions::perms_to_set, value::{format_to_value_type, value_to_value}};

#[derive(Clone)]
struct Accessory {
    iid: u16,
}


struct Characteristic {
    iid: u16,
}

const AID_KEY: &str = "aid";
const CHARACTERISTICS_KEY: &str = "characteristics";
const IID_KEY: &str = "iid";
const TYPE_KEY: &str = "type";
const SERVICES_KEY: &str = "services";
const PERMS_KEY: &str = "perms";
const FORMAT_KEY: &str = "format";
const VALUE_KEY: &str = "value";


pub fn parse_accessory_json(data: String) -> Result<(), ()> {

    let parse_result: serde_json::Result<Value> = serde_json::from_slice(data.as_bytes());
    if parse_result.is_err() {
        //parse error
        return Err(());
    }

    let root_value = parse_result.unwrap();
    let accessories = &root_value["accessories"];
    if accessories.is_null() {
        //accessories object not found
        return Err(());
    }

    if !accessories.is_array() {
        //accessories object is not array
        return Err(());
    }

    for accessory in accessories.as_array().unwrap().into_iter() {
        if !accessory.is_object() {
            //accessory is not object
            return Err(());
        }
        let r = parse_accessory_object(accessory);
        if r.is_err() {
            return Err(());
        }
    }



    Ok(())
}

fn parse_accessory_object(accessory: &Value) -> Result<(), ()> {
    let accessory = accessory.as_object().unwrap();


    if !accessory.contains_key(AID_KEY) {
        //aid not found
        return Err(());
    }

    let aid = &accessory[AID_KEY];
    if !aid.is_number() {
        //iid is not number
        return Err(());
    }
    let aid = aid.as_u64().unwrap() as u16;

    if !accessory.contains_key(SERVICES_KEY) {
        //services not found
        return Err(());
    }
    let services = &accessory[SERVICES_KEY];
    if !services.is_array() {
        //services is not array
        return Err(());
    }

    for service in services.as_array().unwrap().into_iter() {
        if !service.is_object() {
            return Err(());
        }
        let r = parse_service_object(service);
        if r.is_err() {
            return Err(());
        }
    }


    Ok(())
}

fn parse_service_object(service: &Value) -> Result<(), ()> {
    let service = service.as_object().unwrap();


    if !service.contains_key(IID_KEY) {
        //iid not found
        return Err(());
    }
    let iid = &service[IID_KEY];
    if !iid.is_number() {
        //iid is not number
        return Err(());
    }
    let iid = iid.as_u64().unwrap() as u16;

    if !service.contains_key(TYPE_KEY) {
        //type not found
        return Err(());
    }
    let type_value = &service[TYPE_KEY];
    if !type_value.is_string() {
        //type is not string
        return Err(());
    }
    let type_value = type_value.as_str().unwrap();

    let service_type = string_to_service_type(type_value.to_string());

    if !service.contains_key(CHARACTERISTICS_KEY) {
        //characteristics not found
        return Err(());
    }
    let characteristics = &service[CHARACTERISTICS_KEY];
    if !characteristics.is_array() {
        //characteristics is not array
        return Err(());
    }

    for characteristic in characteristics.as_array().unwrap().into_iter() {
        if !characteristic.is_object() {
            return Err(())
        }
        let r = parse_characteristic_object(characteristic);
        if r.is_err() {
            return Err(())
        }
    }

    Ok(())
}

fn parse_characteristic_object(characteristic: &Value) -> Result<(),()> {
    let characteristic = characteristic.as_object().unwrap();

    if !characteristic.contains_key(IID_KEY) {
        //iid not found
        return Err(());
    }
    let iid = &characteristic[IID_KEY];
    if !iid.is_number() {
        //iid is not number
        return Err(());
    }
    let iid = iid.as_u64().unwrap() as u16;

    if !characteristic.contains_key(TYPE_KEY) {
        //type not found
        return Err(());
    }
    let type_value = &characteristic[TYPE_KEY];
    if !type_value.is_string() {
        //type is not string
        return Err(());
    }
    let type_value = type_value.as_str().unwrap();
    //todo str2chartype

    if !characteristic.contains_key(PERMS_KEY) {
        //no perms found
        return Err(());
    }
    let perms = &characteristic[PERMS_KEY];
    if !perms.is_array() {
        //perms is not array
        return Err(());
    }
    let perms = perms_to_set(perms);
    if perms.is_err() {
        //error while parsing parms element
        return Err(());
    }
    let perms = perms.ok().unwrap();

    if !characteristic.contains_key(FORMAT_KEY) {
        //characteristic don't contain format
        return Err(());
    }
    let format = &characteristic[FORMAT_KEY];
    if !format.is_string() {
        //format is not string
        return Err(())
    }
    let value_type = format_to_value_type(format.as_str().unwrap());
    if value_type.is_err() {
        //can't convert format to ValueType
        return Err(())
    }
    let value_type = value_type.unwrap();

    if !characteristic.contains_key(VALUE_KEY) {
        //characteristic don't contain value
        return Err(());
    }

    let value = value_to_value(&characteristic[VALUE_KEY], value_type);

    //Characteristic

    Ok(())
}