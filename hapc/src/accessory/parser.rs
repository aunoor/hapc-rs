use serde_json::{Value};

#[derive(Clone)]
struct Accessory {
    iid: i16,
}


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

    let aid_key = "aid";
    let services_key = "services";

    if !accessory.contains_key(aid_key) {
        //aid not found
        return Err(());
    }

    let aid = &accessory[aid_key];
    if !aid.is_number() {
        //iid is not number
        return Err(());
    }
    let aid = aid.as_u64().unwrap() as u16;

    if !accessory.contains_key(services_key) {
        //services not found
        return Err(());
    }
    let services = &accessory[services_key];
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

    let iid_key = "iid";
    let type_key = "type";

    if !service.contains_key(iid_key) {
        //iid not found
        return Err(());
    }
    let iid = &service[iid_key];
    if !iid.is_number() {
        //iid is not number
        return Err(());
    }
    let iid = iid.as_u64().unwrap() as u16;

    if !service.contains_key(type_key) {
        //type not found
        return Err(());
    }
    let type_value = &service[type_key];
    if !type_value.is_string() {
        //type is not string
        return Err(());
    }






    Ok(())
}

