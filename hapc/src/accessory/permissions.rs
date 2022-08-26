use serde_json::Value;
use std::collections::HashSet;

#[derive(PartialEq, Eq, Hash, Debug)]
pub enum Permissions {
    PairedRead,
    PairedWrite,
    Events,
    AdditionalAuthorization,
    TimedWrite,
    Hidden,
    WriteResponse,
    Unknown
}

pub(crate) fn perms_to_set(perms: &Value) -> Result<HashSet<Permissions>, ()>{
    let mut permissions = HashSet::<Permissions>::new();

    let perms = perms.as_array().unwrap();
    for perm in perms.into_iter() {
        if !perm.is_string() {
            //element is not string
            return Err(());
        }
        let perm = perm.as_str().unwrap();
        permissions.insert(element_to_enum(perm));
    }

    Ok(permissions)
}

fn element_to_enum(value: &str) -> Permissions {
    let value = value.to_ascii_lowercase();
    match value.trim() {
        "pr" => Permissions::PairedRead,
        "pw" => Permissions::PairedWrite,
        "ev" => Permissions::Events,
        "aa" => Permissions::AdditionalAuthorization,
        "tw" => Permissions::TimedWrite,
        "hd" => Permissions::Hidden,
        "wr" => Permissions::WriteResponse,

        _ => Permissions::Unknown,
    }
}