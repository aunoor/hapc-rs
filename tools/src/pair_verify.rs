use std::str::FromStr;

use hapc;
use tokio::net::TcpStream;

#[allow(non_snake_case)]
#[allow(dead_code)]
pub(crate) fn pair_verify() {
    let rt = tokio::runtime::Runtime::new().unwrap();

    _ = rt.block_on(async {
        let host = "192.168.0.50";
        let port = "51826";
        let addr = format!("{}:{}", host, port);
        let stream = TcpStream::connect(addr).await;
        if stream.is_err() {
            println!("connection failed");
            return;
        }

        let iOSDevicePairingID = uuid::Uuid::from_str("1d1b8f74-b59f-4926-86bd-726e5636ed98").unwrap();
        let iOSDeviceLTSK =  hex::decode("7705F90F1A517319B4F782A8C647D7CC2CF8A78A47FD65093459D0E54C93D493").unwrap();
        let iOSDeviceLTPK = hex::decode("7863A15BC88CF5B80FF87AFC04A0A5ABE0B33816B8A75A41CEC6C17ADA64A723").unwrap();
        let AccessoryPairingID = "EF:71:C2:0E:33:A7".to_string();
        let AccessoryLTPK = hex::decode("56680E36069B339F2486CC1A2631ED7162AABD6E7DE5056811EDF413F9DBEE5E").unwrap();

        let hcb = hapc::Builder::new().set_user_agent("hapc".to_string()).
                                set_keys(iOSDeviceLTSK, iOSDeviceLTPK).
                                set_device_pairing_id(iOSDevicePairingID).
                                set_accessory_key(AccessoryPairingID, AccessoryLTPK).
                                finalize(stream.unwrap());

        let r = hcb.pair_verify().await;
        if r.is_err() {
            println!("pair verifing failed: {:?}", r.err());
            return;
        }

        println!("Pair verified succesfully");
    });
}