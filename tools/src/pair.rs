use std::str::FromStr;

use hapc;
use tokio::net::TcpStream;
use uuid;


pub(crate) fn pair() {
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

        let hcb = hapc::Builder::new().set_user_agent("hapc".to_string()).
                                                  set_keys(iOSDeviceLTSK, iOSDeviceLTPK).
                                                  set_device_pairing_id(iOSDevicePairingID).
                                                  finalize();

        let r = hcb.pair(stream.unwrap(), "123-00-321".to_string()).await;
        if r.is_err() {
            println!("pairing failed: {:?}", r.err());
            return;
        }

        println!("Paired succesfully");

        let pair_result = r.unwrap();

        let device_pairing_id_str = &pair_result.device_pairing_id;
        println!("iOSDevicePairingID: {}", device_pairing_id_str);
        let device_ltsk_str = hapc::utils::bytes_to_hex(&pair_result.device_ltsk);
        println!("iOSDeviceLTSK: {}", device_ltsk_str);
        let device_ltpk_str = hapc::utils::bytes_to_hex(&pair_result.device_ltpk);
        println!("iOSDeviceLTPK: {}", device_ltpk_str);

        let accessory_pairing_id_str = &pair_result.accessory_pairing_id;
        println!("AccessoryPairingID: {}", accessory_pairing_id_str);
        let accessory_ltpk_str = hapc::utils::bytes_to_hex(&pair_result.accessory_ltpk);
        println!("AccessoryLTPK: {}", accessory_ltpk_str);

    });

}