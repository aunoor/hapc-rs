use hapc;
use tokio::net::TcpStream;


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

        let r = hapc::HAPClient::pair2(stream.unwrap(), "123-00-321".to_string(), "hapc".to_string()).await;
        if r.is_err() {
            println!("pairing failed");
        }

        println!("Paired succesfully");

        let pair_result = r.unwrap();

        let device_pairing_id_str = hapc::utils::bytes_to_hex(&pair_result.device_pairing_id);
        println!("iOSDevicePairingID: {}", device_pairing_id_str);
        let device_ltsk_str = hapc::utils::bytes_to_hex(&pair_result.device_ltsk);
        println!("iOSDeviceLTSK: {}", device_ltsk_str);
        let device_ltpk_str = hapc::utils::bytes_to_hex(&pair_result.device_ltpk);
        println!("iOSDeviceLTPK: {}", device_ltpk_str);

        let accessory_ltpk_str = hapc::utils::bytes_to_hex(&pair_result.accessory_ltpk);
        println!("AccessoryLTPK: {}", accessory_ltpk_str);
        let accessory_pairing_id_str = hapc::utils::bytes_to_hex(&pair_result.accessory_pairing_id);
        println!("AccessoryPairingID: {}", accessory_pairing_id_str);

    });

}