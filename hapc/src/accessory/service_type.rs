pub enum ServiceType{
    AccessoryInformation,
    AirPurifier,
    AirQualitySensor,
    AudioStreamManagement,
    Battery,
    CameraRtpStreamManagement,
    CarbonDioxideSensor,
    CarbonMonoxideSensor,
    ContactSensor,
    DataStreamTransportManagement,
    Door,
    Doorbell,
    Fan,
    Faucet,
    FilterMaintenance,
    GarageDoorOpener,
    HAPProtocolInformation,
    HeaterCooler,
    HumidifierDehumidifier,
    HumiditySensor,
    IrrigationSystem,
    LeakSensor,
    LightBulb,
    LightSensor,
    LockManagement,


    Unknown
}

pub(crate) fn string_to_service_type(value: String) -> ServiceType {
    let value = value.to_ascii_uppercase();
    match value.trim() {
        "3E" => ServiceType::AccessoryInformation,
        "BB" => ServiceType::AirPurifier,
        "8D" => ServiceType::AirQualitySensor,
        "127" => ServiceType::AudioStreamManagement,
        "96" => ServiceType::Battery,
        "110" => ServiceType::CameraRtpStreamManagement,
        "97" => ServiceType::CarbonDioxideSensor,
        "7F" => ServiceType::CarbonMonoxideSensor,
        "80" => ServiceType::ContactSensor,
        "129" => ServiceType::DataStreamTransportManagement,
        "81" => ServiceType::Door,
        "121" => ServiceType::Doorbell,
        "B7" => ServiceType::Fan,
        "D7" => ServiceType::Faucet,
        "BA" => ServiceType::FilterMaintenance,
        "41" => ServiceType::GarageDoorOpener,
        "A2" => ServiceType::HAPProtocolInformation,
        "BC" => ServiceType::HeaterCooler,
        "BD" => ServiceType::HumidifierDehumidifier,
        "82" => ServiceType::HumiditySensor,
        "CF" => ServiceType::IrrigationSystem,
        "83" => ServiceType::LeakSensor,
        "43" => ServiceType::LightBulb,
        "84" => ServiceType::LightSensor,
        "44" => ServiceType::LockManagement,


        _ => ServiceType::Unknown
    }
}
