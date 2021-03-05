use byteorder::{ByteOrder, LittleEndian, ReadBytesExt};
use fallible_iterator::FallibleIterator;
use log::{info, trace};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serde::Serialize;
use std::collections::HashMap;
use std::convert::TryInto;
use std::io::Read;
use thiserror::Error;

fn serialize_as_base64<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&base64::encode(bytes))
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Previous iteration failed")]
    PreviousIteration,
    #[error("End of file reached")]
    Eof,
    #[error("Unsupported digest method {0} encountered")]
    UnsupportedDigestMethod(u16),
    #[error("Error parsing event: {0}")]
    EventParse(#[from] EventParseError),
}

fn map_eof(e: std::io::Error) -> Error {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        Error::Eof
    } else {
        Error::Io(e)
    }
}

#[derive(Debug)]
enum LogType {
    PcrEvent,
    Event2,
}

const EFI_EVENT_BASE: u32 = 0x80000000;
#[derive(Debug, PartialEq, FromPrimitive, Copy, Clone)]
#[repr(u32)]
enum KnownEventType {
    // TCG PC Client Specific Implementation Specification for Conventional BIOS
    PrebootCert = 0x0,
    PostCode = 0x1,
    Unused = 0x2,
    NoAction = 0x3,
    Separator = 0x4,
    Action = 0x5,
    EventTag = 0x6,
    CrtmContents = 0x7,
    CrtmVersion = 0x8,
    CpuMicrocode = 0x9,
    PlatformConfigFlags = 0xA,
    TableOfDevices = 0xB,
    CompactHash = 0xC,
    IPL = 0xD,
    IPLPartitionData = 0xE,
    NonhostCode = 0xF,
    NonhostConfig = 0x10,
    NonhostInfo = 0x11,
    OmitbootDeviceEvents = 0x12,

    // TCG EFI Platform Specification For TPM Family 1.1 or 1.2, table 7-1
    EFIVariableDriverConfig = EFI_EVENT_BASE + 0x1,
    EFIVariableBoot = EFI_EVENT_BASE + 0x2,
    EFIBootServicesApplication = EFI_EVENT_BASE + 0x3,
    EFIBootServicesDriver = EFI_EVENT_BASE + 0x4,
    EFIRuntimeServicesDriver = EFI_EVENT_BASE + 0x5,
    EFIGptEvent = EFI_EVENT_BASE + 0x6,
    EFIAction = EFI_EVENT_BASE + 0x7,
    EFIPlatformFirmwareBlob = EFI_EVENT_BASE + 0x8,
    EFIHandoffTables = EFI_EVENT_BASE + 0x9,
    EFIVariableAuthority = EFI_EVENT_BASE + 0xE0,
}

#[derive(Debug, PartialEq, Copy, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum EventType {
    // TCG PC Client Specific Implementation Specification for Conventional BIOS
    PrebootCert,
    PostCode,
    Unused,
    NoAction,
    Separator,
    Action,
    EventTag,
    CrtmContents,
    CrtmVersion,
    CpuMicrocode,
    PlatformConfigFlags,
    TableOfDevices,
    CompactHash,
    IPL,
    IPLPartitionData,
    NonhostCode,
    NonhostConfig,
    NonhostInfo,
    OmitbootDeviceEvents,

    // TCG EFI Platform Specification For TPM Family 1.1 or 1.2, table 7-1
    EFIVariableDriverConfig,
    EFIVariableBoot,
    EFIBootServicesApplication,
    EFIBootServicesDriver,
    EFIRuntimeServicesDriver,
    EFIGptEvent,
    EFIAction,
    EFIPlatformFirmwareBlob,
    EFIHandoffTables,
    EFIVariableAuthority,

    // Others
    Unknown(u32),
}

impl From<u32> for EventType {
    fn from(raw: u32) -> Self {
        if let Some(known) = KnownEventType::from_u32(raw) {
            match known {
                KnownEventType::PrebootCert => EventType::PrebootCert,
                KnownEventType::PostCode => EventType::PostCode,
                KnownEventType::Unused => EventType::Unused,
                KnownEventType::NoAction => EventType::NoAction,
                KnownEventType::Separator => EventType::Separator,
                KnownEventType::Action => EventType::Action,
                KnownEventType::EventTag => EventType::EventTag,
                KnownEventType::CrtmContents => EventType::CrtmContents,
                KnownEventType::CrtmVersion => EventType::CrtmVersion,
                KnownEventType::CpuMicrocode => EventType::CpuMicrocode,
                KnownEventType::PlatformConfigFlags => EventType::PlatformConfigFlags,
                KnownEventType::TableOfDevices => EventType::TableOfDevices,
                KnownEventType::CompactHash => EventType::CompactHash,
                KnownEventType::IPL => EventType::IPL,
                KnownEventType::IPLPartitionData => EventType::IPLPartitionData,
                KnownEventType::NonhostCode => EventType::NonhostCode,
                KnownEventType::NonhostConfig => EventType::NonhostConfig,
                KnownEventType::NonhostInfo => EventType::NonhostInfo,
                KnownEventType::OmitbootDeviceEvents => EventType::OmitbootDeviceEvents,
                KnownEventType::EFIVariableDriverConfig => EventType::EFIVariableDriverConfig,
                KnownEventType::EFIVariableBoot => EventType::EFIVariableBoot,
                KnownEventType::EFIBootServicesApplication => EventType::EFIBootServicesApplication,
                KnownEventType::EFIBootServicesDriver => EventType::EFIBootServicesDriver,
                KnownEventType::EFIRuntimeServicesDriver => EventType::EFIRuntimeServicesDriver,
                KnownEventType::EFIGptEvent => EventType::EFIGptEvent,
                KnownEventType::EFIAction => EventType::EFIAction,
                KnownEventType::EFIPlatformFirmwareBlob => EventType::EFIPlatformFirmwareBlob,
                KnownEventType::EFIHandoffTables => EventType::EFIHandoffTables,
                KnownEventType::EFIVariableAuthority => EventType::EFIVariableAuthority,
            }
        } else {
            EventType::Unknown(raw)
        }
    }
}

#[derive(Debug, FromPrimitive, Serialize)]
#[repr(u16)]
#[serde(rename_all = "lowercase")]
pub enum DigestMethod {
    Sha1 = 0x0004,
    Sha256 = 0x000B,
    Sha384 = 0x000C,
    Sha512 = 0x000D,
}

fn string_from_widechar(wchar: &[u8]) -> Result<String, EventParseError> {
    let (head, wchar, tail) = unsafe { wchar.align_to::<u16>() };
    if !head.is_empty() {
        return Err(EventParseError::Unaligned);
    }
    if !tail.is_empty() {
        return Err(EventParseError::Unaligned);
    }
    let ustr = widestring::U16Str::from_slice(wchar);
    Ok(ustr
        .to_string()
        .map(|s| String::from(s.trim_end_matches('\0')))
        .map_err(|_| EventParseError::TextDecoding)?)
}

#[derive(Debug)]
struct EfiSpecId {
    platform_class: u32,
    spec_version_major: u8,
    spec_version_minor: u8,
    spec_errata: u8,
    uintn_size: u8,
    algo_sizes: HashMap<u16, u16>,
    vendor_info: Vec<u8>,
}

impl EfiSpecId {
    fn parse(data: &[u8]) -> Result<EfiSpecId, EventParseError> {
        if data.len() < 29 {
            return Err(EventParseError::TooShort);
        }
        let signature = &data[0..16];
        if signature
            != [
                0x53, 0x70, 0x65, 0x63, 0x20, 0x49, 0x44, 0x20, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x30,
                0x33, 0x00,
            ]
        {
            return Err(EventParseError::InvalidSignature);
        }
        let platform_class = LittleEndian::read_u32(&data[16..20]);
        let spec_version_minor = data[20];
        let spec_version_major = data[21];
        let spec_errata = data[22];
        let uintn_size = data[23];
        let num_algorithms = LittleEndian::read_u32(&data[24..28]);
        let mut algo_sizes = HashMap::new();
        for i in 0..num_algorithms {
            let i = i as usize;
            let algo_id = LittleEndian::read_u16(&data[28 + (i * 4)..28 + (i * 4) + 2]);
            let digest_size = LittleEndian::read_u16(&data[28 + (i * 4) + 2..28 + (i * 4) + 4]);
            algo_sizes.insert(algo_id, digest_size);
        }
        let offset = 28 + (num_algorithms * 4) as usize;
        let vendor_info_size = data[offset] as usize;
        if data.len() != (offset + vendor_info_size + 1) {
            return Err(EventParseError::TooShort);
        }
        let vendor_info = data[offset + 1..].to_vec();

        Ok(EfiSpecId {
            platform_class,
            spec_version_major,
            spec_version_minor,
            spec_errata,
            uintn_size,
            algo_sizes,
            vendor_info,
        })
    }
}

pub type GUID = [u8; 16];

#[derive(Debug, Serialize)]
pub struct EfiVariableData {
    pub variable_guid: [u8; 16],
    pub name: String,
    #[serde(serialize_with = "serialize_as_base64")]
    pub data: Vec<u8>,
}

impl EfiVariableData {
    fn parse(data: &[u8]) -> Result<EfiVariableData, EventParseError> {
        let variable_guid = &data[0..16];
        let num_name_chars = LittleEndian::read_u64(&data[16..24]);
        let name_len = (num_name_chars * 2) as usize;
        let data_len = LittleEndian::read_u64(&data[24..32]) as usize;

        if data.len() != 16 + 8 + 8 + name_len + data_len {
            return Err(EventParseError::TooShort);
        }

        let name_data = &data[32..32 + name_len];
        let data = data[32 + name_len..].to_vec();

        let name = string_from_widechar(name_data)?;

        Ok(EfiVariableData {
            variable_guid: variable_guid.try_into().unwrap(),
            name,
            data,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "end_type", rename_all = "lowercase")]
pub enum EndOfPathType {
    EntireDevicePath,
    Instance,
}

#[derive(Debug, Serialize, FromPrimitive)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum DevicePathInfoHardDrivePartitionFormat {
    Mbr = 0x01,
    Gpt = 0x02,
}

#[derive(Debug, Serialize, FromPrimitive)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum DevicePathInfoHardDriveSignatureType {
    NoSignature = 0x00,
    MbrType = 0x01,
    Guid = 0x02,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DevicePathInfo {
    // Device types we couldn't parse
    UnknownDevice {
        device_type: u8,
        device_subtype: u8,

        #[serde(serialize_with = "serialize_as_base64")]
        data: Vec<u8>,
    },

    // Type: Device Path End
    EndOfPath(EndOfPathType),

    // Type: Hardware Device Path
    DevicePCI {
        function: u8,
        device: u8,
    },
    DeviceMemoryMapped {
        memory_type: u32,
        start_address: u64,
        end_address: u64,
    },

    // Type: ACPI Device Path
    Acpi {
        hid: u32,
        uid: u32,
    },

    // Type: Messaging Device Path

    // Type: Media Device Path
    HardDrive {
        partition_number: u32,
        partition_start: u64,
        partition_size: u64,
        #[serde(serialize_with = "serialize_as_base64")]
        partition_signature: Vec<u8>,
        partition_format: DevicePathInfoHardDrivePartitionFormat,
        signature_type: DevicePathInfoHardDriveSignatureType,
    },
    FilePath {
        path: String,
    },
}

impl DevicePathInfo {
    fn parse(
        device_type: u8,
        device_subtype: u8,
        data: &[u8],
    ) -> Result<DevicePathInfo, EventParseError> {
        match (device_type, device_subtype) {
            // Type: Device Path End
            //  Sub-type: End Entire Device Path
            (0x7F, 0xFF) => Ok(DevicePathInfo::EndOfPath(EndOfPathType::EntireDevicePath)),
            //  Sub-type: End this instance
            (0x7F, 0x01) => Ok(DevicePathInfo::EndOfPath(EndOfPathType::Instance)),

            // Type: Hardware Device Path
            //  Sub-type: PCI
            (0x01, 0x01) => {
                if data.len() != 2 {
                    return Err(EventParseError::TooShort);
                }
                Ok(DevicePathInfo::DevicePCI {
                    function: data[0],
                    device: data[1],
                })
            }

            //  Sub-type: Memory Mapped Device
            (0x01, 0x03) => {
                if data.len() != 20 {
                    return Err(EventParseError::TooShort);
                }
                Ok(DevicePathInfo::DeviceMemoryMapped {
                    memory_type: LittleEndian::read_u32(&data[0..4]),
                    start_address: LittleEndian::read_u64(&data[4..12]),
                    end_address: LittleEndian::read_u64(&data[12..20]),
                })
            }

            // Type: ACPI Device Path
            //  Sub-type: ACPI
            (0x02, 0x01) => {
                if data.len() != 8 {
                    return Err(EventParseError::TooShort);
                }
                Ok(DevicePathInfo::Acpi {
                    hid: LittleEndian::read_u32(&data[0..4]),
                    uid: LittleEndian::read_u32(&data[4..8]),
                })
            }

            // Type Media Devices
            //  Sub-type: Hard Drive
            (0x04, 0x01) => {
                if data.len() != 38 {
                    return Err(EventParseError::TooShort);
                }
                let partition_format =
                    match DevicePathInfoHardDrivePartitionFormat::from_u8(data[36]) {
                        None => return Err(EventParseError::InvalidValue),
                        Some(v) => v,
                    };
                let signature_type = match DevicePathInfoHardDriveSignatureType::from_u8(data[37]) {
                    None => return Err(EventParseError::InvalidValue),
                    Some(v) => v,
                };
                Ok(DevicePathInfo::HardDrive {
                    partition_number: LittleEndian::read_u32(&data[0..4]),
                    partition_start: LittleEndian::read_u64(&data[4..12]),
                    partition_size: LittleEndian::read_u64(&data[12..20]),
                    partition_signature: data[20..36].to_vec(),
                    partition_format,
                    signature_type,
                })
            }

            //  Sub-type: File Path
            (0x04, 0x04) => Ok(DevicePathInfo::FilePath {
                path: string_from_widechar(data)?,
            }),

            // Unknown device types
            _ => Ok(DevicePathInfo::UnknownDevice {
                device_type,
                device_subtype,
                data: data.to_vec(),
            }),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct DevicePath {
    #[serde(flatten)]
    pub info: DevicePathInfo,
    pub next: Option<Box<DevicePath>>,
}

impl DevicePath {
    fn parse(data: &[u8]) -> Result<Option<DevicePath>, EventParseError> {
        if data.is_empty() {
            Ok(None)
        } else {
            let device_type = data[0];
            let device_subtype = data[1];
            let path_len = (LittleEndian::read_u16(&data[2..4]) - 4) as usize;

            let path_data = data[4..4 + path_len].to_vec();

            let next = DevicePath::parse(&data[4 + path_len..])?.map(Box::new);

            Ok(Some(DevicePath {
                info: DevicePathInfo::parse(device_type, device_subtype, &path_data)?,
                next,
            }))
        }
    }
}

#[derive(Debug, Serialize)]
pub enum SeparatorType {
    ConventionalBIOS,
    UEFI,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ParsedEventData {
    FirmwareBlobLocation {
        base: u64,
        length: u64,
    },
    Text(String),
    EfiVariable(EfiVariableData),
    ImageLoadEvent {
        image_location_in_memory: u64,
        image_length_in_memory: u64,
        image_link_time_address: u64,
        device_path: Option<DevicePath>,
        #[serde(serialize_with = "serialize_as_base64")]
        extra_data: Vec<u8>,
    },
    ValidSeparator(SeparatorType),
}

#[derive(Error, Debug)]
pub enum EventParseError {
    #[error("Text decoding error")]
    TextDecoding,
    #[error("Contents are too short")]
    TooShort,
    #[error("Invalid structure signature")]
    InvalidSignature,
    #[error("Unsupported log version")]
    UnsupportedLog,
    #[error("A value was unaligned")]
    Unaligned,
    #[error("An invalid value was encountered")]
    InvalidValue,
}

impl ParsedEventData {
    fn parse_efi_text(data: &[u8]) -> Result<ParsedEventData, EventParseError> {
        Ok(ParsedEventData::Text(
            std::str::from_utf8(data)
                .map_err(|_| EventParseError::TextDecoding)?
                .trim_end_matches('\0')
                .to_string(),
        ))
    }

    fn parse_efi_image_load_event(data: &[u8]) -> Result<ParsedEventData, EventParseError> {
        if data.len() < 32 {
            return Err(EventParseError::TooShort);
        }
        let image_location_in_memory = LittleEndian::read_u64(&data[0..8]);
        let image_length_in_memory = LittleEndian::read_u64(&data[8..16]);
        let image_link_time_address = LittleEndian::read_u64(&data[16..24]);
        let device_path_len = LittleEndian::read_u64(&data[24..32]) as usize;

        let device_path = DevicePath::parse(&data[32..32 + device_path_len])?;
        let extra_data = data[32 + device_path_len..].to_vec();

        Ok(ParsedEventData::ImageLoadEvent {
            image_location_in_memory,
            image_length_in_memory,
            image_link_time_address,
            device_path,
            extra_data,
        })
    }

    fn parse_efi_firmware_blob(data: &[u8]) -> Result<ParsedEventData, EventParseError> {
        if data.len() != 16 {
            return Err(EventParseError::TooShort);
        }
        let base = LittleEndian::read_u64(&data[0..8]);
        let length = LittleEndian::read_u64(&data[8..16]);
        Ok(ParsedEventData::FirmwareBlobLocation { base, length })
    }

    fn parse(event: EventType, data: &[u8]) -> Result<Option<ParsedEventData>, EventParseError> {
        match event {
            // EFI Events
            EventType::CrtmVersion => Ok(Some(ParsedEventData::Text(string_from_widechar(data)?))),
            EventType::EFIVariableDriverConfig
            | EventType::EFIVariableBoot
            | EventType::EFIVariableAuthority => Ok(Some(ParsedEventData::EfiVariable(
                EfiVariableData::parse(data)?,
            ))),
            EventType::PostCode | EventType::IPL | EventType::EFIAction => {
                Ok(Some(ParsedEventData::parse_efi_text(data)?))
            }
            EventType::EFIBootServicesApplication
            | EventType::EFIBootServicesDriver
            | EventType::EFIRuntimeServicesDriver => {
                Ok(Some(ParsedEventData::parse_efi_image_load_event(data)?))
            }
            EventType::EFIPlatformFirmwareBlob => {
                Ok(Some(ParsedEventData::parse_efi_firmware_blob(data)?))
            }

            // EFI Event types to do: GptEvent, HandoffTables
            EventType::Separator => {
                if data == [0, 0, 0, 0] {
                    Ok(Some(ParsedEventData::ValidSeparator(SeparatorType::UEFI)))
                } else if data == [0xff, 0xff, 0xff, 0xff] {
                    Ok(Some(ParsedEventData::ValidSeparator(
                        SeparatorType::ConventionalBIOS,
                    )))
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Digest {
    method: DigestMethod,
    #[serde(serialize_with = "serialize_as_base64")]
    digest: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct Event {
    pub pcr_index: u32,
    pub event: EventType,
    pub digests: Vec<Digest>,
    #[serde(serialize_with = "serialize_as_base64")]
    pub data: Vec<u8>,
    pub parsed_data: Option<ParsedEventData>,
}

#[derive(Debug)]
pub struct Parser<R: Read> {
    reader: R,
    logtype: Option<LogType>,
    log_info: Option<EfiSpecId>,
    last_error: Option<Error>,
}

impl<R: Read> Parser<R> {
    pub fn new(reader: R) -> Self {
        Parser {
            reader,
            logtype: None,
            log_info: None,
            last_error: None,
        }
    }
}

fn zeroed_vec(len: usize) -> Vec<u8> {
    vec![0; len]
}

impl<R: Read> Parser<R> {
    fn parse_pcr_event(&mut self) -> Result<Event, Error> {
        // PCR Index
        let pcr_index = self.reader.read_u32::<LittleEndian>().map_err(map_eof)?;
        // Event Type
        let event_type = self.reader.read_u32::<LittleEndian>()?;
        let event_type = EventType::from(event_type);
        // 20-byte sha1 digest
        let mut digestbuf = zeroed_vec(20);
        self.reader.read_exact(&mut digestbuf)?;
        // Event size
        let event_size = self.reader.read_u32::<LittleEndian>()?;
        // Event contents
        let mut eventbuf = zeroed_vec(event_size as usize);
        self.reader.read_exact(&mut eventbuf)?;

        // Possibly parse
        let parsed_data = ParsedEventData::parse(event_type, &eventbuf)?;

        // Build up event structure
        let digests = vec![Digest {
            method: DigestMethod::Sha1,
            digest: digestbuf,
        }];

        Ok(Event {
            pcr_index,
            event: event_type,
            digests,
            data: eventbuf,
            parsed_data,
        })
    }

    fn parse_event2(&mut self) -> Result<Event, Error> {
        // PCR Index
        let pcr_index = self.reader.read_u32::<LittleEndian>().map_err(map_eof)?;

        // Event Type
        let event_type = self.reader.read_u32::<LittleEndian>()?;
        let event_type = EventType::from(event_type);

        // Digests
        let digest_count = self.reader.read_u32::<LittleEndian>()?;
        let mut digests = Vec::with_capacity(digest_count as usize);
        for _ in 0..digest_count {
            let raw_algo = self.reader.read_u16::<LittleEndian>()?;
            let algo = match DigestMethod::from_u16(raw_algo) {
                None => return Err(Error::UnsupportedDigestMethod(raw_algo)),
                Some(v) => v,
            };
            let log_info = self.log_info.as_ref().unwrap();
            let algo_size = match log_info.algo_sizes.get(&raw_algo) {
                None => return Err(Error::UnsupportedDigestMethod(raw_algo)),
                Some(v) => v,
            };
            let mut digbuf = zeroed_vec(*algo_size as usize);
            self.reader.read_exact(&mut digbuf)?;

            digests.push(Digest {
                method: algo,
                digest: digbuf,
            })
        }

        // Event size
        let event_size = self.reader.read_u32::<LittleEndian>()?;
        // Event contents
        let mut eventbuf = zeroed_vec(event_size as usize);
        self.reader.read_exact(&mut eventbuf)?;

        trace!(
            "Parsing event of type {:?}, size {:?}, PCR {}",
            event_type,
            event_size,
            pcr_index
        );

        // Possibly parse
        let parsed_data = ParsedEventData::parse(event_type, &eventbuf)?;

        // Build up Event structure
        Ok(Event {
            pcr_index,
            event: event_type,
            digests,
            data: eventbuf,
            parsed_data,
        })
    }
}

impl<R: Read> FallibleIterator for Parser<R> {
    type Item = Event;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Event>, Error> {
        if self.logtype.is_none() {
            let firstevent = match self.parse_pcr_event() {
                Err(Error::Eof) => return Ok(None),
                Err(e) => return Err(e),
                Ok(val) => val,
            };

            trace!("First event: {:?}", firstevent);

            if firstevent.event == EventType::NoAction {
                info!("Log type: event2");
                let spec_id = EfiSpecId::parse(&firstevent.data)?;
                trace!("Parsed first event: {:?}", spec_id);
                if spec_id.uintn_size != 2 {
                    return Err(Error::EventParse(EventParseError::UnsupportedLog));
                }
                self.log_info = Some(spec_id);
                self.logtype = Some(LogType::Event2);
            // In this case, we explicitly fall through, to not return this marker event
            } else {
                info!("Log type: PcrEvent");
                self.logtype = Some(LogType::PcrEvent);
                return Ok(Some(firstevent));
            }
        }

        let new_event = match self.logtype.as_ref().unwrap() {
            // The None case is already captured above
            LogType::PcrEvent => self.parse_pcr_event(),
            LogType::Event2 => self.parse_event2(),
        };

        match new_event {
            Err(Error::Eof) => Ok(None),
            Err(e) => Err(e),
            Ok(val) => Ok(Some(val)),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
