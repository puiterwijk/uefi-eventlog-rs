use byteorder::{LittleEndian, ReadBytesExt};
use fallible_iterator::FallibleIterator;
use log::{info, trace};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serde::Serialize;
use std::io::Read;
use thiserror::Error;

pub mod parsed;

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
    EventParse(#[from] parsed::EventParseError),
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
    pub parsed_data: Option<parsed::ParsedEventData>,
}

#[derive(Debug)]
pub struct Parser<R: Read> {
    reader: R,
    logtype: Option<LogType>,
    log_info: Option<parsed::EfiSpecId>,
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
        let parsed_data = parsed::ParsedEventData::parse(event_type, &eventbuf)?;

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
        let parsed_data = parsed::ParsedEventData::parse(event_type, &eventbuf)?;

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
                let spec_id = parsed::EfiSpecId::parse(&firstevent.data)?;
                trace!("Parsed first event: {:?}", spec_id);
                if spec_id.uintn_size != 2 {
                    return Err(Error::EventParse(parsed::EventParseError::UnsupportedLog));
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
