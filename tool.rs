use fallible_iterator::FallibleIterator;
use serde::Serialize;
use std::{env, fs::File};
use thiserror::Error;
use tpmless_tpm2::PcrExtender;

use uefi_eventlog::{Event, Parser};

#[derive(Debug, Error)]
enum ToolError {
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Error parsing event log: {0}")]
    EventLog(#[from] uefi_eventlog::Error),
    #[error("YAML Error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

#[derive(Debug, Serialize)]
struct Results {
    events: Vec<Event>,
    pcrs: PcrExtender,
}

fn main() -> Result<(), ToolError> {
    pretty_env_logger::init();

    let mut args = env::args();
    // Ignore our binary name
    args.next();

    for filename in args {
        let file = File::open(&filename)?;
        let mut parser = Parser::new(file);
        let mut events: Vec<Event> = Vec::new();

        while let Some(event) = parser.next()? {
            events.push(event);
        }

        let any_invalid = parser.any_invalid();

        serde_yaml::to_writer(
            std::io::stdout(),
            &Results {
                events,
                pcrs: parser.pcrs(),
            },
        )?;

        if any_invalid {
            eprintln!("CAUTION: Invalid PCR values encountered!");
        }

        std::process::exit(1);
    }

    Ok(())
}
