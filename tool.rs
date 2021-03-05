use fallible_iterator::FallibleIterator;
use std::{env, fs::File};
use thiserror::Error;

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

fn main() -> Result<(), ToolError> {
    pretty_env_logger::init();

    let mut args = env::args();
    // Ignore our binary name
    args.next();

    for filename in args {
        let file = File::open(&filename)?;
        let parser = Parser::new(file);
        let events: Vec<Event> = parser.collect()?;

        serde_yaml::to_writer(std::io::stdout(), &events)?;
    }

    Ok(())
}
