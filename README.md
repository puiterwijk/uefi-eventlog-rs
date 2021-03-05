# uefi-eventlog-rs

This is a parser for the UEFI Boot Log.

This file is on Linux systems usually available on: `/sys/kernel/security/tpm0/binary_bios_measurements`.

This repository includes a debugging tool, you can run the following commands to run the tool and get your own log:

```
cargo build
sudo target/debug/uefi-eventlog-dump /sys/kernel/security/tpm0/binary_bios_measurements
```
