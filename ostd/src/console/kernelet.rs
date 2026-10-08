// SPDX-License-Identifier: MPL-2.0

//! Sends early image output through the Host's bounded console service.

use core::fmt::{self, Arguments, Write};

use crate::{
    kernelet::{
        abi::{LEVEL_CONSOLE, MAX_LOG_MODULE_BYTES, MAX_LOG_TEXT_BYTES},
        entry,
    },
    log::{self, LevelFilter, Log, Record},
};

const MODULE: &[u8] = b"ostd";

pub(super) fn write(args: Arguments) {
    write_record(LEVEL_CONSOLE, MODULE, args);
}

pub(super) fn init() {
    static LOGGER: KerneletLogger = KerneletLogger;
    log::set_max_level(LevelFilter::Info);
    log::inject_logger(&LOGGER);
}

struct KerneletLogger;

impl Log for KerneletLogger {
    fn log(&self, record: &Record) {
        let module = record.prefix().as_bytes();
        let module = if module.len() <= MAX_LOG_MODULE_BYTES as usize {
            module
        } else {
            MODULE
        };
        write_record(record.level() as u32, module, *record.args());
    }
}

fn write_record(level: u32, module: &[u8], args: Arguments) {
    let mut writer = ConsoleWriter {
        level,
        module,
        bytes: [0; MAX_LOG_TEXT_BYTES as usize],
        len: 0,
    };
    let _ = fmt::write(&mut writer, args);
    let _ = writer.flush();
}

struct ConsoleWriter<'a> {
    level: u32,
    module: &'a [u8],
    bytes: [u8; MAX_LOG_TEXT_BYTES as usize],
    len: usize,
}

impl ConsoleWriter<'_> {
    fn flush(&mut self) -> fmt::Result {
        if self.len == 0 {
            return Ok(());
        }
        let result = (entry::services().log_write)(
            self.level,
            self.module.as_ptr(),
            self.module.len() as u32,
            self.bytes.as_ptr(),
            self.len as u32,
        );
        self.len = 0;
        if result < 0 { Err(fmt::Error) } else { Ok(()) }
    }
}

impl Write for ConsoleWriter<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        for ch in text.chars() {
            let mut bytes = [0; 4];
            let encoded = ch.encode_utf8(&mut bytes).as_bytes();
            if self.len + encoded.len() > self.bytes.len() {
                self.flush()?;
            }
            self.bytes[self.len..self.len + encoded.len()].copy_from_slice(encoded);
            self.len += encoded.len();
        }
        Ok(())
    }
}
