// SPDX-License-Identifier: MPL-2.0

//! Bounded, versioned messages shared by the runtime and guest agent.

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

use crate::config::{Config, Process};

pub const VERSION: u32 = 2;
pub const AGENT_PORT: u32 = 1024;
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
pub const STREAM_CHUNK_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Message {
    Hello {
        version: u32,
    },
    Prepare {
        config: Box<Config>,
    },
    Prepared,
    ListProcesses {
        request_id: u64,
    },
    Processes {
        request_id: u64,
        pids: Vec<u32>,
    },
    Start {
        id: u64,
        process: Option<Process>,
    },
    Started {
        id: u64,
        pid: u32,
    },
    Resize {
        request_id: u64,
        id: u64,
        rows: u16,
        columns: u16,
    },
    InputReady {
        id: u64,
    },
    Signal {
        request_id: u64,
        id: u64,
        signal: i32,
    },
    CloseInput {
        request_id: u64,
        id: u64,
    },
    Data {
        id: u64,
        stream: Stream,
        data: Vec<u8>,
    },
    Close {
        id: u64,
        stream: Stream,
    },
    Exited {
        id: u64,
        code: i32,
    },
    RequestCompleted {
        request_id: u64,
    },
    RequestFailed {
        request: Request,
        detail: String,
    },
    /// A preparation or protocol failure that makes the agent unavailable.
    Error {
        detail: String,
    },
}

/// Identifies the operation that failed without changing another process's state.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum Request {
    ListProcesses { request_id: u64 },
    Start { id: u64 },
    Resize { request_id: u64, id: u64 },
    Signal { request_id: u64, id: u64 },
    CloseInput { request_id: u64, id: u64 },
    Data { id: u64 },
    Close { id: u64 },
}

impl Request {
    pub fn from_message(message: &Message) -> Option<Self> {
        Some(match message {
            Message::ListProcesses { request_id } => Self::ListProcesses {
                request_id: *request_id,
            },
            Message::Start { id, .. } => Self::Start { id: *id },
            Message::Resize { request_id, id, .. } => Self::Resize {
                request_id: *request_id,
                id: *id,
            },
            Message::Signal { request_id, id, .. } => Self::Signal {
                request_id: *request_id,
                id: *id,
            },
            Message::CloseInput { request_id, id } => Self::CloseInput {
                request_id: *request_id,
                id: *id,
            },
            Message::Data {
                id,
                stream: Stream::Stdin,
                ..
            } => Self::Data { id: *id },
            Message::Close {
                id,
                stream: Stream::Stdin,
            } => Self::Close { id: *id },
            _ => return None,
        })
    }

    pub fn request_id(self) -> Option<u64> {
        match self {
            Self::ListProcesses { request_id }
            | Self::Resize { request_id, .. }
            | Self::Signal { request_id, .. }
            | Self::CloseInput { request_id, .. } => Some(request_id),
            Self::Start { .. } | Self::Data { .. } | Self::Close { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub enum Stream {
    Stdin,
    Stdout,
    Stderr,
}

/// Writes one JSON value framed by a little-endian u32 length prefix, then
/// flushes. An oversized value is rejected before the prefix is written, so a
/// failed send cannot desynchronize the peer's framing.
pub fn send_value<T: Serialize>(writer: &mut impl Write, value: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message too large",
        ));
    }
    writer.write_all(&(bytes.len() as u32).to_le_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()
}

/// Reads one length-prefixed JSON value. Zero-length and oversized frames are
/// rejected before any allocation.
pub fn receive_value<T: for<'de> Deserialize<'de>>(reader: &mut impl Read) -> io::Result<T> {
    let mut prefix = [0; 4];
    reader.read_exact(&mut prefix)?;
    let length = u32::from_le_bytes(prefix) as usize;
    if length == 0 || length > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid message length",
        ));
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Writes a little-endian u32 length followed by one JSON message.
pub fn send(writer: &mut impl Write, message: &Message) -> io::Result<()> {
    send_value(writer, message)
}

/// Reads one length-prefixed JSON message.
pub fn receive(reader: &mut impl Read) -> io::Result<Message> {
    receive_value(reader)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_preserves_boundaries_and_streams() {
        let mut bytes = Vec::new();
        send(
            &mut bytes,
            &Message::Data {
                id: 7,
                stream: Stream::Stderr,
                data: vec![0, 255, 10],
            },
        )
        .unwrap();
        send(
            &mut bytes,
            &Message::Close {
                id: 7,
                stream: Stream::Stdin,
            },
        )
        .unwrap();
        let mut input = bytes.as_slice();
        assert!(
            matches!(receive(&mut input).unwrap(), Message::Data { id: 7, stream: Stream::Stderr, data } if data == [0,255,10])
        );
        assert!(matches!(
            receive(&mut input).unwrap(),
            Message::Close {
                id: 7,
                stream: Stream::Stdin
            }
        ));
        assert!(input.is_empty());
    }

    #[test]
    fn oversized_frame_is_rejected_before_allocation() {
        let prefix = ((MAX_MESSAGE_BYTES + 1) as u32).to_le_bytes();
        assert_eq!(
            receive(&mut prefix.as_slice()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn zero_length_frame_is_rejected_before_allocation() {
        assert_eq!(
            receive(&mut 0u32.to_le_bytes().as_slice())
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn oversized_send_rejects_before_writing_any_byte() {
        let mut writer = Vec::new();
        let error = send_value(&mut writer, &vec![0u8; MAX_MESSAGE_BYTES + 1]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(writer.is_empty());
    }

    #[test]
    fn framing_is_generic_over_the_value_type() {
        // The same framing carries agent messages and control-plane values.
        let mut bytes = Vec::new();
        send_value(&mut bytes, &Message::Started { id: 3, pid: 9 }).unwrap();
        send_value(&mut bytes, &vec![1u32, 2]).unwrap();
        let mut input = bytes.as_slice();
        assert!(matches!(
            receive(&mut input).unwrap(),
            Message::Started { id: 3, pid: 9 }
        ));
        assert_eq!(receive_value::<Vec<u32>>(&mut input).unwrap(), vec![1, 2]);
        assert!(input.is_empty());
    }
}
