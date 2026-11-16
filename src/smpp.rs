//! Minimal SMPP 3.4 gateway/ESME support for pushing OTA SMS (#210).
//!
//! **Owns.** A small, self-hosted SMPP server that accepts an ESME bind and
//! `submit_sm` PDUs carrying OTA SMS payloads, and hands the decoded
//! user data to a caller-supplied sink. This lets an operator push OTA SMS to
//! a card without any third-party SMSC service.
//!
//! **Does not own.** The OTA cryptography or the card transport (see
//! [`crate::sms`], [`crate::otacrypto`], [`crate::ota_expanded`]); this module
//! only moves bytes over SMPP and decodes the basic PDU framing. It is a
//! defensive, bounded implementation: malformed or oversized PDUs are refused.
//!
//! **Self-hosted.** The server binds to an address the operator provides and
//! runs in-process; no external account is involved.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// This module's name.
pub const NAME: &str = "smpp";

/// SMPP `bind_receiver` command ID.
pub const CMD_BIND_RECEIVER: u32 = 0x0000_0001;
/// SMPP `bind_transmitter` command ID.
pub const CMD_BIND_TRANSMITTER: u32 = 0x0000_0002;
/// SMPP `bind_transceiver` command ID.
pub const CMD_BIND_TRANSCEIVER: u32 = 0x0000_0009;
/// SMPP `submit_sm` command ID.
pub const CMD_SUBMIT_SM: u32 = 0x0000_0004;
/// SMPP `enquire_link` command ID.
pub const CMD_ENQUIRE_LINK: u32 = 0x0000_0015;
/// SMPP `unbind` command ID.
pub const CMD_UNBIND: u32 = 0x0000_0006;
/// SMPP `generic_nack` command ID.
pub const CMD_GENERIC_NACK: u32 = 0x8000_0000;

/// Status: success.
pub const ESME_ROK: u32 = 0;
/// Invalid command length / malformed.
pub const ESME_RINVCMDLEN: u32 = 0x0000_0002;
/// Invalid bind status.
pub const ESME_RINVBNDSTS: u32 = 0x0000_0004;

/// Max PDU length accepted (defensive bound).
pub const MAX_PDU: usize = 64 * 1024;

/// A decoded submit_sm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitSm {
    /// Destination address (digits/text).
    pub destination_addr: String,
    /// Short message bytes (user data).
    pub short_message: Vec<u8>,
    /// Data coding scheme.
    pub data_coding: u8,
}

/// A gateway event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// An ESME bound.
    Bound {
        /// The ESME system_id supplied in the bind.
        system_id: String,
    },
    /// A submit_sm was received.
    Message(SubmitSm),
    /// An ESME unbound or disconnected.
    Unbound,
}

/// Errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// I/O failure.
    #[error("io: {0}")]
    Io(String),
    /// Protocol/framing error.
    #[error("protocol: {0}")]
    Protocol(String),
}

fn read_exact_or_err(s: &mut TcpStream, n: usize) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).map_err(|e| Error::Io(e.to_string()))?;
    Ok(buf)
}

fn read_c_string(data: &[u8], pos: &mut usize) -> Result<String, Error> {
    let start = *pos;
    while *pos < data.len() && data[*pos] != 0 {
        *pos += 1;
    }
    if *pos >= data.len() {
        return Err(Error::Protocol("unterminated c-string".into()));
    }
    let s = String::from_utf8_lossy(&data[start..*pos]).to_string();
    *pos += 1; // skip NUL
    Ok(s)
}

fn parse_submit_sm(body: &[u8]) -> Result<SubmitSm, Error> {
    let mut p = 0usize;
    // service_type
    let _service_type = read_c_string(body, &mut p)?;
    // source_addr_ton, source_addr_npi
    if p + 2 > body.len() {
        return Err(Error::Protocol("short submit_sm".into()));
    }
    p += 2;
    let _source_addr = read_c_string(body, &mut p)?;
    // dest_addr_ton, dest_addr_npi
    if p + 2 > body.len() {
        return Err(Error::Protocol("short submit_sm".into()));
    }
    p += 2;
    let destination_addr = read_c_string(body, &mut p)?;
    // esm_class, protocol_id, priority_flag
    if p + 3 > body.len() {
        return Err(Error::Protocol("short submit_sm".into()));
    }
    p += 3;
    // schedule_delivery_time, validity_period
    let _sched = read_c_string(body, &mut p)?;
    let _valid = read_c_string(body, &mut p)?;
    // registered_delivery, replace_if_present_flag, data_coding, sm_default_msg_id
    if p + 4 > body.len() {
        return Err(Error::Protocol("short submit_sm".into()));
    }
    let data_coding = body[p + 2];
    p += 4;
    // sm_length
    if p + 1 > body.len() {
        return Err(Error::Protocol("short submit_sm".into()));
    }
    let sm_len = body[p] as usize;
    p += 1;
    if p + sm_len > body.len() {
        return Err(Error::Protocol("short_message overrun".into()));
    }
    let short_message = body[p..p + sm_len].to_vec();
    Ok(SubmitSm {
        destination_addr,
        short_message,
        data_coding,
    })
}

fn write_pdu(
    s: &mut TcpStream,
    cmd_id: u32,
    status: u32,
    seq: u32,
    body: &[u8],
) -> Result<(), Error> {
    let len = 16u32 + body.len() as u32;
    let mut hdr = [0u8; 16];
    hdr[0..4].copy_from_slice(&len.to_be_bytes());
    hdr[4..8].copy_from_slice(&cmd_id.to_be_bytes());
    hdr[8..12].copy_from_slice(&status.to_be_bytes());
    hdr[12..16].copy_from_slice(&seq.to_be_bytes());
    s.write_all(&hdr)
        .and_then(|_| s.write_all(body))
        .map_err(|e| Error::Io(e.to_string()))
}

fn resp_id(cmd: u32) -> u32 {
    cmd | 0x8000_0000
}

/// Run a single SMPP session. Calls `on_event` for each event.
/// Stops when the peer unbinds/disconnects or `stop` becomes true.
pub fn serve_session(
    mut stream: TcpStream,
    stop: &AtomicBool,
    mut on_event: impl FnMut(Event),
) -> Result<(), Error> {
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(1)))
        .ok();
    let mut bound = false;
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf) {
            Ok(_) => {}
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => break,
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if !(16..=MAX_PDU).contains(&len) {
            return Err(Error::Protocol("invalid pdu length".into()));
        }
        let rest = read_exact_or_err(&mut stream, len - 4)?;
        if rest.len() < 12 {
            return Err(Error::Protocol("short header".into()));
        }
        let cmd_id = u32::from_be_bytes(rest[0..4].try_into().unwrap());
        let _status = u32::from_be_bytes(rest[4..8].try_into().unwrap());
        let seq = u32::from_be_bytes(rest[8..12].try_into().unwrap());
        let body = &rest[12..];
        match cmd_id {
            CMD_BIND_RECEIVER | CMD_BIND_TRANSMITTER | CMD_BIND_TRANSCEIVER => {
                // system_id is first c-string
                let mut p = 0usize;
                let system_id = read_c_string(body, &mut p).unwrap_or_default();
                bound = true;
                write_pdu(
                    &mut stream,
                    resp_id(cmd_id),
                    ESME_ROK,
                    seq,
                    b"sim-doctor\0",
                )?;
                on_event(Event::Bound { system_id });
            }
            CMD_SUBMIT_SM => {
                if !bound {
                    write_pdu(&mut stream, resp_id(cmd_id), ESME_RINVBNDSTS, seq, b"\0")?;
                    continue;
                }
                match parse_submit_sm(body) {
                    Ok(msg) => {
                        write_pdu(&mut stream, resp_id(cmd_id), ESME_ROK, seq, b"1\0")?;
                        on_event(Event::Message(msg));
                    }
                    Err(_) => {
                        write_pdu(&mut stream, resp_id(cmd_id), ESME_RINVCMDLEN, seq, b"\0")?;
                    }
                }
            }
            CMD_ENQUIRE_LINK => {
                write_pdu(&mut stream, resp_id(cmd_id), ESME_ROK, seq, &[])?;
            }
            CMD_UNBIND => {
                write_pdu(&mut stream, resp_id(cmd_id), ESME_ROK, seq, &[])?;
                on_event(Event::Unbound);
                break;
            }
            _ => {
                write_pdu(&mut stream, CMD_GENERIC_NACK, ESME_RINVCMDLEN, seq, &[])?;
            }
        }
    }
    Ok(())
}

/// Listen for SMPP connections on `addr` and serve them sequentially until
/// `stop` is set. `addr` is e.g. "127.0.0.1:2775".
pub fn serve<A: ToSocketAddrs>(
    addr: A,
    stop: Arc<AtomicBool>,
    mut on_event: impl FnMut(Event),
) -> Result<(), Error> {
    let listener = TcpListener::bind(addr).map_err(|e| Error::Io(e.to_string()))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| Error::Io(e.to_string()))?;
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_nonblocking(false);
                let _ = serve_session(stream, &stop, &mut on_event);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => return Err(Error::Io(e.to_string())),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resp_id_sets_high_bit() {
        assert_eq!(resp_id(CMD_SUBMIT_SM), 0x8000_0004);
    }
}
