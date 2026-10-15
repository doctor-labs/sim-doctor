//! Simulator socket transport: a [`CardSession`] over a JCSDK TCP simulator
//! (issue #222, after GlobalPlatformPro's `--simulator host:port`).
//!
//! **Owns.** Framing one exchange onto the socket and parsing what comes back.
//! Nothing above this module learns that a card is being simulated.
//!
//! **Wire format.** Every frame is a four byte header followed by its payload.
//! The first header byte is the command code; the remaining three are the
//! payload length, big endian. That is how the reference server writes it: it
//! lays down a `uint32` length and then overwrites the high byte with the code,
//! "a length with the command code in the byte the length never reaches"
//! (apdu4j `remote/src/main/java/apdu4j/remote/JCSDKServer.java:20-32`, read
//! back with `header.getInt(0) & 0xFFFFFF` at line 51). A SELECT MF is
//! therefore `00 00 00 07 00 A4 00 00 02 3F 00` on the wire.
//!
//! **Command codes** (same file, lines 21-22 and the `recv`/`send` switches):
//! `0x00` is an APDU in both directions, `0xF0` is POWER UP - the client asks
//! for the ATR of the card behind the connection and the server answers with
//! it - and `0xFE` is POWER DOWN, after which the connection is gone. The
//! connection *is* the session: "a peer that hangs up takes the card down with
//! it" (line 60), so a hangup is reported as a transport error and never as an
//! empty response.
//!
//! **No unbounded read.** Every socket carries a read and a write timeout, and
//! a frame is read by its own length, a length that cannot exceed 24 bits, so
//! no peer can park this process on an open socket forever.

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use super::{CardSession, Error, ReaderName};

/// Header length: the command code plus the 24 bit payload length.
const HEADER_LEN: usize = 4;

/// Largest payload the 24 bit length field can express.
const MAX_PAYLOAD: usize = 0x00FF_FFFF;

/// An APDU, in both directions.
const CODE_APDU: u8 = 0x00;

/// POWER UP: the client asks for the ATR of the card behind the connection.
const CODE_POWER_UP: u8 = 0xF0;

/// POWER DOWN: the connection is the session, so ending it ends the card.
const CODE_POWER_DOWN: u8 = 0xFE;

/// Host used when `--simulator` is given an empty or absent one.
const DEFAULT_HOST: &str = "localhost";

/// Port used when `--simulator` is given no `host:port` at all.
///
/// 9025 is the simulator's own default (`JCSDKServer.DEFAULT_JCSDK_PORT`,
/// line 25) and the port the reference tool falls back to
/// (`GPCommandLineInterfaceNG` / `GPToolNG.java:670-676`).
const DEFAULT_PORT: u16 = 9025;

/// Reader name prefix, so every refusal names the transport it came from.
const SIMULATOR: &str = "simulator";

/// How long one exchange may take before it is reported as a timeout.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Where `--simulator` points: a host and a port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    host: String,
    port: u16,
}

impl Endpoint {
    /// Parses the `host:port` an operator writes after `--simulator`.
    ///
    /// An empty host, or no `:` at all, means [`DEFAULT_HOST`] and
    /// [`DEFAULT_PORT`], which is what the reference tool does with the same
    /// option: `hp[0].isEmpty() ? "localhost" : hp[0]`, and a port of 9025
    /// unless one was spelled out (`GPToolNG.java:671-673`). So `""`,
    /// `"host"`, `":9026"` and `"127.0.0.1:9026"` are all accepted.
    ///
    /// # Errors
    ///
    /// A string that is neither empty nor a `host`, nor `host:port` with a
    /// port that is a number in `1..=65535`.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let (host, port) = match spec.split_once(':') {
            Some((host, port)) => (host, port),
            None => (spec, ""),
        };
        let host = if host.is_empty() {
            DEFAULT_HOST.to_owned()
        } else {
            host.to_owned()
        };
        let port = if port.is_empty() {
            DEFAULT_PORT
        } else {
            port.parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| format!("`{spec}` is not a host:port: {port} is not a port"))?
        };
        Ok(Self { host, port })
    }

    /// The host to connect to.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port to connect to.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// A live connection to a card behind a simulator socket.
///
/// Obtained from [`SimulatorSession::connect`], which also performs the POWER
/// UP exchange and keeps the ATR the simulator answered with.
pub struct SimulatorSession {
    reader: ReaderName,
    stream: TcpStream,
    atr: Vec<u8>,
    released: bool,
}

impl std::fmt::Debug for SimulatorSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimulatorSession")
            .field("reader", &self.reader)
            .field("atr", &hex::encode(&self.atr))
            .field("released", &self.released)
            .finish()
    }
}

impl SimulatorSession {
    /// Connects to `spec`, powers up and reads the ATR.
    ///
    /// # Errors
    ///
    /// Any failure to resolve or connect to the endpoint, to power up, or to
    /// read the ATR back, as a [`Error`] naming the endpoint.
    pub fn connect(spec: &str) -> Result<Self, Error> {
        Self::connect_within(spec, DEFAULT_TIMEOUT)
    }

    /// [`SimulatorSession::connect`] with a caller-chosen per-exchange timeout.
    ///
    /// `timeout` covers every read and every write, so no exchange can outlive
    /// it no matter what the simulator does.
    ///
    /// # Errors
    ///
    /// As [`SimulatorSession::connect`].
    pub fn connect_within(spec: &str, timeout: Duration) -> Result<Self, Error> {
        let endpoint = Endpoint::parse(spec).map_err(|detail| Self::refuse(spec, &detail))?;
        Self::dial(&endpoint, timeout)
    }

    /// Connects to an already parsed endpoint and powers up.
    ///
    /// # Errors
    ///
    /// As [`SimulatorSession::connect`].
    pub fn dial(endpoint: &Endpoint, timeout: Duration) -> Result<Self, Error> {
        let reader =
            ReaderName::new(format!("{SIMULATOR} {endpoint}")).expect("an endpoint is printable");
        let addrs = (endpoint.host(), endpoint.port())
            .to_socket_addrs()
            .map_err(|err| Self::simulator(&reader, format!("{endpoint} did not resolve: {err}")))?
            .collect::<Vec<SocketAddr>>();
        let stream = addrs
            .iter()
            .find_map(|addr| TcpStream::connect_timeout(addr, timeout).ok())
            .ok_or_else(|| {
                Self::simulator(
                    &reader,
                    format!("{endpoint} accepted no connection ({addrs:?} tried)"),
                )
            })?;
        set_timeouts(&stream, timeout)
            .and_then(|()| stream.set_nodelay(true))
            .map_err(|err| Self::simulator(&reader, format!("{endpoint}: {err}")))?;

        let mut session = Self {
            reader,
            stream,
            atr: Vec::new(),
            released: false,
        };
        // POWER UP opens the session and answers with the ATR of the card
        // behind the connection (`JCSDKClient.apply`, lines 76-85).
        let (code, atr) = session.exchange(CODE_POWER_UP, &[], "power up")?;
        if code != CODE_POWER_UP {
            return Err(session.driver(format!(
                "expected a 0x{CODE_POWER_UP:02X} power up answer, got 0x{code:02X}"
            )));
        }
        session.atr = atr;
        Ok(session)
    }

    /// The ATR the simulator reported when the session was powered up.
    pub fn atr(&self) -> &[u8] {
        &self.atr
    }

    /// One exchange: write one frame, read one frame back.
    fn exchange(&mut self, code: u8, payload: &[u8], what: &str) -> Result<(u8, Vec<u8>), Error> {
        self.write_frame(code, payload, what)?;
        read_frame(&mut self.stream, &self.reader, what)
    }

    /// Writes one frame without waiting for an answer.
    ///
    /// Only POWER DOWN is written this way. The reference server answers 0xF0
    /// and 0x00 with a frame and treats 0xFE as the end of the connection, so
    /// an exchange that waited for one would only ever be waiting for a hangup,
    /// and would report a polite shutdown as a card that went away.
    fn write_frame(&mut self, code: u8, payload: &[u8], what: &str) -> Result<(), Error> {
        let mut header = [0u8; HEADER_LEN];
        header[0] = code;
        header[1..HEADER_LEN].copy_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
        self.stream
            .write_all(&header)
            .and_then(|()| self.stream.write_all(payload))
            .and_then(|()| self.stream.flush())
            .map_err(|err| self.io_error(what, err))
    }

    /// A refusal that is about the simulator itself rather than one exchange.
    fn simulator(reader: &ReaderName, detail: String) -> Error {
        Error::Simulator {
            reader: reader.clone(),
            detail,
        }
    }

    fn refuse(name: &str, detail: &str) -> Error {
        let reader = ReaderName::new(format!("{SIMULATOR} {name}"))
            .expect("a rejected endpoint holds no control character");
        Self::simulator(&reader, detail.to_owned())
    }

    /// A protocol violation: the bytes were not what the framing says.
    fn driver(&self, detail: String) -> Error {
        Self::simulator(&self.reader, detail)
    }

    /// A socket failure, split by what it says about the card.
    fn io_error(&self, what: &str, err: std::io::Error) -> Error {
        if err.kind() == ErrorKind::UnexpectedEof {
            return Error::CardGone {
                reader: self.reader.clone(),
            };
        }
        Self::simulator(&self.reader, format!("{what}: {err}"))
    }
}

impl CardSession for SimulatorSession {
    fn reader(&self) -> &ReaderName {
        &self.reader
    }

    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, Error> {
        if self.released {
            return Err(Error::Disconnected {
                reader: self.reader.clone(),
            });
        }
        if command.len() > MAX_PAYLOAD {
            return Err(self.driver(format!(
                "a {} byte APDU does not fit the frame's 24 bit length",
                command.len()
            )));
        }
        let (code, response) = self.exchange(CODE_APDU, command, "transmit")?;
        if code != CODE_APDU {
            return Err(self.driver(format!(
                "expected a 0x{CODE_APDU:02X} response, got 0x{code:02X}"
            )));
        }
        Ok(response)
    }

    fn disconnect(&mut self) -> Result<(), Error> {
        if self.released {
            return Ok(());
        }
        // POWER DOWN ends the connection, which ends the card with it. It is
        // written and not waited on: the reference treats 0xFE as the end of
        // the session rather than a request with an answer. The session counts
        // as released either way, because failing to be polite about it is not
        // a reason to leave the socket open.
        let result = self.write_frame(CODE_POWER_DOWN, &[], "power down");
        self.released = true;
        let _ = self.stream.shutdown(Shutdown::Both);
        result
    }
}

impl Drop for SimulatorSession {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

/// Gives a socket both a read and a write timeout, so no exchange can hang.
fn set_timeouts(stream: &TcpStream, timeout: Duration) -> std::io::Result<()> {
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))
}

/// Reads exactly one frame: a four byte header, then the payload it names.
fn read_frame(
    stream: &mut TcpStream,
    reader: &ReaderName,
    what: &str,
) -> Result<(u8, Vec<u8>), Error> {
    let mut header = [0u8; HEADER_LEN];
    stream
        .read_exact(&mut header)
        .map_err(|err| io_failure(reader, what, err))?;
    // The high byte is the command code; the length is the low three, which is
    // exactly what `header.getInt(0) & 0xFFFFFF` reads on the other end.
    let code = header[0];
    let len = usize::from(header[1]) << 16 | usize::from(header[2]) << 8 | usize::from(header[3]);
    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .map_err(|err| io_failure(reader, what, err))?;
    Ok((code, payload))
}

/// A hangup is a card that went away; anything else is a failed exchange.
fn io_failure(reader: &ReaderName, what: &str, err: std::io::Error) -> Error {
    if err.kind() == ErrorKind::UnexpectedEof {
        return Error::CardGone {
            reader: reader.clone(),
        };
    }
    Error::Simulator {
        reader: reader.clone(),
        detail: format!("{what}: {err}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::mpsc::{channel, Receiver};
    use std::thread::JoinHandle;
    use std::time::Instant;

    /// A scripted simulator on loopback, started by the test itself.
    ///
    /// Everything here is `127.0.0.1` and one connection: no network, no card
    /// and no daemon. The transcript is the raw byte stream the fake read, so a
    /// test can assert what went on the wire rather than what it meant.
    struct Fake {
        addr: SocketAddr,
        seen: Receiver<Vec<u8>>,
        join: JoinHandle<()>,
    }

    impl Fake {
        /// The endpoint a session should be pointed at.
        fn spec(&self) -> String {
            self.addr.to_string()
        }

        /// Waits for the fake to finish and returns every byte it read.
        fn transcript(self) -> Vec<u8> {
            self.join
                .join()
                .expect("the simulator thread did not panic");
            self.seen.recv().expect("the simulator sent no transcript")
        }
    }

    /// A frame as the reference server writes it: a `uint32` length whose high
    /// byte is overwritten with the command code.
    fn frame(code: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out[0] = code;
        out.extend_from_slice(payload);
        out
    }

    /// Reads one frame off the fake's side of the socket, recording its bytes,
    /// or `None` once the client has hung up.
    fn take_frame(seen: &mut Vec<u8>, stream: &mut TcpStream) -> Option<[u8; HEADER_LEN]> {
        let mut header = [0u8; HEADER_LEN];
        stream.read_exact(&mut header).ok()?;
        seen.extend_from_slice(&header);
        let len =
            usize::from(header[1]) << 16 | usize::from(header[2]) << 8 | usize::from(header[3]);
        let mut payload = vec![0u8; len];
        // A payload that stops short is the peer doing it, not a reason to
        // panic here: callers read a None as "the client stopped talking".
        if stream.read_exact(&mut payload).is_err() {
            return None;
        }
        seen.extend_from_slice(&payload);
        Some(header)
    }

    /// Binds loopback, then runs `script` on the first connection.
    fn fake(script: impl FnOnce(&mut Vec<u8>, &mut TcpStream) + Send + 'static) -> Fake {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let (tx, rx) = channel();
        let join = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            // The fake is a peer, and a peer that blocks forever takes the test
            // run down with it: transcript() joins this thread, so a script
            // waiting for a frame the test never sends would hang the whole
            // binary instead of failing. Bounding the read turns that into a
            // short wait and a None.
            set_timeouts(&stream, FAKE_TIMEOUT).expect("the loopback socket takes timeouts");
            let mut seen = Vec::new();
            script(&mut seen, &mut stream);
            let _ = stream.shutdown(Shutdown::Both);
            let _ = tx.send(seen);
        });
        Fake {
            addr,
            seen: rx,
            join,
        }
    }

    /// A well behaved simulator: answers POWER UP with `atr`, then answers
    /// every APDU with the next scripted response.
    fn scripted(atr: &[u8], responses: &[&[u8]]) -> Fake {
        let atr = atr.to_vec();
        let responses: Vec<Vec<u8>> = responses.iter().map(|r| r.to_vec()).collect();
        fake(move |seen, stream| {
            take_frame(seen, stream);
            stream
                .write_all(&frame(CODE_POWER_UP, atr.as_slice()))
                .unwrap();
            stream.flush().unwrap();
            for response in &responses {
                take_frame(seen, stream).expect("an APDU frame");
                stream
                    .write_all(&frame(CODE_APDU, response.as_slice()))
                    .unwrap();
                stream.flush().unwrap();
            }
            // A simulator waits for the client's POWER DOWN before it hangs up.
            take_frame(seen, stream);
        })
    }

    /// An ATR for a card nobody has: synthetic, and the shortest legal one.
    const ATR: &[u8] = &[0x3B, 0x16, 0x94, 0x00];

    /// How long the fake waits for a frame the test may never send.
    ///
    /// Long enough that a frame which is coming is never missed under load,
    /// short enough that a script waiting for one that is not does not hold
    /// the run open.
    const FAKE_TIMEOUT: Duration = Duration::from_secs(1);

    #[test]
    fn an_endpoint_defaults_to_the_reference_host_and_port() {
        assert_eq!(
            Endpoint::parse("127.0.0.1:9026").unwrap(),
            Endpoint {
                host: "127.0.0.1".to_owned(),
                port: 9026
            }
        );
        assert_eq!(
            Endpoint::parse("").unwrap(),
            Endpoint {
                host: "localhost".to_owned(),
                port: DEFAULT_PORT
            }
        );
        assert_eq!(
            Endpoint::parse("sim.example").unwrap(),
            Endpoint {
                host: "sim.example".to_owned(),
                port: DEFAULT_PORT
            }
        );
        assert_eq!(Endpoint::parse(":9026").unwrap().host(), "localhost");
        assert_eq!(Endpoint::parse(":9026").unwrap().port(), 9026);
        assert_eq!(Endpoint::parse("host:").unwrap().port(), DEFAULT_PORT);
        assert_eq!(
            Endpoint::parse("127.0.0.1:9026").unwrap().to_string(),
            "127.0.0.1:9026"
        );
        assert!(Endpoint::parse("host:0").is_err());
        assert!(Endpoint::parse("host:99999").is_err());
        assert!(Endpoint::parse("host:abc").is_err());
    }

    #[test]
    fn connecting_powers_up_and_reads_the_atr() {
        let sim = scripted(ATR, &[]);
        let spec = sim.spec();
        let session = SimulatorSession::connect(&spec).unwrap();

        assert_eq!(session.atr(), ATR);
        assert_eq!(session.reader().as_str(), format!("simulator {spec}"));
        // Debug text names the endpoint, so a refusal in a log says which
        // simulator answered rather than only that a reader failed.
        assert!(format!("{session:?}").contains(&spec), "{session:?}");
        // POWER UP is the empty 0xF0 frame, and nothing else was sent.
        assert_eq!(sim.transcript(), vec![0xF0, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn an_exchange_is_the_reference_framing_in_both_directions() {
        let sim = scripted(ATR, &[&[0x62, 0x0D, 0x82, 0x02, 0x38, 0x21, 0x90, 0x00]]);
        let spec = sim.spec();
        let mut session = SimulatorSession::connect(&spec).unwrap();

        // SELECT MF
        let response = session
            .transmit(&[0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00])
            .unwrap();

        assert_eq!(
            sim.transcript(),
            vec![
                0xF0, 0x00, 0x00, 0x00, // POWER UP, empty payload
                0x00, 0x00, 0x00, 0x07, // APDU code, then the 7 byte payload length
                0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00, // SELECT MF itself
            ]
        );
        // The answer comes back as its bytes, data and status word alike.
        assert_eq!(
            response,
            vec![0x62, 0x0D, 0x82, 0x02, 0x38, 0x21, 0x90, 0x00]
        );
    }

    #[test]
    fn a_response_is_returned_untouched_including_a_61xx() {
        // 0x61xx is not a final status. A transport that resolved it would make
        // the chaining layer above it impossible to get right.
        let sim = scripted(ATR, &[&[0x61, 0x10]]);
        let spec = sim.spec();
        let mut session = SimulatorSession::connect(&spec).unwrap();
        assert_eq!(
            session.transmit(&[0x00, 0xCA, 0x00, 0x00, 0x00]).unwrap(),
            [0x61, 0x10]
        );
    }

    #[test]
    fn a_status_word_only_answer_is_an_empty_data_body() {
        let sim = scripted(ATR, &[&[0x6A, 0x82]]);
        let spec = sim.spec();
        let mut session = SimulatorSession::connect(&spec).unwrap();
        assert_eq!(
            session.transmit(&[0x00, 0xB0, 0x00, 0x00, 0x02]).unwrap(),
            [0x6A, 0x82]
        );
    }

    #[test]
    fn several_exchanges_are_one_frame_each_in_order() {
        let sim = scripted(ATR, &[&[0x90, 0x00], &[0x61, 0x02], &[0x6D, 0x00]]);
        let spec = sim.spec();
        let mut session = SimulatorSession::connect(&spec).unwrap();
        session
            .transmit(&[0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00])
            .unwrap();
        session.transmit(&[0x00, 0xB0, 0x00, 0x00]).unwrap();
        session.transmit(&[0x00]).unwrap();
        assert_eq!(
            sim.transcript(),
            vec![
                0xF0, 0x00, 0x00, 0x00, //
                0x00, 0x00, 0x00, 0x07, 0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00, //
                0x00, 0x00, 0x00, 0x04, 0x00, 0xB0, 0x00, 0x00, //
                0x00, 0x00, 0x00, 0x01, 0x00, //
            ]
        );
    }

    #[test]
    fn disconnect_sends_power_down_and_is_idempotent() {
        let sim = scripted(ATR, &[]);
        let spec = sim.spec();
        let mut session = SimulatorSession::connect(&spec).unwrap();
        session.disconnect().unwrap();
        session.disconnect().unwrap();
        assert_eq!(
            sim.transcript(),
            vec![0xF0, 0x00, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn a_disconnected_session_refuses_to_transmit() {
        let sim = scripted(ATR, &[]);
        let spec = sim.spec();
        let mut session = SimulatorSession::connect(&spec).unwrap();
        session.disconnect().unwrap();
        let err = session.transmit(&[0x00, 0xA4]).unwrap_err();
        assert!(matches!(err, Error::Disconnected { .. }), "{err}");
        assert!(
            err.to_string().contains("already been disconnected"),
            "{err}"
        );
        sim.transcript();
    }

    #[test]
    fn a_connection_refused_is_reported_rather_than_swallowed() {
        // Bind and drop, so the port is almost certainly free.
        let addr = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let err = SimulatorSession::connect(&addr.to_string()).unwrap_err();
        assert!(matches!(err, Error::Simulator { .. }), "{err}");
        let rendered = err.to_string();
        assert!(rendered.contains(&addr.to_string()), "{rendered}");
        assert!(rendered.contains("accepted no connection"), "{rendered}");
    }

    #[test]
    fn a_hangup_mid_exchange_is_a_transport_error_not_a_short_read() {
        let sim = fake(|seen, stream| {
            take_frame(seen, stream);
            stream.write_all(&frame(CODE_POWER_UP, ATR)).unwrap();
            stream.flush().unwrap();
            // The card goes away with the connection: no frame comes back.
            take_frame(seen, stream);
        });
        let spec = sim.spec();
        let mut session = SimulatorSession::connect(&spec).unwrap();
        let err = session
            .transmit(&[0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00])
            .unwrap_err();
        assert!(matches!(err, Error::CardGone { .. }), "{err}");
        assert!(err.to_string().contains("removed or reset"), "{err}");
        sim.transcript();
    }

    #[test]
    fn a_truncated_response_frame_is_a_transport_error() {
        let sim = fake(|seen, stream| {
            take_frame(seen, stream);
            stream.write_all(&frame(CODE_POWER_UP, ATR)).unwrap();
            stream.flush().unwrap();
            take_frame(seen, stream);
            // A header that promises 8 bytes, followed by 2.
            stream
                .write_all(&[0x00, 0x00, 0x00, 0x08, 0x90, 0x00])
                .unwrap();
            stream.flush().unwrap();
            std::thread::sleep(Duration::from_millis(50));
        });
        let spec = sim.spec();
        let mut session = SimulatorSession::connect(&spec).unwrap();
        let err = session.transmit(&[0x00, 0xA4]).unwrap_err();
        assert!(matches!(err, Error::CardGone { .. }), "{err}");
        sim.transcript();
    }

    #[test]
    fn a_simulator_that_stops_answering_times_out_instead_of_hanging() {
        let sim = fake(|seen, stream| {
            take_frame(seen, stream);
            stream.write_all(&frame(CODE_POWER_UP, ATR)).unwrap();
            stream.flush().unwrap();
            take_frame(seen, stream);
            // No answer, ever: only the read timeout can end this.
            std::thread::sleep(Duration::from_millis(800));
        });
        let spec = sim.spec();
        let mut session =
            SimulatorSession::connect_within(&spec, Duration::from_millis(150)).unwrap();
        let started = Instant::now();
        let err = session.transmit(&[0x00, 0xA4]).unwrap_err();
        assert!(
            started.elapsed() < Duration::from_millis(600),
            "the read was not bounded"
        );
        assert!(matches!(err, Error::Simulator { .. }), "{err}");
        let rendered = err.to_string();
        assert!(rendered.contains("transmit"), "{rendered}");
        assert!(rendered.contains(&spec), "{rendered}");
        sim.transcript();
    }

    #[test]
    fn an_unexpected_frame_code_is_an_error_rather_than_a_response() {
        let sim = fake(|seen, stream| {
            take_frame(seen, stream);
            stream.write_all(&frame(CODE_POWER_UP, ATR)).unwrap();
            stream.flush().unwrap();
            take_frame(seen, stream);
            // A power up answer to an APDU is not an APDU response.
            stream
                .write_all(&frame(CODE_POWER_UP, &[0x90, 0x00]))
                .unwrap();
            stream.flush().unwrap();
            std::thread::sleep(Duration::from_millis(50));
        });
        let spec = sim.spec();
        let mut session = SimulatorSession::connect(&spec).unwrap();
        let err = session.transmit(&[0x00, 0xA4]).unwrap_err();
        assert!(matches!(err, Error::Simulator { .. }), "{err}");
        assert!(
            err.to_string().contains("expected a 0x00 response"),
            "{err}"
        );
        sim.transcript();
    }

    #[test]
    fn a_power_up_that_answers_with_the_wrong_code_is_refused() {
        let sim = fake(|seen, stream| {
            take_frame(seen, stream);
            stream.write_all(&frame(CODE_APDU, ATR)).unwrap();
            stream.flush().unwrap();
            std::thread::sleep(Duration::from_millis(50));
        });
        let spec = sim.spec();
        let err = SimulatorSession::connect(&spec).unwrap_err();
        assert!(matches!(err, Error::Simulator { .. }), "{err}");
        assert!(err.to_string().contains("power up"), "{err}");
        sim.transcript();
    }

    #[test]
    fn a_hangup_before_power_up_is_a_transport_error() {
        let sim = fake(|_seen, _stream| {});
        let spec = sim.spec();
        let err = SimulatorSession::connect(&spec).unwrap_err();
        assert!(matches!(err, Error::CardGone { .. }), "{err}");
        sim.transcript();
    }

    #[test]
    fn an_unparseable_endpoint_never_opens_a_socket() {
        let err = SimulatorSession::connect("host:not-a-port").unwrap_err();
        assert!(matches!(err, Error::Simulator { .. }), "{err}");
        assert!(err.to_string().contains("not a port"), "{err}");
    }

    #[test]
    fn a_frame_carries_its_length_in_the_low_three_bytes() {
        // The reference lays down a uint32 length and overwrites the high byte
        // with the code, so the length is never allowed to reach the high byte.
        assert_eq!(
            frame(CODE_APDU, &[0xAB, 0xCD]),
            [0x00, 0x00, 0x00, 0x02, 0xAB, 0xCD]
        );
        assert_eq!(
            frame(CODE_POWER_UP, &[0x01, 0x02]),
            [0xF0, 0x00, 0x00, 0x02, 0x01, 0x02]
        );
        assert_eq!(frame(CODE_POWER_DOWN, &[]), [0xFE, 0x00, 0x00, 0x00]);
        assert_eq!(MAX_PAYLOAD, 0xFF_FFFF);
    }

    #[test]
    fn a_simulator_session_is_a_card_session() {
        let sim = scripted(ATR, &[&[0x90, 0x00]]);
        let spec = sim.spec();
        let mut session: Box<dyn CardSession> = Box::new(SimulatorSession::connect(&spec).unwrap());
        assert_eq!(session.reader().as_str(), format!("simulator {spec}"));
        assert_eq!(session.transmit(&[0x00, 0xA4]).unwrap(), [0x90, 0x00]);
        session.disconnect().unwrap();
        sim.transcript();
    }
}
