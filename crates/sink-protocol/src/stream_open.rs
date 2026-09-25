//! Additive per-stream framing for raw TCP tunnels.
//!
//! Legacy HTTP streams have no preamble. A raw stream begins with:
//!
//! ```text
//! 0..8   "SINK\0TCP"
//! 8      preamble version (1)
//! 9      stream kind (1 = raw TCP)
//! 10..12 big-endian payload length
//! payload:
//!   u16 route-hostname length, route-hostname bytes,
//!   source socket, destination socket
//! socket:
//!   u8 family (4 or 6), 4 or 16 IP bytes, u16 big-endian port
//! ```

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use futures::{AsyncRead, AsyncReadExt as _};
use thiserror::Error;

/// Magic prefix for the additive raw-stream preamble.
pub const RAW_STREAM_OPEN_MAGIC: [u8; 8] = *b"SINK\0TCP";

/// Version of the raw-stream preamble, independent of the control handshake version.
pub const RAW_STREAM_OPEN_VERSION: u8 = 1;

/// Stream-kind discriminator for raw TCP.
pub const RAW_TCP_STREAM_KIND: u8 = 1;

/// Fixed bytes before the variable raw-stream payload.
pub const RAW_STREAM_OPEN_PREFIX_BYTES: usize = 12;

/// Maximum complete raw-stream preamble, including its fixed header.
pub const MAX_STREAM_OPEN_BYTES: usize = 512;

/// Maximum route hostname carried by a raw-stream preamble.
pub const MAX_ROUTE_HOSTNAME_BYTES: usize = 253;

/// Per-yamux-stream opening behavior.
///
/// `LegacyHttp` deliberately encodes to zero bytes. Existing HTTP, WebSocket,
/// upgrade, and streaming exchanges therefore continue to start directly with
/// their HTTP bytes. Only `RawTcp` streams carry the versioned preamble.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StreamOpen {
    LegacyHttp,
    RawTcp(RawTcpStreamOpen),
}

impl StreamOpen {
    /// Encode the bytes that precede application data on this stream.
    pub fn encode(&self) -> Result<Vec<u8>, StreamOpenError> {
        match self {
            Self::LegacyHttp => Ok(Vec::new()),
            Self::RawTcp(open) => open.encode(),
        }
    }
}

/// Trusted metadata sent by the server before bytes on a raw TCP stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawTcpStreamOpen {
    route_hostname: String,
    source: SocketAddr,
    destination: SocketAddr,
}

impl RawTcpStreamOpen {
    pub fn new(
        route_hostname: impl Into<String>,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> Result<Self, StreamOpenError> {
        let route_hostname = route_hostname.into();
        validate_route_hostname(&route_hostname)?;
        validate_socket(source)?;
        validate_socket(destination)?;
        Ok(Self {
            route_hostname,
            source,
            destination,
        })
    }

    #[must_use]
    pub fn route_hostname(&self) -> &str {
        &self.route_hostname
    }

    #[must_use]
    pub const fn source(&self) -> SocketAddr {
        self.source
    }

    #[must_use]
    pub const fn destination(&self) -> SocketAddr {
        self.destination
    }

    #[must_use]
    pub fn into_parts(self) -> (String, SocketAddr, SocketAddr) {
        (self.route_hostname, self.source, self.destination)
    }

    /// Encode this raw TCP opening preamble.
    pub fn encode(&self) -> Result<Vec<u8>, StreamOpenError> {
        validate_route_hostname(&self.route_hostname)?;
        validate_socket(self.source)?;
        validate_socket(self.destination)?;

        let route_bytes = self.route_hostname.as_bytes();
        let payload_bytes = 2_usize
            .saturating_add(route_bytes.len())
            .saturating_add(encoded_socket_len(self.source))
            .saturating_add(encoded_socket_len(self.destination));
        let total_bytes = RAW_STREAM_OPEN_PREFIX_BYTES.saturating_add(payload_bytes);
        if total_bytes > MAX_STREAM_OPEN_BYTES || payload_bytes > usize::from(u16::MAX) {
            return Err(StreamOpenError::FrameTooLong {
                declared: total_bytes,
                maximum: MAX_STREAM_OPEN_BYTES,
            });
        }

        let mut encoded = Vec::with_capacity(total_bytes);
        encoded.extend_from_slice(&RAW_STREAM_OPEN_MAGIC);
        encoded.push(RAW_STREAM_OPEN_VERSION);
        encoded.push(RAW_TCP_STREAM_KIND);
        encoded.extend_from_slice(&(payload_bytes as u16).to_be_bytes());
        encoded.extend_from_slice(&(route_bytes.len() as u16).to_be_bytes());
        encoded.extend_from_slice(route_bytes);
        encode_socket(&mut encoded, self.source);
        encode_socket(&mut encoded, self.destination);
        debug_assert_eq!(encoded.len(), total_bytes);
        Ok(encoded)
    }
}

/// A decoded raw-stream preamble and the application bytes after it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedRawStreamOpen<'a> {
    pub open: RawTcpStreamOpen,
    pub remaining: &'a [u8],
}

/// Decode one complete raw-stream preamble from the start of `input`.
///
/// The returned `remaining` slice begins at the byte immediately following the
/// declared preamble. It is never copied or rewritten.
pub fn decode_raw_stream_open(input: &[u8]) -> Result<DecodedRawStreamOpen<'_>, StreamOpenError> {
    let total_bytes = raw_stream_frame_len(input)?;
    if input.len() < total_bytes {
        return Err(StreamOpenError::Incomplete {
            needed: total_bytes,
        });
    }

    let payload = &input[RAW_STREAM_OPEN_PREFIX_BYTES..total_bytes];
    let mut cursor = 0;
    let route_len = usize::from(read_u16(payload, &mut cursor)?);
    let route_bytes = take(payload, &mut cursor, route_len)?;
    let route_hostname = std::str::from_utf8(route_bytes)
        .map_err(|_| StreamOpenError::InvalidRouteEncoding)?
        .to_owned();
    validate_route_hostname(&route_hostname)?;

    let source = decode_socket(payload, &mut cursor)?;
    let destination = decode_socket(payload, &mut cursor)?;
    if cursor != payload.len() {
        return Err(StreamOpenError::TrailingPayload {
            bytes: payload.len() - cursor,
        });
    }

    Ok(DecodedRawStreamOpen {
        open: RawTcpStreamOpen {
            route_hostname,
            source,
            destination,
        },
        remaining: &input[total_bytes..],
    })
}

/// Read exactly one raw-stream preamble without reading any following bytes.
///
/// Callers retain timeout and cancellation policy. The fixed stack buffer makes
/// allocation independent of an untrusted declared length.
pub async fn read_raw_stream_open<R>(
    reader: &mut R,
) -> Result<RawTcpStreamOpen, StreamOpenReadError>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = [0_u8; MAX_STREAM_OPEN_BYTES];
    reader
        .read_exact(&mut buffer[..RAW_STREAM_OPEN_PREFIX_BYTES])
        .await
        .map_err(StreamOpenReadError::Io)?;
    let total_bytes = raw_stream_frame_len(&buffer[..RAW_STREAM_OPEN_PREFIX_BYTES])?;
    reader
        .read_exact(&mut buffer[RAW_STREAM_OPEN_PREFIX_BYTES..total_bytes])
        .await
        .map_err(StreamOpenReadError::Io)?;
    Ok(decode_raw_stream_open(&buffer[..total_bytes])?.open)
}

fn raw_stream_frame_len(input: &[u8]) -> Result<usize, StreamOpenError> {
    let comparable = input.len().min(RAW_STREAM_OPEN_MAGIC.len());
    if input[..comparable] != RAW_STREAM_OPEN_MAGIC[..comparable] {
        return Err(StreamOpenError::InvalidMagic);
    }
    if input.len() < RAW_STREAM_OPEN_PREFIX_BYTES {
        return Err(StreamOpenError::Incomplete {
            needed: RAW_STREAM_OPEN_PREFIX_BYTES,
        });
    }
    if input[8] != RAW_STREAM_OPEN_VERSION {
        return Err(StreamOpenError::UnsupportedVersion { received: input[8] });
    }
    if input[9] != RAW_TCP_STREAM_KIND {
        return Err(StreamOpenError::UnsupportedKind { received: input[9] });
    }
    let payload_bytes = usize::from(u16::from_be_bytes([input[10], input[11]]));
    let total_bytes = RAW_STREAM_OPEN_PREFIX_BYTES.saturating_add(payload_bytes);
    if total_bytes > MAX_STREAM_OPEN_BYTES {
        return Err(StreamOpenError::FrameTooLong {
            declared: total_bytes,
            maximum: MAX_STREAM_OPEN_BYTES,
        });
    }
    Ok(total_bytes)
}

fn validate_route_hostname(hostname: &str) -> Result<(), StreamOpenError> {
    if hostname.is_empty()
        || hostname.len() > MAX_ROUTE_HOSTNAME_BYTES
        || !hostname.is_ascii()
        || hostname.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(StreamOpenError::InvalidRouteHostname);
    }
    Ok(())
}

fn validate_socket(address: SocketAddr) -> Result<(), StreamOpenError> {
    if let SocketAddr::V6(address) = address
        && (address.flowinfo() != 0 || address.scope_id() != 0)
    {
        return Err(StreamOpenError::UnsupportedIpv6Scope);
    }
    Ok(())
}

const fn encoded_socket_len(address: SocketAddr) -> usize {
    match address {
        SocketAddr::V4(_) => 7,
        SocketAddr::V6(_) => 19,
    }
}

fn encode_socket(output: &mut Vec<u8>, address: SocketAddr) {
    match address.ip() {
        IpAddr::V4(ip) => {
            output.push(4);
            output.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            output.push(6);
            output.extend_from_slice(&ip.octets());
        }
    }
    output.extend_from_slice(&address.port().to_be_bytes());
}

fn decode_socket(payload: &[u8], cursor: &mut usize) -> Result<SocketAddr, StreamOpenError> {
    let family = take(payload, cursor, 1)?[0];
    let ip = match family {
        4 => {
            let octets = take(payload, cursor, 4)?;
            IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
        }
        6 => {
            let octets = take(payload, cursor, 16)?;
            let mut address = [0_u8; 16];
            address.copy_from_slice(octets);
            IpAddr::V6(Ipv6Addr::from(address))
        }
        received => return Err(StreamOpenError::UnsupportedAddressFamily { received }),
    };
    let port = read_u16(payload, cursor)?;
    Ok(SocketAddr::new(ip, port))
}

fn read_u16(input: &[u8], cursor: &mut usize) -> Result<u16, StreamOpenError> {
    let bytes = take(input, cursor, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn take<'a>(
    input: &'a [u8],
    cursor: &mut usize,
    count: usize,
) -> Result<&'a [u8], StreamOpenError> {
    let end = cursor
        .checked_add(count)
        .ok_or(StreamOpenError::InvalidPayloadLength)?;
    let value = input
        .get(*cursor..end)
        .ok_or(StreamOpenError::InvalidPayloadLength)?;
    *cursor = end;
    Ok(value)
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum StreamOpenError {
    #[error("raw-stream preamble is incomplete; {needed} total bytes are required")]
    Incomplete { needed: usize },
    #[error("raw-stream preamble magic is invalid")]
    InvalidMagic,
    #[error("unsupported raw-stream preamble version {received}")]
    UnsupportedVersion { received: u8 },
    #[error("unsupported stream-open kind {received}")]
    UnsupportedKind { received: u8 },
    #[error("raw-stream preamble is {declared} bytes; maximum is {maximum}")]
    FrameTooLong { declared: usize, maximum: usize },
    #[error("raw-stream route is not valid UTF-8")]
    InvalidRouteEncoding,
    #[error("raw-stream route hostname is invalid")]
    InvalidRouteHostname,
    #[error("unsupported socket address family {received}")]
    UnsupportedAddressFamily { received: u8 },
    #[error("raw-stream socket metadata cannot carry IPv6 flowinfo or scope identifiers")]
    UnsupportedIpv6Scope,
    #[error("raw-stream preamble payload has an invalid length")]
    InvalidPayloadLength,
    #[error("raw-stream preamble has {bytes} trailing payload bytes")]
    TrailingPayload { bytes: usize },
}

#[derive(Debug, Error)]
pub enum StreamOpenReadError {
    #[error("could not read raw-stream preamble")]
    Io(#[source] io::Error),
    #[error(transparent)]
    Protocol(#[from] StreamOpenError),
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use futures::{AsyncRead, AsyncReadExt as _, executor::block_on};
    use uuid::Uuid;

    use crate::{ClientHello, PROTOCOL_VERSION};

    use super::*;

    #[test]
    fn legacy_http_has_no_stream_preamble_and_keeps_v1_handshake()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(StreamOpen::LegacyHttp.encode()?.is_empty());
        assert_eq!(PROTOCOL_VERSION, 1);

        let hello = ClientHello::new(
            Uuid::parse_str("f3ebc60f-6e4f-45b9-836e-3d1ed9c76e58")?,
            Some("demo.example.com".to_owned()),
            "0.3.1",
        );
        assert_eq!(
            serde_json::to_string(&hello)?,
            r#"{"protocol_version":1,"session_id":"f3ebc60f-6e4f-45b9-836e-3d1ed9c76e58","requested_hostname":"demo.example.com","client_version":"0.3.1"}"#
        );
        Ok(())
    }

    #[test]
    fn raw_stream_v4_wire_bytes_are_stable_and_preserve_tail()
    -> Result<(), Box<dyn std::error::Error>> {
        let open = RawTcpStreamOpen::new(
            "edge.example.com",
            "192.0.2.10:42311".parse()?,
            "198.51.100.7:443".parse()?,
        )?;
        let encoded = open.encode()?;
        let mut expected = b"SINK\0TCP\x01\x01\x00\x20\x00\x10edge.example.com\x04\xc0\x00\x02\x0a\xa5\x47\x04\xc6\x33\x64\x07\x01\xbb".to_vec();
        assert_eq!(encoded, expected);

        expected.extend_from_slice(b"\x16\x03\x01client-hello");
        let decoded = decode_raw_stream_open(&expected)?;
        assert_eq!(decoded.open, open);
        assert_eq!(decoded.remaining, b"\x16\x03\x01client-hello");
        Ok(())
    }

    #[test]
    fn raw_stream_supports_independent_ipv6_socket_addresses()
    -> Result<(), Box<dyn std::error::Error>> {
        let open = RawTcpStreamOpen::new(
            "v6.example.com",
            "[2001:db8::1]:50000".parse()?,
            "[2001:db8::2]:443".parse()?,
        )?;
        let encoded = open.encode()?;
        let decoded = decode_raw_stream_open(&encoded)?;
        assert_eq!(decoded.open, open);
        assert!(decoded.remaining.is_empty());
        Ok(())
    }

    #[test]
    fn exact_reader_handles_one_byte_fragments_without_consuming_tls()
    -> Result<(), Box<dyn std::error::Error>> {
        block_on(async {
            let open = RawTcpStreamOpen::new(
                "fragmented.example.com",
                "203.0.113.8:55123".parse()?,
                "203.0.113.9:443".parse()?,
            )?;
            let mut bytes = open.encode()?;
            let tls = b"\x16\x03\x03\x00\x05hello";
            bytes.extend_from_slice(tls);
            let mut reader = FragmentedReader::new(bytes, 1);

            assert_eq!(read_raw_stream_open(&mut reader).await?, open);
            let mut remaining = Vec::new();
            reader.read_to_end(&mut remaining).await?;
            assert_eq!(remaining, tls);
            Ok::<_, Box<dyn std::error::Error>>(())
        })
    }

    #[test]
    fn rejects_invalid_envelope_and_payload_shapes() -> Result<(), Box<dyn std::error::Error>> {
        let open = RawTcpStreamOpen::new(
            "edge.example.com",
            "192.0.2.1:1234".parse()?,
            "192.0.2.2:443".parse()?,
        )?;
        let encoded = open.encode()?;

        assert_eq!(
            decode_raw_stream_open(&encoded[..7]),
            Err(StreamOpenError::Incomplete { needed: 12 })
        );
        let mut invalid = encoded.clone();
        invalid[0] ^= 1;
        assert_eq!(
            decode_raw_stream_open(&invalid),
            Err(StreamOpenError::InvalidMagic)
        );
        let mut invalid = encoded.clone();
        invalid[8] = 2;
        assert_eq!(
            decode_raw_stream_open(&invalid),
            Err(StreamOpenError::UnsupportedVersion { received: 2 })
        );
        let mut invalid = encoded.clone();
        invalid[9] = 2;
        assert_eq!(
            decode_raw_stream_open(&invalid),
            Err(StreamOpenError::UnsupportedKind { received: 2 })
        );
        let mut invalid = encoded.clone();
        invalid[10..12].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(matches!(
            decode_raw_stream_open(&invalid),
            Err(StreamOpenError::FrameTooLong { .. })
        ));
        let mut invalid = encoded.clone();
        let address_family = RAW_STREAM_OPEN_PREFIX_BYTES + 2 + "edge.example.com".len();
        invalid[address_family] = 9;
        assert_eq!(
            decode_raw_stream_open(&invalid),
            Err(StreamOpenError::UnsupportedAddressFamily { received: 9 })
        );
        let mut invalid = encoded;
        let payload_len = u16::from_be_bytes([invalid[10], invalid[11]]) + 1;
        invalid[10..12].copy_from_slice(&payload_len.to_be_bytes());
        invalid.push(0);
        assert_eq!(
            decode_raw_stream_open(&invalid),
            Err(StreamOpenError::TrailingPayload { bytes: 1 })
        );
        Ok(())
    }

    #[test]
    fn route_hostname_and_frame_are_bounded_before_encoding()
    -> Result<(), Box<dyn std::error::Error>> {
        let longest = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(longest.len(), MAX_ROUTE_HOSTNAME_BYTES);
        let open = RawTcpStreamOpen::new(
            longest,
            "[2001:db8::1]:1234".parse()?,
            "[2001:db8::2]:443".parse()?,
        )?;
        assert!(open.encode()?.len() <= MAX_STREAM_OPEN_BYTES);
        assert_eq!(
            RawTcpStreamOpen::new(
                "a".repeat(MAX_ROUTE_HOSTNAME_BYTES + 1),
                "192.0.2.1:1".parse()?,
                "192.0.2.2:2".parse()?,
            ),
            Err(StreamOpenError::InvalidRouteHostname)
        );
        Ok(())
    }

    #[test]
    fn rejects_ipv6_scope_metadata_that_the_wire_cannot_preserve() {
        let scoped = SocketAddr::V6(std::net::SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1234, 1, 2));
        assert_eq!(
            RawTcpStreamOpen::new("edge.example.com", scoped, scoped),
            Err(StreamOpenError::UnsupportedIpv6Scope)
        );
    }

    struct FragmentedReader {
        bytes: Vec<u8>,
        position: usize,
        max_chunk: usize,
    }

    impl FragmentedReader {
        fn new(bytes: Vec<u8>, max_chunk: usize) -> Self {
            Self {
                bytes,
                position: 0,
                max_chunk,
            }
        }
    }

    impl AsyncRead for FragmentedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            output: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            if self.position == self.bytes.len() {
                return Poll::Ready(Ok(0));
            }
            let count = output
                .len()
                .min(self.max_chunk)
                .min(self.bytes.len() - self.position);
            output[..count].copy_from_slice(&self.bytes[self.position..self.position + count]);
            self.position += count;
            Poll::Ready(Ok(count))
        }
    }
}
