//! Bounded PROXY Protocol v2 parsing and fresh-header encoding.
//!
//! Parsing accepts only the standard v2 signature and the `LOCAL` or `PROXY`
//! commands. `PROXY` is restricted to TCP/STREAM over IPv4 or IPv6. Supported
//! address blocks may be followed by structurally valid TLVs, which are
//! consumed but not propagated. `LOCAL` payloads remain opaque as the protocol
//! requires. Every accepted header is at most [`MAX_PROXY_V2_HEADER_BYTES`].

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use futures::{AsyncRead, AsyncReadExt as _};
use thiserror::Error;

/// Binary PROXY Protocol v2 signature.
pub const PROXY_V2_SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";

/// Fixed bytes before the variable PROXY v2 payload.
pub const PROXY_V2_PREFIX_BYTES: usize = 16;

/// Maximum accepted complete PROXY v2 header, including the fixed prefix.
///
/// Sink needs only TCP socket metadata and small optional TLVs. Keeping this
/// substantially below the protocol's theoretical `u16` payload prevents an
/// ingress peer from forcing large buffering before TLS dispatch.
pub const MAX_PROXY_V2_HEADER_BYTES: usize = 512;

const VERSION: u8 = 2;
const COMMAND_LOCAL: u8 = 0;
const COMMAND_PROXY: u8 = 1;
const FAMILY_INET: u8 = 1;
const FAMILY_INET6: u8 = 2;
const TRANSPORT_STREAM: u8 = 1;
const IPV4_ADDRESS_BYTES: usize = 12;
const IPV6_ADDRESS_BYTES: usize = 36;

/// Trusted result of a bounded PROXY v2 parse.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProxyV2Header {
    /// The sender explicitly declined to provide relayed addresses. The payload
    /// and family/protocol byte are opaque by specification and are ignored.
    Local,
    /// Original endpoints supplied by a trusted TCP proxy.
    Proxy {
        source: SocketAddr,
        destination: SocketAddr,
    },
}

impl ProxyV2Header {
    /// Construct a fresh TCP/STREAM header. PROXY v2 requires both endpoints to
    /// use the same address family.
    pub fn proxied(source: SocketAddr, destination: SocketAddr) -> Result<Self, ProxyV2Error> {
        ensure_matching_families(source, destination)?;
        Ok(Self::Proxy {
            source,
            destination,
        })
    }

    #[must_use]
    pub const fn local() -> Self {
        Self::Local
    }

    #[must_use]
    pub const fn source(&self) -> Option<SocketAddr> {
        match self {
            Self::Local => None,
            Self::Proxy { source, .. } => Some(*source),
        }
    }

    #[must_use]
    pub const fn destination(&self) -> Option<SocketAddr> {
        match self {
            Self::Local => None,
            Self::Proxy { destination, .. } => Some(*destination),
        }
    }

    /// Encode a fresh header without copying any inbound TLVs.
    pub fn encode(&self) -> Result<Vec<u8>, ProxyV2Error> {
        let mut output = Vec::with_capacity(match self {
            Self::Local => PROXY_V2_PREFIX_BYTES,
            Self::Proxy { source, .. } if source.is_ipv4() => {
                PROXY_V2_PREFIX_BYTES + IPV4_ADDRESS_BYTES
            }
            Self::Proxy { .. } => PROXY_V2_PREFIX_BYTES + IPV6_ADDRESS_BYTES,
        });
        output.extend_from_slice(&PROXY_V2_SIGNATURE);
        match self {
            Self::Local => {
                output.push((VERSION << 4) | COMMAND_LOCAL);
                output.push(0);
                output.extend_from_slice(&0_u16.to_be_bytes());
            }
            Self::Proxy {
                source,
                destination,
            } => {
                ensure_matching_families(*source, *destination)?;
                output.push((VERSION << 4) | COMMAND_PROXY);
                match (source.ip(), destination.ip()) {
                    (IpAddr::V4(source_ip), IpAddr::V4(destination_ip)) => {
                        output.push((FAMILY_INET << 4) | TRANSPORT_STREAM);
                        output.extend_from_slice(&(IPV4_ADDRESS_BYTES as u16).to_be_bytes());
                        output.extend_from_slice(&source_ip.octets());
                        output.extend_from_slice(&destination_ip.octets());
                    }
                    (IpAddr::V6(source_ip), IpAddr::V6(destination_ip)) => {
                        output.push((FAMILY_INET6 << 4) | TRANSPORT_STREAM);
                        output.extend_from_slice(&(IPV6_ADDRESS_BYTES as u16).to_be_bytes());
                        output.extend_from_slice(&source_ip.octets());
                        output.extend_from_slice(&destination_ip.octets());
                    }
                    _ => return Err(ProxyV2Error::AddressFamilyMismatch),
                }
                output.extend_from_slice(&source.port().to_be_bytes());
                output.extend_from_slice(&destination.port().to_be_bytes());
            }
        }
        debug_assert!(output.len() <= MAX_PROXY_V2_HEADER_BYTES);
        Ok(output)
    }
}

/// A parsed PROXY v2 header and the untouched bytes following it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedProxyV2<'a> {
    pub header: ProxyV2Header,
    pub remaining: &'a [u8],
}

/// Parse one bounded PROXY v2 header at the beginning of `input`.
///
/// Unknown, structurally valid TLVs are consumed but intentionally not
/// propagated. A `LOCAL` payload is opaque as required by the protocol. The
/// returned `remaining` slice is byte-identical to the input after the header.
pub fn parse_proxy_v2(input: &[u8]) -> Result<ParsedProxyV2<'_>, ProxyV2Error> {
    let total_bytes = proxy_v2_frame_len(input)?;
    if input.len() < total_bytes {
        return Err(ProxyV2Error::Incomplete {
            needed: total_bytes,
        });
    }

    let command = input[12] & 0x0f;
    if command == COMMAND_LOCAL {
        return Ok(ParsedProxyV2 {
            header: ProxyV2Header::Local,
            remaining: &input[total_bytes..],
        });
    }

    let family = input[13] >> 4;
    let transport = input[13] & 0x0f;
    if transport != TRANSPORT_STREAM {
        return Err(ProxyV2Error::UnsupportedTransportProtocol {
            received: transport,
        });
    }

    let payload = &input[PROXY_V2_PREFIX_BYTES..total_bytes];
    let (source, destination, address_bytes) = match family {
        FAMILY_INET => parse_ipv4_addresses(payload)?,
        FAMILY_INET6 => parse_ipv6_addresses(payload)?,
        received => return Err(ProxyV2Error::UnsupportedAddressFamily { received }),
    };
    validate_tlvs(&payload[address_bytes..], address_bytes)?;

    Ok(ParsedProxyV2 {
        header: ProxyV2Header::Proxy {
            source,
            destination,
        },
        remaining: &input[total_bytes..],
    })
}

/// Read exactly one bounded PROXY v2 header without reading ClientHello bytes.
///
/// Callers own timeout and cancellation policy. The parser uses a fixed stack
/// buffer and rejects oversized declared lengths before reading the payload.
pub async fn read_proxy_v2<R>(reader: &mut R) -> Result<ProxyV2Header, ProxyV2ReadError>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = [0_u8; MAX_PROXY_V2_HEADER_BYTES];
    reader
        .read_exact(&mut buffer[..PROXY_V2_PREFIX_BYTES])
        .await
        .map_err(ProxyV2ReadError::Io)?;
    let total_bytes = proxy_v2_frame_len(&buffer[..PROXY_V2_PREFIX_BYTES])?;
    reader
        .read_exact(&mut buffer[PROXY_V2_PREFIX_BYTES..total_bytes])
        .await
        .map_err(ProxyV2ReadError::Io)?;
    Ok(parse_proxy_v2(&buffer[..total_bytes])?.header)
}

fn proxy_v2_frame_len(input: &[u8]) -> Result<usize, ProxyV2Error> {
    let comparable = input.len().min(PROXY_V2_SIGNATURE.len());
    if input[..comparable] != PROXY_V2_SIGNATURE[..comparable] {
        return Err(ProxyV2Error::InvalidSignature);
    }
    if input.len() < PROXY_V2_PREFIX_BYTES {
        return Err(ProxyV2Error::Incomplete {
            needed: PROXY_V2_PREFIX_BYTES,
        });
    }

    let version = input[12] >> 4;
    if version != VERSION {
        return Err(ProxyV2Error::UnsupportedVersion { received: version });
    }
    let command = input[12] & 0x0f;
    if command != COMMAND_LOCAL && command != COMMAND_PROXY {
        return Err(ProxyV2Error::UnsupportedCommand { received: command });
    }

    let payload_bytes = usize::from(u16::from_be_bytes([input[14], input[15]]));
    let total_bytes = PROXY_V2_PREFIX_BYTES.saturating_add(payload_bytes);
    if total_bytes > MAX_PROXY_V2_HEADER_BYTES {
        return Err(ProxyV2Error::HeaderTooLong {
            declared: total_bytes,
            maximum: MAX_PROXY_V2_HEADER_BYTES,
        });
    }
    Ok(total_bytes)
}

fn parse_ipv4_addresses(payload: &[u8]) -> Result<(SocketAddr, SocketAddr, usize), ProxyV2Error> {
    if payload.len() < IPV4_ADDRESS_BYTES {
        return Err(ProxyV2Error::InvalidAddressLength {
            family: FAMILY_INET,
            declared: payload.len(),
            minimum: IPV4_ADDRESS_BYTES,
        });
    }
    let source_ip = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
    let destination_ip = Ipv4Addr::new(payload[4], payload[5], payload[6], payload[7]);
    let source_port = u16::from_be_bytes([payload[8], payload[9]]);
    let destination_port = u16::from_be_bytes([payload[10], payload[11]]);
    Ok((
        SocketAddr::new(IpAddr::V4(source_ip), source_port),
        SocketAddr::new(IpAddr::V4(destination_ip), destination_port),
        IPV4_ADDRESS_BYTES,
    ))
}

fn parse_ipv6_addresses(payload: &[u8]) -> Result<(SocketAddr, SocketAddr, usize), ProxyV2Error> {
    if payload.len() < IPV6_ADDRESS_BYTES {
        return Err(ProxyV2Error::InvalidAddressLength {
            family: FAMILY_INET6,
            declared: payload.len(),
            minimum: IPV6_ADDRESS_BYTES,
        });
    }
    let mut source_octets = [0_u8; 16];
    source_octets.copy_from_slice(&payload[..16]);
    let mut destination_octets = [0_u8; 16];
    destination_octets.copy_from_slice(&payload[16..32]);
    let source_port = u16::from_be_bytes([payload[32], payload[33]]);
    let destination_port = u16::from_be_bytes([payload[34], payload[35]]);
    Ok((
        SocketAddr::new(IpAddr::V6(Ipv6Addr::from(source_octets)), source_port),
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from(destination_octets)),
            destination_port,
        ),
        IPV6_ADDRESS_BYTES,
    ))
}

fn validate_tlvs(mut input: &[u8], mut offset: usize) -> Result<(), ProxyV2Error> {
    while !input.is_empty() {
        if input.len() < 3 {
            return Err(ProxyV2Error::MalformedTlv { offset });
        }
        let value_bytes = usize::from(u16::from_be_bytes([input[1], input[2]]));
        let tlv_bytes = 3_usize.saturating_add(value_bytes);
        if input.len() < tlv_bytes {
            return Err(ProxyV2Error::MalformedTlv { offset });
        }
        input = &input[tlv_bytes..];
        offset = offset.saturating_add(tlv_bytes);
    }
    Ok(())
}

fn ensure_matching_families(
    source: SocketAddr,
    destination: SocketAddr,
) -> Result<(), ProxyV2Error> {
    for address in [source, destination] {
        if let SocketAddr::V6(address) = address
            && (address.flowinfo() != 0 || address.scope_id() != 0)
        {
            return Err(ProxyV2Error::UnsupportedIpv6Scope);
        }
    }
    if source.is_ipv4() != destination.is_ipv4() {
        return Err(ProxyV2Error::AddressFamilyMismatch);
    }
    Ok(())
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProxyV2Error {
    #[error("PROXY v2 header is incomplete; {needed} total bytes are required")]
    Incomplete { needed: usize },
    #[error("PROXY v2 signature is invalid")]
    InvalidSignature,
    #[error("unsupported PROXY protocol version {received}")]
    UnsupportedVersion { received: u8 },
    #[error("unsupported PROXY v2 command {received}")]
    UnsupportedCommand { received: u8 },
    #[error("unsupported PROXY v2 address family {received}")]
    UnsupportedAddressFamily { received: u8 },
    #[error("unsupported PROXY v2 transport protocol {received}")]
    UnsupportedTransportProtocol { received: u8 },
    #[error("PROXY v2 source and destination address families differ")]
    AddressFamilyMismatch,
    #[error("PROXY v2 cannot encode IPv6 flowinfo or scope identifiers")]
    UnsupportedIpv6Scope,
    #[error("PROXY v2 header is {declared} bytes; maximum is {maximum}")]
    HeaderTooLong { declared: usize, maximum: usize },
    #[error("PROXY v2 family {family} address block is {declared} bytes; minimum is {minimum}")]
    InvalidAddressLength {
        family: u8,
        declared: usize,
        minimum: usize,
    },
    #[error("malformed PROXY v2 TLV at payload offset {offset}")]
    MalformedTlv { offset: usize },
}

#[derive(Debug, Error)]
pub enum ProxyV2ReadError {
    #[error("could not read PROXY v2 header")]
    Io(#[source] io::Error),
    #[error(transparent)]
    Protocol(#[from] ProxyV2Error),
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use futures::{AsyncRead, AsyncReadExt as _, executor::block_on};

    use super::*;

    #[test]
    fn ipv4_encode_is_wire_exact_and_tail_is_untouched() -> Result<(), Box<dyn std::error::Error>> {
        let header =
            ProxyV2Header::proxied("192.0.2.1:42311".parse()?, "198.51.100.7:443".parse()?)?;
        let encoded = header.encode()?;
        assert_eq!(
            encoded,
            b"\r\n\r\n\0\r\nQUIT\n\x21\x11\x00\x0c\xc0\x00\x02\x01\xc6\x33\x64\x07\xa5\x47\x01\xbb"
        );

        let mut input = encoded;
        input.extend_from_slice(b"\x16\x03\x01client-hello");
        let parsed = parse_proxy_v2(&input)?;
        assert_eq!(parsed.header, header);
        assert_eq!(parsed.remaining, b"\x16\x03\x01client-hello");
        Ok(())
    }

    #[test]
    fn ipv6_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let header =
            ProxyV2Header::proxied("[2001:db8::1]:50000".parse()?, "[2001:db8::2]:443".parse()?)?;
        let encoded = header.encode()?;
        assert_eq!(encoded.len(), PROXY_V2_PREFIX_BYTES + IPV6_ADDRESS_BYTES);
        let parsed = parse_proxy_v2(&encoded)?;
        assert_eq!(parsed.header, header);
        assert!(parsed.remaining.is_empty());
        Ok(())
    }

    #[test]
    fn local_is_explicit_and_ignores_opaque_family_and_payload()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut input = PROXY_V2_SIGNATURE.to_vec();
        input.extend_from_slice(&[0x20, 0xff, 0x00, 0x02, 0xde, 0xad]);
        input.extend_from_slice(b"tls");
        let parsed = parse_proxy_v2(&input)?;
        assert_eq!(parsed.header, ProxyV2Header::Local);
        assert_eq!(parsed.remaining, b"tls");
        assert_eq!(
            ProxyV2Header::local().encode()?.len(),
            PROXY_V2_PREFIX_BYTES
        );
        Ok(())
    }

    #[test]
    fn accepts_unknown_well_formed_tlvs_but_rejects_malformed_tlvs()
    -> Result<(), Box<dyn std::error::Error>> {
        let header = ProxyV2Header::proxied("192.0.2.1:1234".parse()?, "192.0.2.2:443".parse()?)?;
        let mut with_tlv = header.encode()?;
        with_tlv[14..16].copy_from_slice(&16_u16.to_be_bytes());
        with_tlv.extend_from_slice(&[0xee, 0x00, 0x01, 0xaa]);
        assert_eq!(parse_proxy_v2(&with_tlv)?.header, header);

        let mut short_tlv_header = header.encode()?;
        short_tlv_header[14..16].copy_from_slice(&13_u16.to_be_bytes());
        short_tlv_header.push(0xee);
        assert_eq!(
            parse_proxy_v2(&short_tlv_header),
            Err(ProxyV2Error::MalformedTlv { offset: 12 })
        );

        let mut short_tlv_value = header.encode()?;
        short_tlv_value[14..16].copy_from_slice(&16_u16.to_be_bytes());
        short_tlv_value.extend_from_slice(&[0xee, 0x00, 0x02, 0xaa]);
        assert_eq!(
            parse_proxy_v2(&short_tlv_value),
            Err(ProxyV2Error::MalformedTlv { offset: 12 })
        );
        Ok(())
    }

    #[test]
    fn rejects_malformed_signature_version_command_family_protocol_and_length()
    -> Result<(), Box<dyn std::error::Error>> {
        let base = ProxyV2Header::proxied("192.0.2.1:1234".parse()?, "192.0.2.2:443".parse()?)?
            .encode()?;

        let mut invalid = base.clone();
        invalid[0] = b'!';
        assert_eq!(
            parse_proxy_v2(&invalid),
            Err(ProxyV2Error::InvalidSignature)
        );
        let mut invalid = base.clone();
        invalid[12] = 0x11;
        assert_eq!(
            parse_proxy_v2(&invalid),
            Err(ProxyV2Error::UnsupportedVersion { received: 1 })
        );
        let mut invalid = base.clone();
        invalid[12] = 0x22;
        assert_eq!(
            parse_proxy_v2(&invalid),
            Err(ProxyV2Error::UnsupportedCommand { received: 2 })
        );
        let mut invalid = base.clone();
        invalid[13] = 0x31;
        assert_eq!(
            parse_proxy_v2(&invalid),
            Err(ProxyV2Error::UnsupportedAddressFamily { received: 3 })
        );
        let mut invalid = base.clone();
        invalid[13] = 0x12;
        assert_eq!(
            parse_proxy_v2(&invalid),
            Err(ProxyV2Error::UnsupportedTransportProtocol { received: 2 })
        );
        let mut invalid = base.clone();
        invalid[14..16].copy_from_slice(&11_u16.to_be_bytes());
        assert_eq!(
            parse_proxy_v2(&invalid),
            Err(ProxyV2Error::InvalidAddressLength {
                family: 1,
                declared: 11,
                minimum: 12,
            })
        );
        let mut invalid = base;
        invalid[14..16].copy_from_slice(&497_u16.to_be_bytes());
        assert_eq!(
            parse_proxy_v2(&invalid),
            Err(ProxyV2Error::HeaderTooLong {
                declared: 513,
                maximum: MAX_PROXY_V2_HEADER_BYTES,
            })
        );
        Ok(())
    }

    #[test]
    fn incomplete_inputs_report_the_bounded_total_needed() -> Result<(), Box<dyn std::error::Error>>
    {
        assert_eq!(
            parse_proxy_v2(&PROXY_V2_SIGNATURE[..5]),
            Err(ProxyV2Error::Incomplete {
                needed: PROXY_V2_PREFIX_BYTES,
            })
        );
        let encoded = ProxyV2Header::proxied("192.0.2.1:1234".parse()?, "192.0.2.2:443".parse()?)?
            .encode()?;
        assert_eq!(
            parse_proxy_v2(&encoded[..PROXY_V2_PREFIX_BYTES]),
            Err(ProxyV2Error::Incomplete { needed: 28 })
        );
        Ok(())
    }

    #[test]
    fn exact_reader_handles_one_byte_fragments_without_consuming_tls()
    -> Result<(), Box<dyn std::error::Error>> {
        block_on(async {
            let header = ProxyV2Header::proxied(
                "[2001:db8::1]:50000".parse()?,
                "[2001:db8::2]:443".parse()?,
            )?;
            let mut bytes = header.encode()?;
            let tls = b"\x16\x03\x03\x00\x05hello";
            bytes.extend_from_slice(tls);
            let mut reader = FragmentedReader::new(bytes, 1);

            assert_eq!(read_proxy_v2(&mut reader).await?, header);
            let mut remaining = Vec::new();
            reader.read_to_end(&mut remaining).await?;
            assert_eq!(remaining, tls);
            Ok::<_, Box<dyn std::error::Error>>(())
        })
    }

    #[test]
    fn encoder_rejects_mixed_address_families() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            ProxyV2Header::proxied("192.0.2.1:1234".parse()?, "[2001:db8::2]:443".parse()?,),
            Err(ProxyV2Error::AddressFamilyMismatch)
        );
        Ok(())
    }

    #[test]
    fn encoder_rejects_ipv6_scope_metadata_the_protocol_cannot_carry() {
        let scoped = SocketAddr::V6(std::net::SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1234, 1, 2));
        assert_eq!(
            ProxyV2Header::proxied(scoped, scoped),
            Err(ProxyV2Error::UnsupportedIpv6Scope)
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
