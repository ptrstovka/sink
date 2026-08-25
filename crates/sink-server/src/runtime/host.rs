use sink_protocol::{RESERVED_CONNECT_SUBDOMAIN, Subdomain};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum HostRoute {
    Control,
    Base,
    Tunnel(Subdomain),
    Invalid,
}

pub(crate) fn classify_host(host: &str, base_domain: &str) -> HostRoute {
    if !host.is_ascii() || host.is_empty() || host.ends_with('.') || host.contains(':') {
        return HostRoute::Invalid;
    }
    let host = host.to_ascii_lowercase();
    if host == base_domain {
        return HostRoute::Base;
    }
    if host == format!("{RESERVED_CONNECT_SUBDOMAIN}.{base_domain}") {
        return HostRoute::Control;
    }

    let Some(label) = host.strip_suffix(&format!(".{base_domain}")) else {
        return HostRoute::Invalid;
    };
    if label.contains('.') {
        return HostRoute::Invalid;
    }
    match Subdomain::parse(label) {
        Ok(subdomain) => HostRoute::Tunnel(subdomain),
        Err(_) => HostRoute::Invalid,
    }
}

pub(crate) fn requested_subdomain(
    requested_hostname: &str,
    base_domain: &str,
) -> Option<Subdomain> {
    match classify_host(requested_hostname, base_domain) {
        HostRoute::Tunnel(subdomain) => Some(subdomain),
        HostRoute::Control | HostRoute::Base | HostRoute::Invalid => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_host_classification_has_no_suffix_or_port_ambiguity() {
        let base = "example.test";
        assert_eq!(classify_host("example.test", base), HostRoute::Base);
        assert_eq!(
            classify_host("connect.example.test", base),
            HostRoute::Control
        );
        assert_eq!(
            classify_host("DEMO.EXAMPLE.TEST", base),
            HostRoute::Tunnel(Subdomain::parse("demo").expect("test subdomain"))
        );
        for invalid in [
            "connect.attacker.example.test",
            "demo.nested.example.test",
            "example.test.attacker",
            "demo.example.test:443",
            "demo.example.test.",
            ".example.test",
            "bad_name.example.test",
        ] {
            assert_eq!(
                classify_host(invalid, base),
                HostRoute::Invalid,
                "{invalid} must not classify"
            );
        }
    }

    #[test]
    fn requested_hostname_must_be_one_claim_under_the_base() {
        let base = "example.test";
        assert_eq!(
            requested_subdomain("Demo.Example.Test", base),
            Some(Subdomain::parse("demo").expect("test subdomain"))
        );
        assert!(requested_subdomain("connect.example.test", base).is_none());
        assert!(requested_subdomain("demo.other.test", base).is_none());
        assert!(requested_subdomain("nested.demo.example.test", base).is_none());
    }
}
