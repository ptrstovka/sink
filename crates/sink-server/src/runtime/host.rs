use sink_protocol::RESERVED_CONNECT_SUBDOMAIN;

use crate::certificates::Hostname;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum HostRoute {
    Control,
    Base,
    Tunnel(Hostname),
    Invalid,
}

pub(crate) fn classify_host(host: &str, base_domain: &str) -> HostRoute {
    if !host.is_ascii() || host.is_empty() || host.ends_with('.') || host.contains(':') {
        return HostRoute::Invalid;
    }
    let Ok(host) = Hostname::parse(host) else {
        return HostRoute::Invalid;
    };
    let Ok(base_domain) = Hostname::parse(base_domain) else {
        return HostRoute::Invalid;
    };
    if host == base_domain {
        return HostRoute::Base;
    }
    if host.as_str() == format!("{RESERVED_CONNECT_SUBDOMAIN}.{base_domain}") {
        return HostRoute::Control;
    }
    if !host.is_same_or_below(&base_domain) || is_reserved_hostname(&host, &base_domain) {
        return HostRoute::Invalid;
    }
    HostRoute::Tunnel(host)
}

pub(crate) fn requested_hostname(requested_hostname: &str, base_domain: &str) -> Option<Hostname> {
    match classify_host(requested_hostname, base_domain) {
        HostRoute::Tunnel(hostname) => Some(hostname),
        HostRoute::Control | HostRoute::Base | HostRoute::Invalid => None,
    }
}

pub(crate) fn is_reserved_hostname(hostname: &Hostname, base_domain: &Hostname) -> bool {
    let Some(depth) = hostname.depth_below(base_domain) else {
        return false;
    };
    if depth == 0 {
        return true;
    }
    let suffix = format!(".{base_domain}");
    let Some(relative) = hostname.as_str().strip_suffix(&suffix) else {
        return true;
    };
    relative
        .split('.')
        .any(|label| label == RESERVED_CONNECT_SUBDOMAIN)
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
            HostRoute::Tunnel(Hostname::parse("demo.example.test").expect("test hostname"))
        );
        assert_eq!(
            classify_host("api.cloud.example.test", base),
            HostRoute::Tunnel(Hostname::parse("api.cloud.example.test").expect("test hostname"))
        );
        for invalid in [
            "connect.attacker.example.test",
            "api.connect.example.test",
            "connect.cloud.example.test",
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
    fn requested_hostname_accepts_valid_descendants_under_the_base() {
        let base = "example.test";
        assert_eq!(
            requested_hostname("Demo.Example.Test", base),
            Some(Hostname::parse("demo.example.test").expect("test hostname"))
        );
        assert_eq!(
            requested_hostname("api.cloud.example.test", base),
            Some(Hostname::parse("api.cloud.example.test").expect("test hostname"))
        );
        assert!(requested_hostname("connect.example.test", base).is_none());
        assert!(requested_hostname("demo.other.test", base).is_none());
    }
}
