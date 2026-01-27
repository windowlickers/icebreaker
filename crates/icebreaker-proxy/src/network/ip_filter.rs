//! IP address filtering for SSRF prevention.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use icebreaker_common::{NetworkProtectionConfig, Result, TokenizerError};
use ipnet::{IpNet, Ipv4Net};

/// Pre-parsed IPv4 reserved CIDRs for efficient lookups.
/// These are initialized once on first use.
mod reserved_cidrs {
    use super::*;

    // RFC 1918 private networks
    static PRIVATE_10: OnceLock<Ipv4Net> = OnceLock::new();
    static PRIVATE_172: OnceLock<Ipv4Net> = OnceLock::new();
    static PRIVATE_192: OnceLock<Ipv4Net> = OnceLock::new();

    // Link-local
    static LINK_LOCAL: OnceLock<Ipv4Net> = OnceLock::new();

    // Reserved ranges
    static CGN: OnceLock<Ipv4Net> = OnceLock::new();
    static IETF: OnceLock<Ipv4Net> = OnceLock::new();
    static TEST_NET_1: OnceLock<Ipv4Net> = OnceLock::new();
    static TEST_NET_2: OnceLock<Ipv4Net> = OnceLock::new();
    static TEST_NET_3: OnceLock<Ipv4Net> = OnceLock::new();

    /// Helper to create an Ipv4Net, panics only if the hardcoded values are wrong.
    fn make_net(addr: [u8; 4], prefix: u8) -> Ipv4Net {
        Ipv4Net::new(Ipv4Addr::from(addr), prefix)
            .unwrap_or_else(|_| unreachable!("hardcoded CIDR values are valid"))
    }

    pub fn private_10() -> &'static Ipv4Net {
        PRIVATE_10.get_or_init(|| make_net([10, 0, 0, 0], 8))
    }

    pub fn private_172() -> &'static Ipv4Net {
        PRIVATE_172.get_or_init(|| make_net([172, 16, 0, 0], 12))
    }

    pub fn private_192() -> &'static Ipv4Net {
        PRIVATE_192.get_or_init(|| make_net([192, 168, 0, 0], 16))
    }

    pub fn link_local() -> &'static Ipv4Net {
        LINK_LOCAL.get_or_init(|| make_net([169, 254, 0, 0], 16))
    }

    pub fn cgn() -> &'static Ipv4Net {
        CGN.get_or_init(|| make_net([100, 64, 0, 0], 10))
    }

    pub fn ietf() -> &'static Ipv4Net {
        IETF.get_or_init(|| make_net([192, 0, 0, 0], 24))
    }

    pub fn test_net_1() -> &'static Ipv4Net {
        TEST_NET_1.get_or_init(|| make_net([192, 0, 2, 0], 24))
    }

    pub fn test_net_2() -> &'static Ipv4Net {
        TEST_NET_2.get_or_init(|| make_net([198, 51, 100, 0], 24))
    }

    pub fn test_net_3() -> &'static Ipv4Net {
        TEST_NET_3.get_or_init(|| make_net([203, 0, 113, 0], 24))
    }
}

/// Reason why an IP address was blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReason {
    /// Private network (RFC 1918).
    PrivateNetwork,
    /// Loopback address (localhost).
    Loopback,
    /// Link-local address.
    LinkLocal,
    /// Explicitly blocked CIDR.
    BlockedCidr,
    /// Reserved or special-purpose address.
    Reserved,
}

impl std::fmt::Display for BlockReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrivateNetwork => write!(f, "private network"),
            Self::Loopback => write!(f, "loopback address"),
            Self::LinkLocal => write!(f, "link-local address"),
            Self::BlockedCidr => write!(f, "blocked CIDR"),
            Self::Reserved => write!(f, "reserved address"),
        }
    }
}

/// IP filter for network protection.
///
/// Validates IP addresses against a set of rules to prevent SSRF attacks.
#[derive(Debug, Clone)]
pub struct IpFilter {
    /// Block private networks (RFC 1918).
    block_private: bool,
    /// Block loopback addresses.
    block_loopback: bool,
    /// Block link-local addresses.
    block_link_local: bool,
    /// Additional blocked CIDRs.
    blocked_cidrs: Vec<IpNet>,
    /// Allowed CIDRs (overrides blocking rules).
    allowed_cidrs: Vec<IpNet>,
    /// Blocked hostnames.
    blocked_hostnames: Vec<String>,
}

impl IpFilter {
    /// Creates a new IP filter from configuration.
    pub fn new(config: &NetworkProtectionConfig) -> Result<Self> {
        let blocked_cidrs = config
            .blocked_cidrs
            .iter()
            .map(|s| s.parse::<IpNet>())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| TokenizerError::ConfigError(format!("invalid blocked CIDR: {e}")))?;

        let allowed_cidrs = config
            .allowed_cidrs
            .iter()
            .map(|s| s.parse::<IpNet>())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| TokenizerError::ConfigError(format!("invalid allowed CIDR: {e}")))?;

        Ok(Self {
            block_private: config.block_private,
            block_loopback: config.block_loopback,
            block_link_local: config.block_link_local,
            blocked_cidrs,
            allowed_cidrs,
            blocked_hostnames: config.blocked_hostnames.clone(),
        })
    }

    /// Creates a permissive filter that allows all addresses.
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            block_private: false,
            block_loopback: false,
            block_link_local: false,
            blocked_cidrs: Vec::new(),
            allowed_cidrs: Vec::new(),
            blocked_hostnames: Vec::new(),
        }
    }

    /// Checks if an IP address is allowed.
    #[must_use]
    pub fn is_allowed(&self, ip: &IpAddr) -> bool {
        self.check_ip(ip).is_none()
    }

    /// Checks if an IP address is blocked and returns the reason.
    #[must_use]
    pub fn check_ip(&self, ip: &IpAddr) -> Option<BlockReason> {
        // Handle IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) by extracting
        // the embedded IPv4 and validating it. This prevents SSRF bypass via
        // addresses like ::ffff:127.0.0.1 or ::ffff:10.0.0.1.
        if let IpAddr::V6(v6) = ip {
            if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                return self.check_ip(&IpAddr::V4(mapped_v4));
            }
        }

        // First check if explicitly allowed
        if self.is_in_allowed_cidrs(ip) {
            return None;
        }

        // Check block rules
        if self.block_loopback && self.is_loopback(ip) {
            return Some(BlockReason::Loopback);
        }

        if self.block_private && self.is_private(ip) {
            return Some(BlockReason::PrivateNetwork);
        }

        if self.block_link_local && self.is_link_local(ip) {
            return Some(BlockReason::LinkLocal);
        }

        if self.is_in_blocked_cidrs(ip) {
            return Some(BlockReason::BlockedCidr);
        }

        // Block other reserved/special addresses
        if self.is_reserved(ip) {
            return Some(BlockReason::Reserved);
        }

        None
    }

    /// Validates an IP address, returning an error if blocked.
    pub fn validate_ip(&self, ip: &IpAddr) -> Result<()> {
        if let Some(reason) = self.check_ip(ip) {
            return Err(TokenizerError::BlockedAddress {
                ip: ip.to_string(),
                reason: reason.to_string(),
            });
        }
        Ok(())
    }

    /// Checks if a hostname is blocked.
    #[must_use]
    pub fn is_hostname_blocked(&self, hostname: &str) -> bool {
        let hostname_lower = hostname.to_lowercase();
        self.blocked_hostnames
            .iter()
            .any(|h| hostname_lower == h.to_lowercase())
    }

    /// Validates a hostname, returning an error if blocked.
    pub fn validate_hostname(&self, hostname: &str) -> Result<()> {
        if self.is_hostname_blocked(hostname) {
            return Err(TokenizerError::HostNotAllowed {
                host: hostname.to_string(),
            });
        }
        Ok(())
    }

    fn is_loopback(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => v4.is_loopback(),
            IpAddr::V6(v6) => v6.is_loopback(),
        }
    }

    fn is_private(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.is_private_v4(v4),
            IpAddr::V6(v6) => self.is_private_v6(v6),
        }
    }

    fn is_private_v4(&self, ip: &Ipv4Addr) -> bool {
        // RFC 1918 private networks (pre-parsed)
        reserved_cidrs::private_10().contains(ip)
            || reserved_cidrs::private_172().contains(ip)
            || reserved_cidrs::private_192().contains(ip)
    }

    fn is_private_v6(&self, ip: &Ipv6Addr) -> bool {
        // Unique local addresses (fc00::/7)
        let octets = ip.octets();
        (octets[0] & 0xfe) == 0xfc
    }

    fn is_link_local(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.is_link_local_v4(v4),
            IpAddr::V6(v6) => self.is_link_local_v6(v6),
        }
    }

    fn is_link_local_v4(&self, ip: &Ipv4Addr) -> bool {
        // 169.254.0.0/16 (pre-parsed)
        reserved_cidrs::link_local().contains(ip)
    }

    fn is_link_local_v6(&self, ip: &Ipv6Addr) -> bool {
        // fe80::/10
        let octets = ip.octets();
        octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80
    }

    fn is_reserved(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.is_reserved_v4(v4),
            IpAddr::V6(v6) => self.is_reserved_v6(v6),
        }
    }

    fn is_reserved_v4(&self, ip: &Ipv4Addr) -> bool {
        let octets = ip.octets();

        // 0.0.0.0/8 - Current network
        if octets[0] == 0 {
            return true;
        }

        // 224.0.0.0/4 - Multicast
        if ip.is_multicast() {
            return true;
        }

        // 240.0.0.0/4 - Reserved for future use (includes broadcast)
        if octets[0] >= 240 {
            return true;
        }

        // Pre-parsed CIDR checks
        reserved_cidrs::cgn().contains(ip)           // 100.64.0.0/10 - CGN
            || reserved_cidrs::ietf().contains(ip)       // 192.0.0.0/24 - IETF
            || reserved_cidrs::test_net_1().contains(ip) // 192.0.2.0/24 - TEST-NET-1
            || reserved_cidrs::test_net_2().contains(ip) // 198.51.100.0/24 - TEST-NET-2
            || reserved_cidrs::test_net_3().contains(ip) // 203.0.113.0/24 - TEST-NET-3
    }

    fn is_reserved_v6(&self, ip: &Ipv6Addr) -> bool {
        // ::/128 - Unspecified
        if ip.is_unspecified() {
            return true;
        }

        // ff00::/8 - Multicast
        if ip.is_multicast() {
            return true;
        }

        // 2001:db8::/32 - Documentation
        let octets = ip.octets();
        if octets[0] == 0x20 && octets[1] == 0x01 && octets[2] == 0x0d && octets[3] == 0xb8 {
            return true;
        }

        // 100::/64 - Discard prefix
        if octets[0] == 0x01 && octets[1] == 0x00 {
            return true;
        }

        false
    }

    fn is_in_blocked_cidrs(&self, ip: &IpAddr) -> bool {
        self.blocked_cidrs.iter().any(|cidr| cidr.contains(ip))
    }

    fn is_in_allowed_cidrs(&self, ip: &IpAddr) -> bool {
        self.allowed_cidrs.iter().any(|cidr| cidr.contains(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_filter() -> IpFilter {
        IpFilter::new(&NetworkProtectionConfig::default()).expect("valid config")
    }

    #[test]
    fn test_loopback_v4_blocked() {
        let filter = default_filter();
        let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");
        assert!(!filter.is_allowed(&ip));
        assert_eq!(filter.check_ip(&ip), Some(BlockReason::Loopback));
    }

    #[test]
    fn test_loopback_v6_blocked() {
        let filter = default_filter();
        let ip: IpAddr = "::1".parse().expect("valid IP");
        assert!(!filter.is_allowed(&ip));
        assert_eq!(filter.check_ip(&ip), Some(BlockReason::Loopback));
    }

    #[test]
    fn test_private_10_blocked() {
        let filter = default_filter();
        let ip: IpAddr = "10.0.0.1".parse().expect("valid IP");
        assert!(!filter.is_allowed(&ip));
        assert_eq!(filter.check_ip(&ip), Some(BlockReason::PrivateNetwork));
    }

    #[test]
    fn test_private_172_blocked() {
        let filter = default_filter();
        let ip: IpAddr = "172.16.0.1".parse().expect("valid IP");
        assert!(!filter.is_allowed(&ip));
        assert_eq!(filter.check_ip(&ip), Some(BlockReason::PrivateNetwork));
    }

    #[test]
    fn test_private_192_blocked() {
        let filter = default_filter();
        let ip: IpAddr = "192.168.1.1".parse().expect("valid IP");
        assert!(!filter.is_allowed(&ip));
        assert_eq!(filter.check_ip(&ip), Some(BlockReason::PrivateNetwork));
    }

    #[test]
    fn test_link_local_v4_blocked() {
        let filter = default_filter();
        let ip: IpAddr = "169.254.1.1".parse().expect("valid IP");
        assert!(!filter.is_allowed(&ip));
        assert_eq!(filter.check_ip(&ip), Some(BlockReason::LinkLocal));
    }

    #[test]
    fn test_link_local_v6_blocked() {
        let filter = default_filter();
        let ip: IpAddr = "fe80::1".parse().expect("valid IP");
        assert!(!filter.is_allowed(&ip));
        assert_eq!(filter.check_ip(&ip), Some(BlockReason::LinkLocal));
    }

    #[test]
    fn test_private_v6_blocked() {
        let filter = default_filter();
        let ip: IpAddr = "fc00::1".parse().expect("valid IP");
        assert!(!filter.is_allowed(&ip));
        assert_eq!(filter.check_ip(&ip), Some(BlockReason::PrivateNetwork));
    }

    #[test]
    fn test_public_v4_allowed() {
        let filter = default_filter();
        let ip: IpAddr = "8.8.8.8".parse().expect("valid IP");
        assert!(filter.is_allowed(&ip));
        assert_eq!(filter.check_ip(&ip), None);
    }

    #[test]
    fn test_public_v6_allowed() {
        let filter = default_filter();
        let ip: IpAddr = "2001:4860:4860::8888".parse().expect("valid IP");
        assert!(filter.is_allowed(&ip));
        assert_eq!(filter.check_ip(&ip), None);
    }

    #[test]
    fn test_custom_blocked_cidr() {
        let config = NetworkProtectionConfig {
            blocked_cidrs: vec!["8.8.8.0/24".to_string()],
            ..Default::default()
        };
        let filter = IpFilter::new(&config).expect("valid config");

        let blocked: IpAddr = "8.8.8.8".parse().expect("valid IP");
        assert!(!filter.is_allowed(&blocked));
        assert_eq!(filter.check_ip(&blocked), Some(BlockReason::BlockedCidr));

        let allowed: IpAddr = "1.1.1.1".parse().expect("valid IP");
        assert!(filter.is_allowed(&allowed));
    }

    #[test]
    fn test_allowed_cidr_overrides() {
        let config = NetworkProtectionConfig {
            block_private: true,
            allowed_cidrs: vec!["10.0.0.0/24".to_string()],
            ..Default::default()
        };
        let filter = IpFilter::new(&config).expect("valid config");

        // This specific /24 is allowed
        let allowed: IpAddr = "10.0.0.1".parse().expect("valid IP");
        assert!(filter.is_allowed(&allowed));

        // But other private addresses are still blocked
        let blocked: IpAddr = "10.1.0.1".parse().expect("valid IP");
        assert!(!filter.is_allowed(&blocked));
    }

    #[test]
    fn test_permissive_filter() {
        let filter = IpFilter::permissive();

        let localhost: IpAddr = "127.0.0.1".parse().expect("valid IP");
        assert!(filter.is_allowed(&localhost));

        let private: IpAddr = "10.0.0.1".parse().expect("valid IP");
        assert!(filter.is_allowed(&private));
    }

    #[test]
    fn test_hostname_blocking() {
        let config = NetworkProtectionConfig {
            blocked_hostnames: vec!["localhost".to_string(), "internal.example.com".to_string()],
            ..Default::default()
        };
        let filter = IpFilter::new(&config).expect("valid config");

        assert!(filter.is_hostname_blocked("localhost"));
        assert!(filter.is_hostname_blocked("LOCALHOST"));
        assert!(filter.is_hostname_blocked("internal.example.com"));
        assert!(!filter.is_hostname_blocked("external.example.com"));
    }

    #[test]
    fn test_validate_ip_error() {
        let filter = default_filter();
        let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");

        let result = filter.validate_ip(&ip);
        assert!(result.is_err());

        if let Err(TokenizerError::BlockedAddress { ip: ip_str, reason }) = result {
            assert_eq!(ip_str, "127.0.0.1");
            assert_eq!(reason, "loopback address");
        } else {
            panic!("Expected BlockedAddress error");
        }
    }

    #[test]
    fn test_multicast_blocked() {
        let filter = default_filter();
        let ip: IpAddr = "224.0.0.1".parse().expect("valid IP");
        assert!(!filter.is_allowed(&ip));
        assert_eq!(filter.check_ip(&ip), Some(BlockReason::Reserved));
    }

    #[test]
    fn test_broadcast_blocked() {
        let filter = default_filter();
        let ip: IpAddr = "255.255.255.255".parse().expect("valid IP");
        assert!(!filter.is_allowed(&ip));
        assert_eq!(filter.check_ip(&ip), Some(BlockReason::Reserved));
    }

    #[test]
    fn test_cgn_blocked() {
        let filter = default_filter();
        let ip: IpAddr = "100.64.0.1".parse().expect("valid IP");
        assert!(!filter.is_allowed(&ip));
        assert_eq!(filter.check_ip(&ip), Some(BlockReason::Reserved));
    }

    #[test]
    fn test_documentation_v6_blocked() {
        let filter = default_filter();
        let ip: IpAddr = "2001:db8::1".parse().expect("valid IP");
        assert!(!filter.is_allowed(&ip));
        assert_eq!(filter.check_ip(&ip), Some(BlockReason::Reserved));
    }

    // Tests for IPv4-mapped IPv6 address bypass prevention
    #[test]
    fn test_ipv4_mapped_loopback_blocked() {
        let filter = default_filter();
        // ::ffff:127.0.0.1 is an IPv4-mapped representation of localhost
        let ip: IpAddr = "::ffff:127.0.0.1".parse().expect("valid IP");
        assert!(!filter.is_allowed(&ip));
        assert_eq!(filter.check_ip(&ip), Some(BlockReason::Loopback));
    }

    #[test]
    fn test_ipv4_mapped_private_10_blocked() {
        let filter = default_filter();
        // ::ffff:10.0.0.1 is an IPv4-mapped representation of 10.0.0.1
        let ip: IpAddr = "::ffff:10.0.0.1".parse().expect("valid IP");
        assert!(!filter.is_allowed(&ip));
        assert_eq!(filter.check_ip(&ip), Some(BlockReason::PrivateNetwork));
    }

    #[test]
    fn test_ipv4_mapped_private_172_blocked() {
        let filter = default_filter();
        let ip: IpAddr = "::ffff:172.16.0.1".parse().expect("valid IP");
        assert!(!filter.is_allowed(&ip));
        assert_eq!(filter.check_ip(&ip), Some(BlockReason::PrivateNetwork));
    }

    #[test]
    fn test_ipv4_mapped_private_192_blocked() {
        let filter = default_filter();
        let ip: IpAddr = "::ffff:192.168.1.1".parse().expect("valid IP");
        assert!(!filter.is_allowed(&ip));
        assert_eq!(filter.check_ip(&ip), Some(BlockReason::PrivateNetwork));
    }

    #[test]
    fn test_ipv4_mapped_link_local_blocked() {
        let filter = default_filter();
        let ip: IpAddr = "::ffff:169.254.1.1".parse().expect("valid IP");
        assert!(!filter.is_allowed(&ip));
        assert_eq!(filter.check_ip(&ip), Some(BlockReason::LinkLocal));
    }

    #[test]
    fn test_ipv4_mapped_public_allowed() {
        let filter = default_filter();
        // ::ffff:8.8.8.8 should still be allowed as it maps to a public IP
        let ip: IpAddr = "::ffff:8.8.8.8".parse().expect("valid IP");
        assert!(filter.is_allowed(&ip));
        assert_eq!(filter.check_ip(&ip), None);
    }

    #[test]
    fn test_ipv4_mapped_cgn_blocked() {
        let filter = default_filter();
        let ip: IpAddr = "::ffff:100.64.0.1".parse().expect("valid IP");
        assert!(!filter.is_allowed(&ip));
        assert_eq!(filter.check_ip(&ip), Some(BlockReason::Reserved));
    }

    #[test]
    fn test_ipv4_mapped_allowed_cidr_overrides() {
        let config = NetworkProtectionConfig {
            block_private: true,
            allowed_cidrs: vec!["10.0.0.0/24".to_string()],
            ..Default::default()
        };
        let filter = IpFilter::new(&config).expect("valid config");

        // IPv4-mapped address for allowed CIDR should be allowed
        let allowed: IpAddr = "::ffff:10.0.0.1".parse().expect("valid IP");
        assert!(filter.is_allowed(&allowed));

        // IPv4-mapped address outside allowed CIDR should still be blocked
        let blocked: IpAddr = "::ffff:10.1.0.1".parse().expect("valid IP");
        assert!(!filter.is_allowed(&blocked));
    }
}
