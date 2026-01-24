//! IP address filtering for SSRF prevention.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use icebreaker_common::{NetworkProtectionConfig, Result, TokenizerError};
use ipnet::{IpNet, Ipv4Net};

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
        // RFC 1918 private networks
        let private_10: Ipv4Net = "10.0.0.0/8".parse().unwrap_or_else(|_| {
            Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 8).expect("valid network")
        });
        let private_172: Ipv4Net = "172.16.0.0/12".parse().unwrap_or_else(|_| {
            Ipv4Net::new(Ipv4Addr::new(172, 16, 0, 0), 12).expect("valid network")
        });
        let private_192: Ipv4Net = "192.168.0.0/16".parse().unwrap_or_else(|_| {
            Ipv4Net::new(Ipv4Addr::new(192, 168, 0, 0), 16).expect("valid network")
        });

        private_10.contains(ip) || private_172.contains(ip) || private_192.contains(ip)
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
        // 169.254.0.0/16
        let link_local: Ipv4Net = "169.254.0.0/16".parse().unwrap_or_else(|_| {
            Ipv4Net::new(Ipv4Addr::new(169, 254, 0, 0), 16).expect("valid network")
        });
        link_local.contains(ip)
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
        // 0.0.0.0/8 - Current network
        if ip.octets()[0] == 0 {
            return true;
        }

        // 100.64.0.0/10 - Shared address space (CGN)
        let cgn: Ipv4Net = "100.64.0.0/10".parse().unwrap_or_else(|_| {
            Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 10).expect("valid network")
        });
        if cgn.contains(ip) {
            return true;
        }

        // 192.0.0.0/24 - IETF Protocol Assignments
        let ietf: Ipv4Net = "192.0.0.0/24".parse().unwrap_or_else(|_| {
            Ipv4Net::new(Ipv4Addr::new(192, 0, 0, 0), 24).expect("valid network")
        });
        if ietf.contains(ip) {
            return true;
        }

        // 192.0.2.0/24 - TEST-NET-1
        let test1: Ipv4Net = "192.0.2.0/24".parse().unwrap_or_else(|_| {
            Ipv4Net::new(Ipv4Addr::new(192, 0, 2, 0), 24).expect("valid network")
        });
        if test1.contains(ip) {
            return true;
        }

        // 198.51.100.0/24 - TEST-NET-2
        let test2: Ipv4Net = "198.51.100.0/24".parse().unwrap_or_else(|_| {
            Ipv4Net::new(Ipv4Addr::new(198, 51, 100, 0), 24).expect("valid network")
        });
        if test2.contains(ip) {
            return true;
        }

        // 203.0.113.0/24 - TEST-NET-3
        let test3: Ipv4Net = "203.0.113.0/24".parse().unwrap_or_else(|_| {
            Ipv4Net::new(Ipv4Addr::new(203, 0, 113, 0), 24).expect("valid network")
        });
        if test3.contains(ip) {
            return true;
        }

        // 224.0.0.0/4 - Multicast
        if ip.is_multicast() {
            return true;
        }

        // 240.0.0.0/4 - Reserved for future use
        if ip.octets()[0] >= 240 {
            return true;
        }

        // 255.255.255.255 - Broadcast
        if ip == &Ipv4Addr::BROADCAST {
            return true;
        }

        false
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
}
