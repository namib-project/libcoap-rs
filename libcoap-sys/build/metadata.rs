use std::{
    fmt::{Display, Formatter, Write},
    str::FromStr,
};

use anyhow::anyhow;
use enumset::{EnumSet, EnumSetType};

pub const MINIMUM_LIBCOAP_VERSION: &str = "4.3.5";

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct LibcoapDefineInfo {
    pub version: Option<String>,
    pub supported_features: EnumSet<LibcoapFeature>,
}

#[derive(EnumSetType, Debug)]
pub enum LibcoapFeature {
    AfUnix,
    Async,
    Client,
    SmallStack,
    Tcp,
    Epoll,
    Ipv4,
    Ipv6,
    Oscore,
    QBlock,
    Server,
    ThreadRecursiveLockDetection,
    ThreadSafe,
    Dtls,
    ObservePersist,
    WebSockets,
    SecureWebSockets,
    DtlsCid,
    DtlsPsk,
    DtlsPki,
    DtlsPkcs11,
    DtlsRpk,
    Tls,
}

impl LibcoapFeature {
    pub fn define_name(&self) -> Option<&'static str> {
        match self {
            LibcoapFeature::AfUnix => Some("COAP_AF_UNIX_SUPPORT"),
            LibcoapFeature::Async => Some("COAP_ASYNC_SUPPORT"),
            LibcoapFeature::Client => Some("COAP_CLIENT_SUPPORT"),
            LibcoapFeature::SmallStack => Some("COAP_CONSTRAINED_STACK"),
            LibcoapFeature::Tcp => Some("COAP_DISABLE_TCP"), // TODO invert
            LibcoapFeature::Epoll => Some("COAP_EPOLL_SUPPORT"),
            LibcoapFeature::Ipv4 => Some("COAP_IPV4_SUPPORT"),
            LibcoapFeature::Ipv6 => Some("COAP_IPV6_SUPPORT"),
            LibcoapFeature::Oscore => Some("COAP_OSCORE_SUPPORT"),
            // TODO proxy support?
            LibcoapFeature::QBlock => Some("COAP_Q_BLOCK_SUPPORT"),
            LibcoapFeature::Server => Some("COAP_SERVER_SUPPORT"),
            LibcoapFeature::ThreadRecursiveLockDetection => Some("COAP_THREAD_RECURSIVE_CHECK"),
            LibcoapFeature::ThreadSafe => Some("COAP_THREAD_SAFE"),
            LibcoapFeature::Dtls => None, // TODO has multiple defines
            LibcoapFeature::ObservePersist => Some("COAP_WITH_OBSERVE_PERSIST"),
            LibcoapFeature::WebSockets => Some("COAP_WS_SUPPORT"),
            _ => None,
        }
    }

    pub fn features_from_define(define_name: &str, define_value: i64) -> EnumSet<Self> {
        match define_name {
            "COAP_AF_UNIX_SUPPORT" => EnumSet::from(LibcoapFeature::AfUnix),
            "COAP_ASYNC_SUPPORT" => EnumSet::from(LibcoapFeature::Async),
            "COAP_CLIENT_SUPPORT" => EnumSet::from(LibcoapFeature::Client),
            "COAP_CONSTRAINED_STACK" => EnumSet::from(LibcoapFeature::SmallStack),
            "COAP_EPOLL_SUPPORT" => EnumSet::from(LibcoapFeature::Epoll),
            "COAP_IPV4_SUPPORT" => EnumSet::from(LibcoapFeature::Ipv4),
            "COAP_IPV6_SUPPORT" => EnumSet::from(LibcoapFeature::Ipv6),
            "COAP_OSCORE_SUPPORT" => EnumSet::from(LibcoapFeature::Oscore),
            "COAP_Q_BLOCK_SUPPORT" => EnumSet::from(LibcoapFeature::QBlock),
            "COAP_SERVER_SUPPORT" => EnumSet::from(LibcoapFeature::Server),
            "COAP_THREAD_RECURSIVE_CHECK" => EnumSet::from(LibcoapFeature::ThreadRecursiveLockDetection),
            "COAP_THREAD_SAFE" => EnumSet::from(LibcoapFeature::ThreadSafe),
            "COAP_WITH_OBSERVE_PERSIST" => EnumSet::from(LibcoapFeature::ObservePersist),
            "COAP_WS_SUPPORT" => EnumSet::from(LibcoapFeature::WebSockets),
            "COAP_DISABLE_TCP" => {
                if define_value == 0 {
                    EnumSet::from(LibcoapFeature::Tcp)
                } else {
                    EnumSet::empty()
                }
            },
            "COAP_WITH_LIBGNUTLS"
            | "COAP_WITH_LIBMBEDTLS"
            | "COAP_WITH_LIBOPENSSL"
            | "COAP_WITH_LIBTINYDTLS"
            | "COAP_WITH_LIBWOLFSSL" => EnumSet::from(LibcoapFeature::Dtls),
            _ => EnumSet::empty(),
        }
    }

    pub fn configure_flag_name(&self) -> Option<&'static str> {
        match self {
            LibcoapFeature::AfUnix => Some("af-unix"),
            LibcoapFeature::Async => Some("async"),
            LibcoapFeature::Client => Some("client"),
            LibcoapFeature::SmallStack => Some("small-stack"),
            LibcoapFeature::Tcp => Some("tcp"),
            LibcoapFeature::Epoll => Some("epoll"),
            LibcoapFeature::Ipv4 => Some("ipv4"),
            LibcoapFeature::Ipv6 => Some("ipv6"),
            LibcoapFeature::Oscore => Some("oscore"),
            LibcoapFeature::QBlock => Some("q-block"),
            LibcoapFeature::Server => Some("server"),
            LibcoapFeature::ThreadRecursiveLockDetection => Some("thread-recursive-lock-detection"),
            LibcoapFeature::ThreadSafe => Some("thread-safe"),
            LibcoapFeature::Dtls => Some("dtls"),
            LibcoapFeature::ObservePersist => Some("observe-persist"),
            LibcoapFeature::WebSockets => Some("websockets"),
            _ => None,
        }
    }

    pub fn cargo_feature_var_name(&self) -> String {
        self.as_str().to_uppercase().replace('-', "_")
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            LibcoapFeature::AfUnix => "af-unix",
            LibcoapFeature::Async => "async",
            LibcoapFeature::Client => "client",
            LibcoapFeature::SmallStack => "small-stack",
            LibcoapFeature::Tcp => "tcp",
            LibcoapFeature::Epoll => "epoll",
            LibcoapFeature::Ipv4 => "ipv4",
            LibcoapFeature::Ipv6 => "ipv6",
            LibcoapFeature::Oscore => "oscore",
            LibcoapFeature::QBlock => "q-block",
            LibcoapFeature::Server => "server",
            LibcoapFeature::ThreadRecursiveLockDetection => "thread-recursive-lock-detection",
            LibcoapFeature::ThreadSafe => "thread-safe",
            LibcoapFeature::Dtls => "dtls",
            LibcoapFeature::ObservePersist => "observe-persist",
            LibcoapFeature::WebSockets => "websockets",
            LibcoapFeature::SecureWebSockets => "secure-websockets",
            LibcoapFeature::DtlsCid => "dtls-cid",
            LibcoapFeature::DtlsPsk => "dtls-psk",
            LibcoapFeature::DtlsPki => "dtls-pki",
            LibcoapFeature::DtlsPkcs11 => "dtls-pkcs11",
            LibcoapFeature::DtlsRpk => "dtls-rpk",
            LibcoapFeature::Tls => "tls",
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DtlsBackend {
    GnuTls,
    OpenSsl,
    MbedTls,
    TinyDtls,
    WolfSsl,
}

impl FromStr for DtlsBackend {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "gnutls" => Ok(DtlsBackend::GnuTls),
            "openssl" => Ok(DtlsBackend::OpenSsl),
            "mbedtls" => Ok(DtlsBackend::MbedTls),
            "tinydtls" => Ok(DtlsBackend::TinyDtls),
            "wolfssl" => Ok(DtlsBackend::WolfSsl),
            v => Err(anyhow!("unknown DTLS backend {v}")),
        }
    }
}

impl Display for DtlsBackend {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl DtlsBackend {
    pub fn pkg_config_suffix(&self) -> &'static str {
        // just keeping this here in case we ever need to change this definition for some libraries.
        self.as_str()
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            DtlsBackend::GnuTls => "gnutls",
            DtlsBackend::OpenSsl => "openssl",
            DtlsBackend::MbedTls => "mbedtls",
            DtlsBackend::TinyDtls => "tinydtls",
            DtlsBackend::WolfSsl => "wolfssl",
        }
    }
}
