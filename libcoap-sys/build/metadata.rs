// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright © The libcoap-rs Contributors, all rights reserved.
 * This file is part of the libcoap-rs project, see the README file for
 * general information on this project and the NOTICE.md and LICENSE files
 * for information regarding copyright ownership and terms of use.
 *
 * build/metadata.rs - Type definitions for metadata in the libcoap-sys build script.
 */

use std::{
    fmt::{Display, Formatter},
    str::FromStr,
};

use anyhow::anyhow;
use enumset::{EnumSet, EnumSetType};

/// Minimum required version of libcoap in order to build the bindgen-generated bindings.
///
/// Note that this is *not* the minimum supported version of the safe wrapper, and should only be
/// increased if building on older versions causes issues with libcoap-sys specifically.
pub const MINIMUM_LIBCOAP_VERSION: &str = "4.3.5";

/// Information about a version of libcoap that was parsed by
/// [`LibcoapDefineParser`](crate::bindings::LibcoapDefineParser).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct LibcoapDefineInfo {
    pub version: Option<String>,
    pub dtls_backend: Option<DtlsBackend>,
    pub supported_features: EnumSet<LibcoapFeature>,
}

/// An optional feature that may or may not be supported by a version of `libcoap`.
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
    /// Returns the name of the #define in `coap_defines.h` that corresponds to the given feature,
    /// or None if there is no direct correspondence to such a #define.
    pub fn define_name(&self) -> Option<&'static str> {
        match self {
            LibcoapFeature::AfUnix => Some("COAP_AF_UNIX_SUPPORT"),
            LibcoapFeature::Async => Some("COAP_ASYNC_SUPPORT"),
            LibcoapFeature::Client => Some("COAP_CLIENT_SUPPORT"),
            LibcoapFeature::SmallStack => Some("COAP_CONSTRAINED_STACK"),
            LibcoapFeature::Tcp => Some("COAP_DISABLE_TCP"),
            LibcoapFeature::Epoll => Some("COAP_EPOLL_SUPPORT"),
            LibcoapFeature::Ipv4 => Some("COAP_IPV4_SUPPORT"),
            LibcoapFeature::Ipv6 => Some("COAP_IPV6_SUPPORT"),
            LibcoapFeature::Oscore => Some("COAP_OSCORE_SUPPORT"),
            LibcoapFeature::QBlock => Some("COAP_Q_BLOCK_SUPPORT"),
            LibcoapFeature::Server => Some("COAP_SERVER_SUPPORT"),
            LibcoapFeature::ThreadRecursiveLockDetection => Some("COAP_THREAD_RECURSIVE_CHECK"),
            LibcoapFeature::ThreadSafe => Some("COAP_THREAD_SAFE"),
            LibcoapFeature::ObservePersist => Some("COAP_WITH_OBSERVE_PERSIST"),
            LibcoapFeature::WebSockets => Some("COAP_WS_SUPPORT"),
            _ => None,
        }
    }

    /// Returns the set of features that are supposedly enabled if the #define with the name
    /// `define_name` is set to `define_value` in `coap_defines.h`, or an empty set if the provided
    /// define does not correspond to such a feature.
    pub fn features_from_define(define_name: &str, define_value: i64) -> EnumSet<Self> {
        // Only consider values != 0.
        if define_name != "COAP_DISABLE_TCP" && define_value == 0 {
            return EnumSet::empty();
        }
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

    /// Return the configure argument name (--enable-<NAME>) that can be provided to libcoap's
    /// configure-script to enable the given feature (or None if no such flag is available).
    pub fn configure_flag_name(&self) -> Option<&'static str> {
        match self {
            LibcoapFeature::AfUnix => Some("af-unix"),
            LibcoapFeature::Async => Some("async"),
            LibcoapFeature::Client => Some("client-mode"),
            LibcoapFeature::SmallStack => Some("small-stack"),
            LibcoapFeature::Tcp => Some("tcp"),
            LibcoapFeature::Epoll => Some("epoll"),
            LibcoapFeature::Ipv4 => Some("ipv4"),
            LibcoapFeature::Ipv6 => Some("ipv6"),
            LibcoapFeature::Oscore => Some("oscore"),
            LibcoapFeature::QBlock => Some("q-block"),
            LibcoapFeature::Server => Some("server-mode"),
            LibcoapFeature::ThreadRecursiveLockDetection => Some("thread-recursive-lock-detection"),
            LibcoapFeature::ThreadSafe => Some("thread-safe"),
            LibcoapFeature::Dtls => Some("dtls"),
            LibcoapFeature::ObservePersist => Some("observe-persist"),
            LibcoapFeature::WebSockets => Some("websockets"),
            _ => None,
        }
    }

    /// Return the ESP-IDF sdkconfig option name that must be set to enable this feature, or None
    /// if no configuration option is available.
    /// Reference: https://github.com/espressif/idf-extra-components/blob/master/coap/Kconfig
    pub fn sdkconfig_flag_name(&self) -> Option<&'static str> {
        match self {
            LibcoapFeature::DtlsPsk => Some("COAP_MBEDTLS_PSK"),
            LibcoapFeature::DtlsPki => Some("COAP_MBEDTLS_PKI"),
            // Should be implied by mbedtls being enabled.
            LibcoapFeature::DtlsCid => Some("COAP_MBEDTLS_PSK"),
            LibcoapFeature::Tcp => Some("COAP_TCP_SUPPORT"),
            LibcoapFeature::Oscore => Some("COAP_OSCORE_SUPPORT"),
            LibcoapFeature::ObservePersist => Some("COAP_OBSERVE_PERSIST"),
            LibcoapFeature::QBlock => Some("COAP_Q_BLOCK"),
            LibcoapFeature::Async => Some("COAP_ASYNC_SUPPORT"),
            LibcoapFeature::ThreadSafe => Some("COAP_THREAD_SAFE"),
            LibcoapFeature::ThreadRecursiveLockDetection => Some("COAP_THREAD_RECURSIVE_CHECK"),
            LibcoapFeature::WebSockets => Some("COAP_WEBSOCKETS"),
            LibcoapFeature::Client => Some("COAP_CLIENT_SUPPORT"),
            LibcoapFeature::Server => Some("COAP_SERVER_SUPPORT"),
            _ => None,
        }
    }

    /// Returns the suffix of the CARGO_FEATURE_<FEATURE> environment variable that must be set
    /// during build script execution if the feature has been enabled.
    pub fn cargo_feature_var_suffix(&self) -> String {
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

/// A DLTS library that can be used by `libcoap` for encryption support.
#[derive(Debug, EnumSetType, Hash)]
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
    /// Returns the suffix that has to be appended to libcoap-3-<DTLS library> to find a library
    /// version linked against the right DTLS library.
    pub fn library_suffix(&self) -> &'static str {
        // just keeping this here in case we ever need to change this definition to something
        // different than self.as_str() for some libraries.
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

    /// Returns the DTLS library that is supposedly enabled if the #define with the name
    /// `define_name` is set to `define_value` in `coap_defines.h`, or None if the provided
    /// define does not correspond to a DTLS library.
    pub fn library_from_define(define_name: &str, define_value: i64) -> Option<DtlsBackend> {
        if define_value == 0 {
            return None;
        }
        match define_name {
            "COAP_WITH_LIBGNUTLS" => Some(DtlsBackend::GnuTls),
            "COAP_WITH_LIBMBEDTLS" => Some(DtlsBackend::MbedTls),
            "COAP_WITH_LIBOPENSSL" => Some(DtlsBackend::OpenSsl),
            "COAP_WITH_LIBTINYDTLS" => Some(DtlsBackend::TinyDtls),
            "COAP_WITH_LIBWOLFSSL" => Some(DtlsBackend::WolfSsl),
            _ => None,
        }
    }
}
