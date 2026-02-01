{ pkgs, lib, config, inputs, ... }:
let
  possible_dtls_libraries = [ "openssl" "mbedtls" "gnutls" "wolfssl" ];
in {
  # https://devenv.sh/basics/
  options = {
    rust-version = lib.mkOption {
      type = lib.types.enum [ "msrv" "stable" "nightly" ];
      default = "stable";
      description = "Version of the Rust toolchain to use";
    };

    dtls-library = lib.mkOption {
      type = lib.types.enum ([ "all" "none" ] ++ possible_dtls_libraries);
      default = "all";
      description = "DTLS library/libraries that should be provided for libcoap to link against.";
    };
  };

  config = rec {
    # https://devenv.sh/packages/
    packages =
      let wolfssl-libcoap = (pkgs.wolfssl.override {
          variant = "opensslall";
          extraConfigureFlags = [
            "--enable-dtls"
            "--enable-psk"
            "--enable-aesccm"
            "--enable-dh"
          ];
        }).overrideAttrs (final: prev: {
          # Need to override the CFLAGS in the preConfigure script, because
          # adding more than one CFLAG to extraConfigureFlags causes issues
          # due to the whitespace (see
          # https://discourse.nixos.org/t/cmakeflags-and-spaces-in-option-values/20170)
          preConfigure = ''
            export CFLAGS="-DHAVE_ALPN -DHAVE_EX_DATA"
          '';
        });
      in with pkgs; (
        # Generic dependencies. We want LLDB for the VS Code dev container (gdb is also
        # provided by setting languages.c.enable = true).
        [ autoconf automake libtool pkg-config lldb rustPlatform.bindgenHook ]
        # DTLS library specific dependencies (mbedtls also needs zlib).
        ++ (if config.dtls-library == "all" then [ openssl mbedtls gnutls wolfssl-libcoap zlib ]
           else if config.dtls-library == "openssl" then [ openssl ]
           else if config.dtls-library == "mbedtls" then [ mbedtls zlib ]
           else if config.dtls-library == "gnutls" then [ gnutls ]
           else if config.dtls-library == "wolfssl" then [ wolfssl-libcoap ]
           else [])
      );

    # https://devenv.sh/languages/
    languages = {
      rust = let
        # Parse the MSRV from the Cargo.toml files, choose the newer one of both MSRVs.
        libcoap-msrv = (builtins.fromTOML (builtins.readFile ./libcoap/Cargo.toml)).package.rust-version;
        libcoap-sys-msrv = (builtins.fromTOML (builtins.readFile ./libcoap-sys/Cargo.toml)).package.rust-version;
        msrv = if (builtins.compareVersions libcoap-msrv libcoap-sys-msrv) >= 0 then libcoap-msrv else libcoap-sys-msrv;
      in {
        enable = true;

        # Explicitly setting the version is not supported when channel == "nixpkgs", so we set it
        # to stable here if necessary.
        channel = if config.rust-version == "msrv" then "stable" else config.rust-version;
        version = if config.rust-version == "msrv" then msrv else if config.rust-version == "nightly" then "2026-01-31" else "latest";
        components = ["rustc" "cargo" "clippy" "rustfmt" "rust-analyzer" "rust-src"];
      };
      c = {
        enable = true;
      };
    };

    # https://devenv.sh/processes/

    # https://devenv.sh/services/

    # https://devenv.sh/scripts/
    scripts = let
      # Features that should always be enabled for development scripts.
      default_features = [ "vendored" ];
      # Features specific to either of the crates.
      crate_specific_feature_matrix = {
        libcoap-rs = [ "tcp" "rand" ];
        libcoap-sys = [ "default" ];
      };
      # Feaures specific to some DTLS libraries.
      dtls_supported_feature_matrix = {
        openssl = [ "tls" "dtls-psk" "dtls-pki" ];
        mbedtls = [ "tls" "dtls-psk" "dtls-pki" "dtls-cid" ];
        gnutls = [ "tls" "dtls-psk" "dtls-pki" "dtls-rpk" ];
        tinydtls = [ "dtls-psk" "dtls-rpk" "dtls-tinydtls-sys-vendored" ];
        wolfssl = [ "tls" "dtls-psk" "dtls-pki"];
      };
    # This monstrosity of a nix expression generates a script for each crate + dtls library combo that runs all tests available for that specific crate+library combo.
    in (builtins.listToAttrs (lib.lists.flatten (lib.mapAttrsToList (dtls_lib: dtls_features:
      if config.dtls-library == "all" || dtls_lib == "tinydtls" || config.dtls-library == dtls_lib then 
        (lib.mapAttrsToList (crate_name: crate_features:
          (lib.nameValuePair (crate_name + ":test_" + dtls_lib) {
            exec = ''
              LIBCOAP_RS_DTLS_BACKEND=${dtls_lib} cargo test -p ${crate_name} --no-default-features --features ${ lib.concatStringsSep "," (default_features ++ crate_features ++ dtls_features) } "$@" 
            '';
            description = "Run all possible tests for the ${crate_name} crate using the ${dtls_lib} DTLS library.";
          })
        ) crate_specific_feature_matrix)
      else []
    ) dtls_supported_feature_matrix))) // {
      # Documentation builder script.
      docs = let
        # gnutls has the largest feature set, so prefer using it for the documentation builds.
        doc_dtls_lib = if config.dtls-library == "all" then "gnutls" else config.dtls-library;
      in {
        exec = ''
            cargo doc --no-deps --workspace --features ${
              lib.concatStringsSep "," (
                (map (x: "libcoap-rs/"+x) crate_specific_feature_matrix.libcoap-rs)
                ++ (map (x: "libcoap-sys/"+x) crate_specific_feature_matrix.libcoap-sys)
                ++ dtls_supported_feature_matrix."${doc_dtls_lib}"
                ++ default_features
              )
            }
          '';
        description = "Build the library documentation";
      };
    };

    # A pretty
    enterShell = ''
      cat << EOF

      Entering the libcoap-rs development environment!

      Environment-provided DTLS libraries: ${ if config.dtls-library == "all" then lib.concatStringsSep "," possible_dtls_libraries else config.dtls-library}

      Some helpful scripts/commands you can run for your convenience:
      ${ lib.concatStringsSep "\n" (lib.mapAttrsToList (name: value: "${name}  \t${value.description}") scripts) }

      EOF
    '';

    # https://devenv.sh/tasks/
    # tasks = {
    #   "myproj:setup".exec = "mytool build";
    #   "devenv:enterShell".after = [ "myproj:setup" ];
    # };

    # https://devenv.sh/tests/
    enterTest = ''
    '';

    # Add clippy and rustfmt checks as git commit hooks.
    # https://devenv.sh/git-hooks/
    git-hooks.hooks = {
      clippy = {
        enable = true;
        settings.allFeatures = true;
        packageOverrides = {
            cargo = config.languages.rust.toolchainPackage;
            clippy = config.languages.rust.toolchainPackage;
        };
      };
      rustfmt = {
        enable = true;
        # Set to check mode so that we don't automatically make changes to the
        # code.
        settings.check = true;
        packageOverrides = {
            cargo = config.languages.rust.toolchainPackage;
            rustfmt = config.languages.rust.toolchainPackage;
        };
      };
    };

    # See full reference at https://devenv.sh/reference/options/

    # Development container specification.
    devcontainer.enable = true;
    devcontainer.settings = {
      updateContentCommand = "devenv test";

      # Required for rootless podman, see
      # https://github.com/cachix/devenv/issues/935.
      runArgs = [
        "--userns=keep-id:uid=1000,gid=1000"
      ];
      containerUser = "vscode";
      updateRemoteUserUID = true;
      containerEnv = {
        HOME = "/home/vscode";
      };

      # Install appropriate JetBrains IDE plugins.
      customizations.jetbrains.plugins = [
        "com.jetbrains.rust"
        "systems.fehn.intellijdirenv"
      ];

      # Install appropraite VS Code extensions.
      customizations.vscode = {
        extensions = [
          "rust-lang.rust-analyzer"
          "ms-vscode.cpptools"
          "mkhl.direnv"
          "vadimcn.vscode-lldb"
          "tamasfe.even-better-toml"
        ];
        settings = {
          "rust-analyzer.cargo.features" = ["vendored"];
        };
      };
    };
  };
}
