# Notices for the libcoap-rs Project

The libcoap-rs project (which includes both the libcoap-rs and libcoap-sys
crates) is maintained by the (former) NAMIB project members, see [below](#maintainers)
for an up-to-date list of people currently maintaining this repository.

- [Project website: https://namib-project.github.io/](https://namib-project.github.io/)
- [GitHub organization: https://github.com/namib-project/](https://github.com/namib-project/)
- [libcoap-rs repository: https://github.com/namib-project/libcoap-rs](https://github.com/namib-project/libcoap-rs)

## Maintainers

This repository is currently maintained by the following developers:

|       Name       |    Email Address     |               GitHub Username                |
|:----------------:|:--------------------:|:--------------------------------------------:|
| Hugo Hakim Damer | hdamer@uni-bremen.de | [@pulsastrix](https://github.com/pulsastrix) |

## Reporting Security Vulnerabilities

Security vulnerabilities may be reported using the
[GitHub Vulnerability Reporting Tool](https://github.com/namib-project/libcoap-rs/security).
If you prefer email, you may also report security vulnerabilities to any of the maintainers' email
addresses listed above (ideally encrypted using PGP).
*DO NOT* open a public GitHub issue for security vulnerabilities.

When reporting a security vulnerability, please provide instructions on how to reproduce the issue.
Do not send reports that were generated with automated vulnerability scanning or AI tools without
verifying that they are not false positives or without providing additional context.

Also, please ensure that reported security vulnerabilities pertain to libcoap-rs and/or libcoap-sys
in particular, not to the libcoap C library or any libraries libcoap depends on.
For instructions on reporting security vulnerabilities that pertain to libcoap, refer to
[its own security policy](https://github.com/obgm/libcoap/blob/develop/SECURITY.md).

As libcoap-rs is not maintained by a for-profit entity, we do not offer any monetary compensation
for vulnerability or bug reports, but your contributions are greatly appreciated.

Lastly, please note that as an open source project, libcoap-rs and libcoap-sys are provided "as is",
i.e., without any warranty or guarantee of fitness for a particular purpose ([see below](#copyright-information)).

### Security Vulnerability Hall of Fame

We are very thankful to the following people for reporting security issues in the past:

- None yet.

## Copyright Information

Copyright © 2021-2025 Hugo Hakim Damer, the NAMIB Project Members, and the other libcoap-rs Contributors.
All rights reserved.

The libcoap-rs project (including both the libcoap-rs and libcoap-sys crates) is licensed under the
2-Clause/Simplified BSD License, matching the license of the libcoap C library.

The license should be provided as part of this distribution in a [LICENSE](LICENSE) or
[LICENSE-BSD-2-Clause](LICENSE-BSD-2-CLAUSE) file. Alternatively, it may be viewed
[on opensource.org](https://opensource.org/licenses/BSD-2-Clause).

For information on authorship of this content, refer to the logs of the source code repository containing
this file or [the GitHub repository](https://github.com/namib-project/libcoap-rs) if you are using the
[libcoap-rs](https://crates.io/crates/libcoap-rs) or [libcoap-sys](https://crates.io/crates/libcoap-sys/)
crates released on crates.io.

### Note on Third-Party-Code

Note that for the libcoap-sys binding and generated binaries, the license terms of the libcoap C library as well
as linked dependencies (e.g. TLS libraries) may apply.
See https://github.com/obgm/libcoap/blob/develop/LICENSE as well as the licenses of dependency crates for more
information and terms.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, shall be licensed as above, without any additional terms or conditions.
