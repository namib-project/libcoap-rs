// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright © The libcoap-rs Contributors, all rights reserved.
 * This file is part of the libcoap-rs project, see the README file for
 * general information on this project and the NOTICE.md and LICENSE files
 * for information regarding copyright ownership and terms of use.
 *
 * wrapper.h - wrapper header to generate libcoap Rust bindings using bindgen
 */

#include <coap3/coap.h>

#if __has_include(<coap3/coap_defines.h>)
#include <coap3/coap_defines.h>
#endif
