mod pdu;
mod option_handling;
mod pdu_builder;
mod payload;

use std::borrow::{Borrow, BorrowMut};
use std::ops::Deref;
use coap_message::{MessageOption, MinimalWritableMessage, ReadableMessage, SeekWritableMessage};
use pdu::PduKind;
use crate::session::CoapSessionCommon;


