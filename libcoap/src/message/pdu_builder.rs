use std::borrow::{Borrow, BorrowMut};
use coap_message::{MinimalWritableMessage, SeekWritableMessage};
use libcoap_sys::{coap_insert_optlist, coap_new_optlist, coap_pdu_set_code, coap_pdu_t};
use std::ptr::NonNull;
use crate::error::MessageConversionError;
use crate::mem::OwnedRef;
use crate::message::option_handling::Optlist;
use crate::message::pdu::{Pdu, PduKind};
use crate::protocol::{CoapMessageCode, CoapMessageType, CoapOptionType};
use crate::session::CoapSession;

enum PduPayload<PayloadContainer: Borrow<[u8]> = Box<[u8]>> {
    Small(PayloadContainer),
    Large(Box<[u8]>),
}

pub struct PduBuilder<K: PduKind, PduType: BorrowMut<coap_pdu_t>, PayloadContainer: Borrow<[u8]>> {
    pdu: Pdu<K, PduType>,
    payload: Option<PduPayload<PayloadContainer>>,
    optlist: Optlist,
}

impl<'r> PduBuilder<'r, OwnedRef<'static, coap_pdu_t>> {
    pub fn new_request(session: &'r CoapSession<'r>) -> Self {
        Self {
            pdu: Pdu::new(CoapMessageType::),
            in_response_to: None,
            session,
            payload: None,
            optlist: Optlist {},
        }
    }
}

impl<'r, T: BorrowMut<coap_pdu_t>, R: Borrow<coap_pdu_t>> PduBuilder<'r, T, R> {
    pub fn with_request_pdu(pdu: Pdu<T>, session: &'r CoapSession<'r>) -> Result<Self, MessageConversionError> {
        Ok(Self {
            pdu,
            in_response_to: None,
            session,
            payload: None,
            optlist: Optlist::new(),
        })
    }

    pub fn with_response_pdu(pdu: Pdu<T>, in_response_to: &'r Pdu<R>, session: &'r CoapSession<'r>) -> Result<Self, MessageConversionError> {
        Ok(Self {
            pdu,
            in_response_to: Some(in_response_to),
            session,
            payload: None,
            optlist: std::ptr::null_mut(),
        })
    }

    pub fn set_token(&mut self, token: impl Into<Box<[u8]>>) -> &mut Self {
        
    }

    pub fn build(mut self) -> Result<Pdu<T>, MessageConversionError> {
        self.optlist.add_to_pdu(&mut self.pdu)?;
        let raw_pdu = self.pdu.raw_pdu.borrow_mut();
        unsafe {
            coap_
        }

        Ok(self.pdu)
    }
}

impl<'r, T: BorrowMut<coap_pdu_t>, R: Borrow<coap_pdu_t>> MinimalWritableMessage for PduBuilder<'r, T, R> {
    type AddOptionError = MessageConversionError;
    type Code = CoapMessageCode;
    type OptionNumber = CoapOptionType;
    type SetPayloadError = MessageConversionError;
    type UnionError = MessageConversionError;

    fn set_code(&mut self, code: Self::Code) {
        unsafe { coap_pdu_set_code(self.pdu.raw_pdu.borrow_mut(), code.to_raw_pdu_code()) }
    }

    fn add_option(&mut self, number: Self::OptionNumber, value: &[u8]) -> Result<(), Self::AddOptionError> {
        unsafe {
            let option = NonNull::new(coap_new_optlist(number.to_raw_option_num(), value.len(), value.as_ptr())).ok_or(MessageConversionError::Unknown)?;

            (coap_insert_optlist(&mut self.optlist, option.as_ptr()) == 1).then_some(()).ok_or(MessageConversionError::Unknown)
        }
    }

    fn set_payload(&mut self, data: &[u8]) -> Result<(), Self::SetPayloadError> {
        let data = Vec::from(data).into_boxed_slice();
        self.payload = Some(data);
        Ok(())
    }
}

impl<'r, T: BorrowMut<coap_pdu_t>, R: Borrow<coap_pdu_t>> SeekWritableMessage for PduBuilder<'r, T, R> {}