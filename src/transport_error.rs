use std::fmt;

use frame;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Error(u16);

macro_rules! errors {
    {$($name:ident($val:expr) $desc:expr;)*} => {
        impl Error {
            $(pub const $name: Self = Error($val);)*
        }
        impl fmt::Display for Error {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                if self.0 >= 0x100 && self.0 <= 0x1ff {
                    return write!(f, "error in {} frame", frame::Type::from(self.0 as u8));
                }
                let x = match self.0 {
                    $($val => $desc,)*
                    _ => "unknown error"
                };
                f.write_str(x)
            }
        }
    }
}

errors!{
    NO_ERROR(0x0) "the connection is being closed abruptly in the absence of any error";
    INTERNAL_ERROR(0x1) "the endpoint encountered an internal error and cannot continue with the connection";
    SERVER_BUSY(0x2) "the server is currently busy and does not accept any new connections";
    FLOW_CONTROL_ERROR(0x3) "an endpoint received more data than it permitted in its advertised data limits";
    STREAM_ID_ERROR(0x4) "an endpoint received a frame for a stream identifier that exceeded its advertised maximum stream ID";
    STREAM_STATE_ERROR(0x5) "an endpoint received a frame for a stream that was not in a state that permitted that frame";
    FINAL_OFFSET_ERROR(0x6) "an endpoint received a STREAM frame containing data that exceeded the previously established final offset, or a RST_STREAM frame containing a final offset that was lower than the maximum offset of data that was already received, or a RST_STREAM frame containing a different final offset to the one already established";
    FRAME_FORMAT_ERROR(0x7) "an endpoint received a frame that was badly formatted. For instance, an empty STREAM frame that omitted the FIN flag, or an ACK frame that has more acknowledgment ranges than the remainder of the packet could carry";
    TRANSPORT_PARAMETER_ERROR(0x8) "an endpoint received transport parameters that were badly formatted, included an invalid value, was absent even though it is mandatory, was present though it is forbidden, or is otherwise in error";
    VERSION_NEGOTIATION_ERROR(0x9) "an endpoint received transport parameters that contained version negotiation parameters that disagreed with the version negotiation that it performed, constituting a potential version downgrade attack";
    PROTOCOL_VIOLATION(0xA) "an endpoint detected an error with protocol compliance that was not covered by more specific error codes";
    UNSOLICITED_PATH_RESPONSE(0xB) "an endpoint received a PATH_RESPONSE frame that did not correspond to any PATH_CHALLENGE frame that it previously sent";

    TLS_HANDSHAKE_FAILED(0x201) "the TLS handshake failed";
    TLS_FATAL_ALERT_GENERATED(0x202) "a TLS fatal alert was sent, causing the TLS connection to end prematurely";
    TLS_FATAL_ALERT_RECEIVED(0x203) "a TLS fatal alert was received, causing the TLS connection to end prematurely";
}
