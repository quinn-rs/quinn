// This is only here because qpack is new and quinn no uses it yet.
// TODO remove allow dead code
#![allow(unused_imports)]

/*
 *QUIC                                                           C. Krasic
 *Internet-Draft                                               Google, Inc
 *Intended status: Standards Track                               M. Bishop
 *Expires: November 24, 2018                           Akamai Technologies
 *                                                        A. Frindell, Ed.
 *                                                                Facebook
 *                                                            May 23, 2018
 *
 *
 *              QPACK: Header Compression for HTTP over QUIC
 *                        draft-ietf-quic-qpack-00
 */

#[allow(dead_code)]
pub const QPACK_VERSION: &'static str = "0.0.0~draft";
#[allow(dead_code)]
pub const QPACK_VERSION_DATE: &'static str = "23-may-2018";

pub mod string;
pub mod table;

pub mod decoder;
pub mod vas;

pub mod prefix_int;
