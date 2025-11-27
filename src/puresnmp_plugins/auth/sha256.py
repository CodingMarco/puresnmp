"""
This module provides the plugin for SHA-256 based authentication

Implements usmHMAC192SHA256AuthProtocol as defined in RFC 7860.
Uses SHA-256 with HMAC truncated to 192 bits (24 bytes).
"""

import hashlib

import puresnmp_plugins.auth.hashbase as hashbase
from puresnmp.util import password_to_key

IDENTIFIER = "sha256"
IANA_ID = 5  # RFC 7860: usmHMAC192SHA256AuthProtocol
MAC_LENGTH = 24  # RFC 7860: usmHMAC192SHA256AuthProtocol uses 24-byte (192-bit) truncated MAC

# SHA-256 requires 32-byte padding for key localization
hasher = password_to_key(hashlib.sha256, 32)

#: Compare incoming message digest with expected value. Return True if the
#: digest matches the expected value.
#: RFC 7860: usmHMAC192SHA256AuthProtocol uses 24-byte (192-bit) truncation
authenticate_incoming_message = hashbase.for_incoming(hasher, "sha256", truncate_to=24)

#: Calculate the message digest for a SNMPv3 message.
#: RFC 7860: usmHMAC192SHA256AuthProtocol uses 24-byte (192-bit) truncation
authenticate_outgoing_message = hashbase.for_outgoing(hasher, "sha256", truncate_to=24)
