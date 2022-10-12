#!/usr/bin/python3

from typing import Tuple
from util import print_ipv4
from config import ETH_HLEN, UDP_HLEN


def parse_long_header(first: int, packet_bytearray: bytearray, payload_offset: int) -> Tuple[dict, int]:
    # Initial Packet {
    #   Header Form (1) = 1,
    #   Fixed Bit (1) = 1,
    #   Long Packet Type (2) = {0: Initial; 1: 0RTT; 2: Handshake; 3: Retry}
    #   ----- INITIAL TYPE SPECIFIC BITS (P)
    #   Reserved Bits (2),
    #   Packet Number Length (2),
    #   ----- 0RTT TYPE SPECIFIC BITS (P)
    #   Reserved Bits (2),
    #   Packet Number Length (2),
    #   ----- HANDSHAKE TYPE SPECIFIC BITS (P)
    #   Reserved Bits (2),
    #   Packet Number Length (2),
    #   ----- RETRY TYPE SPECIFIC BITS (P)
    #   Unused (4),
    #   -----
    #   Version (32),
    #   Destination Connection ID Length (8),
    #   Destination Connection ID (0..160),
    #   Source Connection ID Length (8),
    #   Source Connection ID (0..160),
    #   ----- INITIAL PACKET PAYLOAD
    #   Token Length (i),
    #   Token (..),
    #   Length (i),
    #   Packet Number (8..32),
    #   Packet Payload (8..),
    #   ----- 0RTT PACKET PAYLOAD
    #   Length (i),
    #   Packet Number (8..32),
    #   Packet Payload (8..),
    #   ----- HANDSHAKE PACKET PAYLOAD
    #   Length (i),
    #   Packet Number (8..32),
    #   Packet Payload (8..),
    #   ----- RETRY PACKET PAYLOAD
    #   Retry Token (..),
    #   Retry Integrity Tag (128)
    # }

    long_packet_type = first & 0b00110000
    long_packet_type = long_packet_type >> 4
    if long_packet_type == 0:
        packet_type = "Initial"
    elif long_packet_type == 1:
        packet_type = "0RTT"
    elif long_packet_type == 2:
        packet_type = "Handshake"
    elif long_packet_type == 3:
        packet_type = "Retry"

    # type_specific_bits = first & 0b00001111

    version_length = 4
    version = int.from_bytes(
        packet_bytearray[
            payload_offset + 1:
            payload_offset + version_length + 1
        ], 'big')

    dest_conn_id_length = packet_bytearray[
        payload_offset + 5
    ]
    dest_conn_id = packet_bytearray[
        payload_offset + 6:
        payload_offset + 6 + dest_conn_id_length
    ]

    src_conn_id_length = packet_bytearray[
        payload_offset + 6 + dest_conn_id_length
    ]
    src_conn_id = packet_bytearray[
        payload_offset + 7 + dest_conn_id_length:
        payload_offset + 7 + dest_conn_id_length + src_conn_id_length
    ]

    return {
        "header_form": 1,
        "fixed_bit": 1,
        "packet_type": packet_type,
        #  "type_specific_bits": type_specific_bits,
        "version": f'{version:x}',
        "dest_conn_id_length": dest_conn_id_length,
        "dest_conn_id": "".join(["%02x" % i for i in dest_conn_id]),
        "dest_conn_id_int": int.from_bytes(dest_conn_id, 'big'),
        "src_conn_id_length": src_conn_id_length,
        "src_conn_id": "".join(["%02x" % i for i in src_conn_id]),
        "src_conn_id_int": int.from_bytes(src_conn_id, 'big')
    }, payload_offset + 7 + dest_conn_id_length + src_conn_id_length


def parse_short_header(first: int, packet_bytearray: bytearray, payload_offset: int) -> Tuple[dict, int]:
    # 1-RTT Packet {
    #  Header Form (1) = 0
    #  Fixed Bit (1) = 1
    #  Spin Bit (1)
    #  Reserved Bits (2) (P)
    #  Key Phase (1) (P)
    #  Packet Number Length (2) (P)
    #  Destination Connection ID (0..160)
    #  Packet Number (8..32)
    #  Packet Payload (8..)
    # }
    spin_bit = (first & 0b00100000) >> 5
    #  key_phase = (first & 0b00000100) >> 2
    # The least significant two bits (those with a mask of 0x03) of byte 0 contain the
    # length of the Packet Number field, encoded as an unsigned two-bit integer that
    # is one less than the length of the Packet Number field in bytes. That is, the
    # length of the Packet Number field is the value of this field plus one. These
    # bits are protected using header protection.
    packet_number_length = (first & 0b00000011) + 1

    # In this implementation, the dcid is always 8 bytes
    dest_conn_id_length = 20
    dest_conn_id = packet_bytearray[
        payload_offset + 1:
        payload_offset + 1 + dest_conn_id_length
    ]

    # Then we have from 1 to 4 bytes for the packet number, using the
    # packet_number_length field
    packet_number = int.from_bytes(
        packet_bytearray[
            payload_offset + 1 + dest_conn_id_length:
            payload_offset + 1 + dest_conn_id_length + packet_number_length
        ], 'big')

    # Convert dest_conn_id to string
    dest_conn_id_str = "".join(["%02x" % i for i in dest_conn_id])

    return {
        "spin_bit": spin_bit,
        #  "key_phase": key_phase,
        "packet_number_length": packet_number_length,
        "packet_type": "1RTT",
        "dest_conn_id_length": dest_conn_id_length,
        "dest_conn_id": dest_conn_id_str,
        "packet_number": packet_number
    }, payload_offset + 1 + dest_conn_id_length + packet_number_length


def parse_first_layers(packet_bytearray: bytearray) -> Tuple[dict, int]:
    # https://tools.ietf.org/html/rfc791
    # calculate packet total length
    total_length = packet_bytearray[ETH_HLEN + 2]  # load MSB
    total_length = total_length << 8  # shift MSB
    total_length = total_length + packet_bytearray[ETH_HLEN+3]  # add LSB

    # calculate ip header length
    ip_header_length = packet_bytearray[ETH_HLEN]  # load Byte
    ip_header_length = ip_header_length & 0x0F  # mask bits 0..3
    ip_header_length = ip_header_length << 2  # shift to obtain length

    # retrieve ip source/dest
    # ip source offset 12..15
    ip_src = packet_bytearray[ETH_HLEN + 12:ETH_HLEN + 16]
    # ip dest offset 16..19
    ip_dst = packet_bytearray[ETH_HLEN + 16:ETH_HLEN + 20]

    # parsing ip addresses, but leaving them in their byte order (network)
    ip_src = int.from_bytes(ip_src, 'little')
    ip_dst = int.from_bytes(ip_dst, 'little')

    ip_src = print_ipv4(ip_src)
    ip_dst = print_ipv4(ip_dst)

    # parse udp packet
    # get source and dest ports
    # udp source port offset 20..21
    port_src = int.from_bytes(
        packet_bytearray[ETH_HLEN + 20:ETH_HLEN + 22], 'big')
    # udp dest port offset 22..23
    port_dst = int.from_bytes(
        packet_bytearray[ETH_HLEN + 22:ETH_HLEN + 24], 'big')

    # calculate payload offset (quic packet)
    payload_offset = ETH_HLEN + ip_header_length + UDP_HLEN

    return {
        "total_length": total_length,
        "ip_header_length": ip_header_length,
        "ip_src": ip_src,
        "ip_dst": ip_dst,
        "port_src": port_src,
        "port_dst": port_dst,
    }, payload_offset
