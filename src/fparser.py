#!/usr/bin/python3

from typing import Tuple
from util import get_varint
from flags import flags
from frame_types import get_frame_name, APPLICATION_CLOSE, \
    CONNECTION_CLOSE, NEW_CONNECTION_ID, PADDING, \
    RETIRE_CONNECTION_ID, STREAM, STREAM_DATA_BLOCKED, \
    STREAMS_BLOCKED_BIDI, STREAMS_BLOCKED_UNI, ACK
from config import MAX_STREAM_SIZE, SEAL_BYTES, LAST_FRAME_PADDING


def parse_connid_frame(packet_bytearray: bytearray, payload_offset: int) -> Tuple[dict, int]:
    # NEW_CONNECTION_ID Frame {
    #   Type (i) = 0x18,
    #   Sequence Number (i),
    #   Retire Prior To (i),
    #   Length (8),
    #   Connection ID (8..160),
    #   Stateless Reset Token (128)
    # }
    # RETIRE_CONNECTION_ID Frame {
    #   Type (i) = 0x19,
    #   Sequence Number (i),
    # }
    first = packet_bytearray[payload_offset]
    payload_offset += 1

    # Discard two most significant bits
    frame_type = first & 0b00111111

    if frame_type == NEW_CONNECTION_ID:
        sequence_number, payload_offset = get_varint(
            packet_bytearray, payload_offset)
        retire_prior_to, payload_offset = get_varint(
            packet_bytearray, payload_offset)

        length = packet_bytearray[payload_offset]
        payload_offset += 1

        connection_id = int.from_bytes(
            packet_bytearray[payload_offset:payload_offset + length], byteorder="big")
        payload_offset += length

        stateless_reset_token = int.from_bytes(
            packet_bytearray[payload_offset:payload_offset + 16], byteorder="big")
        payload_offset += 16

        return {
            "frame_name": "NEW_CONNECTION_ID",
            "frame_type": frame_type,
            "sequence_number": sequence_number,
            "retire_prior_to": retire_prior_to,
            "connection_id": connection_id,
            "connection_id_length": length,
            "stateless_reset_token": stateless_reset_token,
        }, payload_offset

    elif frame_type == RETIRE_CONNECTION_ID:
        sequence_number, payload_offset = get_varint(
            packet_bytearray, payload_offset)

        return {
            "frame_name": "RETIRE_CONNECTION_ID",
            "frame_type": frame_type,
            "sequence_number": sequence_number,
        }, payload_offset


def parse_streamsblocked_frame(packet_bytearray: bytearray, payload_offset: int) -> Tuple[dict, int]:
    first = packet_bytearray[payload_offset]
    payload_offset += 1

    # Discard two most significant bits
    frame_type = first & 0b00111111

    if frame_type == STREAM_DATA_BLOCKED:
        stream_id, payload_offset = get_varint(
            packet_bytearray, payload_offset)
        limit, payload_offset = get_varint(packet_bytearray, payload_offset)
        return {
            "frame_name": "STREAM_DATA_BLOCKED",
            "frame_type": frame_type,
            "stream_id": stream_id,
            "limit": limit,
        }, payload_offset

    elif frame_type == STREAMS_BLOCKED_BIDI:
        limit, payload_offset = get_varint(packet_bytearray, payload_offset)
        return {
            "frame_name": "STREAMS_BLOCKED_BIDI",
            "frame_type": frame_type,
            "limit": limit,
        }, payload_offset

    elif frame_type == STREAMS_BLOCKED_UNI:
        limit, payload_offset = get_varint(packet_bytearray, payload_offset)
        return {
            "frame_name": "STREAMS_BLOCKED_UNI",
            "frame_type": frame_type,
            "limit": limit,
        }, payload_offset


def parse_ack_frame(packet_bytearray: bytearray, payload_offset: int) -> Tuple[dict, int]:
    # ACK Frame {
    #     Type (i) = 0x02..0x03,
    #     Largest Acknowledged (i),
    #     ACK Delay (i),
    #     ACK Range Count (i),
    #     First ACK Range (i),
    #     ACK Range (..) ...,
    #     [ECN Counts (..)],
    # }
    first = packet_bytearray[payload_offset]
    payload_offset += 1

    largest_ack, payload_offset = get_varint(packet_bytearray, payload_offset)
    ack_delay, payload_offset = get_varint(packet_bytearray, payload_offset)
    block_count, payload_offset = get_varint(packet_bytearray, payload_offset)
    ack_block, payload_offset = get_varint(packet_bytearray, payload_offset)

    if largest_ack < ack_block:
        raise ValueError("largest ack < ack block")

    smallest_ack = largest_ack - ack_block
    acks = set()
    result = {}

    if acks is not None:
        acks.add((smallest_ack, largest_ack))
        # savd = f">>> {(smallest_ack, largest_ack)}"

        for _ in range(0, block_count):
            gap, payload_offset = get_varint(packet_bytearray, payload_offset)

            if smallest_ack < gap + 2:
                raise ValueError("smallest_ack < gap + 2")

            largest_ack = (smallest_ack - gap) - 2
            ack_block, payload_offset = get_varint(
                packet_bytearray, payload_offset)

            if largest_ack < ack_block:
                raise ValueError("largest ack < ack block")

            smallest_ack = largest_ack - ack_block

            acks.add((smallest_ack, largest_ack))
            # savd += f"\n>>> {(smallest_ack, largest_ack)}"

        has_ecn_counts = (first & 0x01) != 0
        if has_ecn_counts:
            ect0, payload_offset = get_varint(packet_bytearray, payload_offset)
            ect1, payload_offset = get_varint(packet_bytearray, payload_offset)
            ecn_ce, payload_offset = get_varint(packet_bytearray, payload_offset)

        result = {
            "frame_name": "ACK",
            "frame_type": f"{first:02x}",
            "ack_delay": ack_delay,
            "acked": acks,
            "block_count": block_count,
            "ecn_counts": has_ecn_counts and {
                "ect0_count": ect0,
                "ect1_count": ect1,
                "ecn_ce_count": ecn_ce
            } or None
        }

    if acks is None:
        return generate_result(
            status=400,
            reason={
                "str": "Failed to parse ACK frame, acks is None",
                "data": result
            },
            payload_offset=payload_offset,
            remaining_length=len(packet_bytearray) - payload_offset,
        ), payload_offset

    return result, payload_offset


def parse_stream_frame(packet_bytearray: bytearray, payload_offset: int) -> Tuple[dict, int]:
    first = packet_bytearray[payload_offset]
    payload_offset += 1

    fin = (first & 0x01) != 0

    stream_id, payload_offset = get_varint(packet_bytearray, payload_offset)

    if (first & 0x04) != 0:
        packet_offset, payload_offset = get_varint(
            packet_bytearray, payload_offset)
    else:
        packet_offset = 0

    if (first & 0x02) != 0:
        frame_len, payload_offset = get_varint(
            packet_bytearray, payload_offset)
        payload_offset += frame_len

        if payload_offset > len(packet_bytearray):
            raise ValueError(
                "frame_len + payload_offset > len(packet_bytearray)")

    else:
        # All the remaining bytes
        frame_len = len(packet_bytearray[payload_offset:])
        payload_offset = len(packet_bytearray)

    if frame_len + packet_offset >= MAX_STREAM_SIZE:
        raise ValueError("frame_len + packet_offset >= MAX_STREAM_SIZE")

    if frame_len + packet_offset < 0:
        raise ValueError("frame_len + packet_offset < 0")

    # Stream type
    stream_type = stream_id & 0b11
    if stream_type == 0x00:
        stream_type = "Client-Bidi"
    if stream_type == 0x01:
        stream_type = "Server-Bidi"
    if stream_type == 0x02:
        stream_type = "Client-Uni"
    if stream_type == 0x03:
        stream_type = "Server-Uni"

    return {
        "frame_name": "STREAM",
        "frame_type": f"{first:02x}",
        "stream_id": stream_id,
        "stream_type": stream_type,
        "offset": packet_offset,
        "fin": fin,
        "len": frame_len,
    }, payload_offset


def parse_closing_frame(packet_bytearray: bytearray, payload_offset: int) -> Tuple[dict, int]:
    # Skip the first byte
    first = packet_bytearray[payload_offset]
    payload_offset += 1

    # Discard two most significant bits
    frame_type = first & 0b00111111

    if frame_type == CONNECTION_CLOSE:
        error_code, payload_offset = get_varint(
            packet_bytearray, payload_offset)
        offending_frame, payload_offset = get_varint(
            packet_bytearray, payload_offset)
        reason_phrase_length, payload_offset = get_varint(
            packet_bytearray, payload_offset)

        # Print reason as hex
        reason_phrase = packet_bytearray[payload_offset:
                                         payload_offset + reason_phrase_length]
        reason_phrase_hex = ":".join("{:02x}".format(c) for c in reason_phrase)

        return {
            "frame_name": "CONNECTION_CLOSE",
            "frame_type": frame_type,
            "error_code": f"{error_code:02x}",
            "reason_phrase": reason_phrase_hex,
            "offending_frame": get_frame_name(offending_frame)
        }, payload_offset + reason_phrase_length

    elif frame_type == APPLICATION_CLOSE:
        error_code, payload_offset = get_varint(
            packet_bytearray, payload_offset)
        reason_phrase_length, payload_offset = get_varint(
            packet_bytearray, payload_offset)

        # Print reason as hex
        reason_phrase = int.from_bytes(
            packet_bytearray[payload_offset: payload_offset +
                             reason_phrase_length],
            byteorder="big")

        return {
            "frame_name": "APPLICATION_CLOSE",
            "frame_type": frame_type,
            "error_code": f"{error_code:02x}",
            "reason_phrase": f"{reason_phrase:02x}",
        }, payload_offset + reason_phrase_length


def parse_frames_rec(packet_bytearray: bytearray, payload_offset: int, frames: list, parsing_flags: int = 0) -> list:
    remaining_length = len(packet_bytearray) - payload_offset
    if remaining_length <= SEAL_BYTES:
        return generate_result(
            status=200,
            reason="Buffer finished",
            payload_offset=payload_offset,
            remaining_length=remaining_length
        )
    if payload_offset >= len(packet_bytearray):
        return generate_result(
            status=400,
            reason="Payload offset is out of bounds",
            payload_offset=payload_offset,
            remaining_length=remaining_length
        )

    frame_type = packet_bytearray[payload_offset]

    # Discard two most significant bits
    frame_type = frame_type & 0b00111111

    if frame_type == PADDING:
        # Padding frames are just a single byte
        payload_offset += 1
        if parsing_flags & LAST_FRAME_PADDING:
            frames[-1]["amount"] += 1
        else:
            frames.append({
                "frame_name": "PADDING",
                "frame_type": frame_type,
                "amount": 1
            })
        return parse_frames_rec(packet_bytearray, payload_offset, frames, parsing_flags | LAST_FRAME_PADDING)
    elif frame_type in STREAM:
        function_name = parse_stream_frame
    elif frame_type in ACK:
        function_name = parse_ack_frame
    elif frame_type == CONNECTION_CLOSE or frame_type == APPLICATION_CLOSE:
        function_name = parse_closing_frame
    elif frame_type in (STREAM_DATA_BLOCKED, STREAMS_BLOCKED_BIDI, STREAMS_BLOCKED_UNI):
        function_name = parse_streamsblocked_frame
    elif frame_type == NEW_CONNECTION_ID or frame_type == RETIRE_CONNECTION_ID:
        function_name = parse_connid_frame
    else:
        unparsed_frame = get_frame_name(frame_type)
        if unparsed_frame is None:
            status = 400
            frame_name = "UNKNOWN"
        else:
            status = 501
            frame_name = unparsed_frame

        return generate_result(
            status=status,
            reason={
                "str": "Packet could not be parsed",
                "frame_name": frame_name,
                "frame_type": frame_type,
            },
            payload_offset=payload_offset,
            remaining_length=len(packet_bytearray) - payload_offset
        )

    if function_name:
        frame, payload_offset = function_name(
            packet_bytearray, payload_offset)
        if "status" in frame:
            return frame
        frames.append(frame)
        return parse_frames_rec(packet_bytearray, payload_offset, frames, parsing_flags)
    else:
        raise Exception(
            f"function_name is None and {frame_type} cannot be parsed")


def parse_frames(packet_bytearray: bytearray, payload_offset: int) -> list:
    frames = []
    result = parse_frames_rec(packet_bytearray, payload_offset, frames)

    return frames, result


def generate_result(status, reason, payload_offset: int, remaining_length: int) -> dict:
    return {
        "status": status,
        "reason": reason,
        "payload_offset": payload_offset,
        "remaining_length": remaining_length
    }
