#!/usr/bin/python3

#  class FrameType(enum.IntEnum):
PADDING = 0x00  # IH01, NP
PING = 0x01  # IH01
ACK = range(0x02, 0x03 + 1)  # IH_1, NC
RESET_STREAM = 0x04  # __01
STOP_SENDING = 0x05  # __01
CRYPTO = 0x06  # IH_1
NEW_TOKEN = 0x07  # ___1
STREAM = range(0x08, 0x0f + 1)  # __01, F
MAX_DATA = 0x10  # __01
MAX_STREAM_DATA = 0x11  # __01
MAX_STREAMS = range(0x12, 0x13 + 1)  # __01
DATA_BLOCKED = 0x14  # __01
STREAM_DATA_BLOCKED = 0x15  # __01
STREAMS_BLOCKED_BIDI = 0x16  # __01
STREAMS_BLOCKED_UNI = 0x17  # __01
NEW_CONNECTION_ID = 0x18  # __01, P
RETIRE_CONNECTION_ID = 0x19  # __01
PATH_CHALLENGE = 0x1a  # __01, P
PATH_RESPONSE = 0x1b  # ___1, P
CONNECTION_CLOSE = 0x1c  # ih01, N
APPLICATION_CLOSE = 0x1d  # ih01, N
HANDSHAKE_DONE = 0x1e  # ___1
DATAGRAM = range(0x30, 0x31 + 1)

frame_types = {
    0x00: "PADDING",  # IH01, NP
    0x01: "PING",  # IH01
    0x02: "ACK",  # IH_1, NC
    0x03: "ACK",  # IH_1, NC
    0x04: "RESET_STREAM",  # __01
    0x05: "STOP_SENDING",  # __01
    0x06: "CRYPTO",  # IH_1
    0x07: "NEW_TOKEN",  # ___1
    0x08: "STREAM",  # __01, F
    0x09: "STREAM",  # __01, F
    0x0a: "STREAM",  # __01, F
    0x0b: "STREAM",  # __01, F
    0x0c: "STREAM",  # __01, F
    0x0d: "STREAM",  # __01, F
    0x0e: "STREAM",  # __01, F
    0x0f: "STREAM",  # __01, F
    0x10: "MAX_DATA",  # __01
    0x11: "MAX_STREAM_DATA",  # __01
    0x12: "MAX_STREAMS",  # __01
    0x13: "MAX_STREAMS",  # __01
    0x14: "DATA_BLOCKED",  # __01
    0x15: "STREAM_DATA_BLOCKED",  # __01
    0x16: "STREAMS_BLOCKED_BIDI",  # __01
    0x17: "STREAMS_BLOCKED_UNI",  # __01
    0x18: "NEW_CONNECTION_ID",  # __01, P
    0x19: "RETIRE_CONNECTION_ID",  # __01
    0x1a: "PATH_CHALLENGE",  # __01, P
    0x1b: "PATH_RESPONSE",  # ___1, P
    0x1c: "CONNECTION_CLOSE",  # ih01, N
    0x1d: "APPLICATION_CLOSE",  # ih01, N
    0x1e: "HANDSHAKE_DONE",  # ___1
    0x30: "DATAGRAM",
    0x31: "DATAGRAM"
}


def get_frame_name(frame_type: int) -> str:
    try:
        return frame_types[frame_type]
    except KeyError:
        return None
