#!/usr/bin/python3

#    if flags["ALERT_PACKET_CORRUPTION"]:  # A40; requires T50
#        # Alerts on repeated garbage packets and PROTOCOL_VIOLATION frames.
#        if local_state["garbage"]["avg_time"] > THRESHOLD_GARBAGE_TIME:
#            print_monitor(f"[A40] Useless packets being sent: {local_state['garbage']['avg_time']}")
#        if local_state["garbage"]["unparsed"] > THRESHOLD_GARBAGE_AMOUNT:
#            print_monitor(f"[A40] Repeated garbage packets: {local_state['garbage']['amount']}")
#        if local_state["garbage"]["protocol_violation"]:
#            print_monitor(f"[A40] Connection terminated with PROTOCOL_VIOLATION.")
#            local_state["garbage"]["protocol_violation"] = False


# if flags["ALERT_STATELESS_RESET"]:  # A20; requires T50, T60
#     # Alerts on a stateless reset attempt
#     # (saved token and repeated unparseable packets)
#     if local_state["alt_conn_ids"] != {}:
#         if local_state["garbage"]["avg_time"] > THRESHOLD_GARBAGE_TIME:
#             print_monitor(f"[A20] Useless packets being sent: {local_state['garbage']['avg_time']}")
#         pass  # ..

def varint_parse_len(first_byte: int) -> int:
    dt = first_byte >> 6
    if dt == 0:
        return 1
    elif dt == 1:
        return 2
    elif dt == 2:
        return 4
    elif dt == 3:
        return 8
    else:
        raise ValueError("Invalid varint length")


def get_varint(packet_bytearray: bytearray, payload_offset: int) -> Tuple[int, int]:
    first = packet_bytearray[payload_offset]

    __len = varint_parse_len(first)

    try:
        packet_bytearray[payload_offset + 1:payload_offset + __len]
    except IndexError:
        raise ValueError("Out of bounds")

    if __len == 1:
        res = first
    elif __len == 2:
        res = int.from_bytes(
            packet_bytearray[payload_offset + 1:payload_offset + 2], 'big') & 0x3fff
    elif __len == 4:
        res = int.from_bytes(
            packet_bytearray[payload_offset + 1:payload_offset + 4], 'big') & 0x3fffffff
    elif __len == 8:
        res = int.from_bytes(
            packet_bytearray[payload_offset + 1:payload_offset + 8], 'big') & 0x3fffffffffffffff
    else:
        raise ValueError("Invalid varint")

    return res, (payload_offset + __len)