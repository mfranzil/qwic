#!/usr/bin/python3

import hwcounter
import time
import threading

import hparser
from fparser import parse_frames

from flags import flags

from frame_types import APPLICATION_CLOSE, STREAM, ACK, \
    CONNECTION_CLOSE, NEW_CONNECTION_ID, \
    RETIRE_CONNECTION_ID, PADDING

from util import ParsingException, print_monitor, print_byte

from config import \
    ACK_DELAY_EXPONENT, MAX_ACK_DELAY, \
    THRESHOLD_PACKET_LEN, THRESHOLD_STREAM_TIME, \
    THRESHOLD_STREAM_LEN, \
    KILLSWITCH_ENABLED, DISCARD_CID_WINDOW, \
    SMOOTHED_RTT_FRAC, GARBAGE_FRAC, RTTVAR_FRAC, \
    SMOOTHED_STREAM_LEN_FRAC, AVERAGE_PAYLOAD_LEN_FRAC, \
    THRESHOLD_ACK_HOLE, THRESHOLD_MAX_STREAM_ID


local_dictionary = {}
connection_ids = {}


def clean_old_entries():
    '''
    Function to clear the local dict from the oldest entries
    (the bpf map will not be cleared since LRU map)
    '''
    global local_dictionary

    curr_time = time.time()
    for key in list(local_dictionary.keys()):
        if local_dictionary[key]['last_1rtt_seen'] + DISCARD_CID_WINDOW < curr_time:
            del local_dictionary[key]
            print_monitor("Removed {}".format(key))
    t = threading.Timer(DISCARD_CID_WINDOW, clean_old_entries, ())
    t.daemon = True
    t.start()


def parse_packet(
        packet_bytearray: bytearray,
        packet_time: int,
        is_from_ingress: bool = None,
        parse_other_layers: bool = True):

    global local_dictionary
    global connection_ids

    cycle_start = hwcounter.count()

    if parse_other_layers:
        other_layers_data, payload_offset = hparser.parse_first_layers(
            packet_bytearray)
    else:
        other_layers_data = {}
        payload_offset = 0

    # Now parse the QUIC packet
    first = packet_bytearray[payload_offset]

    # if (fixed_bit := (first & 0b01000000) >> 6) != 0:
    #    print(
    #        f"Fixed bit {fixed_bit} not set, non-QUIC packet detected.")
    #    print(f"Other layers: {other_layers_data}")
    #    print(f"Packet: {packet_bytearray:x}")
    #    exit(1)

    if (header_form := (first & 0b10000000) >> 7) == 1:
        quic_header, payload_offset = hparser.parse_long_header(
            first, packet_bytearray, payload_offset)
    elif header_form == 0:
        quic_header, payload_offset = hparser.parse_short_header(
            first, packet_bytearray, payload_offset)
    else:
        raise ParsingException(f"Invalid header form: {header_form}")

    info = {}
    if flags["SAVE_ADDITIONAL_INFO"]:
        info['quic_header'] = quic_header

    # Creating the key tuple
    if header_form == 1:
        src_conn_id = quic_header['src_conn_id']
        dest_conn_id = quic_header['dest_conn_id']

        # Let Retry packets wipe out the previous state
        if quic_header['packet_type'] == "Retry":
            if src_conn_id in connection_ids:
                del connection_ids[src_conn_id]
            if dest_conn_id in connection_ids:
                del connection_ids[dest_conn_id]

        if quic_header['src_conn_id_int'] < quic_header['dest_conn_id_int']:
            key = (src_conn_id, dest_conn_id)
        else:
            key = (dest_conn_id, src_conn_id)

        if src_conn_id not in connection_ids:
            connection_ids[src_conn_id] = key
        if dest_conn_id not in connection_ids:
            connection_ids[dest_conn_id] = key

        if key in local_dictionary:
            local_state = local_dictionary[key]
        else:
            local_state = {
                "src_conn_id": src_conn_id,
                "dest_conn_id": dest_conn_id,
                'last_1rtt_seen': 0
            }

            if flags["TRACK_PACKET_COUNT"]:  # T10
                local_state['last_1rtt_number'] = 0
                local_state['1rtt_count'] = 0
                local_state['average_1rtt_length'] = 0

            if flags["TRACK_RTT"]:  # T20
                local_state['rttvar'] = 0
                local_state['smoothed_rtt'] = 0
                local_state['spin_bit'] = 0
                local_state['last_rtt_time'] = packet_time

            if flags["TRACK_STREAMS"]:  # T30
                local_state["streams"] = {}

            if flags["TRACK_ACKS"]:  # T40
                local_state["ack"] = {
                    "acked": (0, 0),
                    "missing": set(),
                    "ack_delay_exceeded": False
                }

            if flags["TRACK_GARBAGE"]:  # T50
                local_state["garbage"] = {
                    "unparsed": 0,
                    "all_padding": 0,
                    "avg_time": 0,
                    "last_time": packet_time,
                    "protocol_violation": False
                }

            if flags["TRACK_CONN_ID"]:  # T60
                local_state["alt_conn_ids"] = {}

            local_dictionary[key] = local_state

    else:
        try:
            key = connection_ids[quic_header['dest_conn_id']]
        except KeyError:
            raise ParsingException(f"No connection ID found for {quic_header['dest_conn_id']}")

        if key not in local_dictionary:
            raise ParsingException(f"No entry found for {key}")

        local_state = local_dictionary[key]

        local_state["last_1rtt_seen"] = packet_time

        if flags["TRACK_PACKET_COUNT"]:  # T10
            local_state["last_1rtt_number"] = quic_header['packet_number']
            local_state["1rtt_count"] += 1
            local_state["average_1rtt_length"] = \
                (1 - AVERAGE_PAYLOAD_LEN_FRAC) * \
                local_state["average_1rtt_length"] + \
                AVERAGE_PAYLOAD_LEN_FRAC * \
                len(packet_bytearray[payload_offset:])

        if flags["TRACK_RTT"] and quic_header['spin_bit'] != local_state["spin_bit"]:  # T20
            local_state["spin_bit"] = quic_header['spin_bit']

            smoothed_rtt = local_state["smoothed_rtt"]
            rttvar = local_state["rttvar"]

            latest_rtt = packet_time - local_state["last_rtt_time"]

            smoothed_rtt = (1 - SMOOTHED_RTT_FRAC) * smoothed_rtt + \
                SMOOTHED_RTT_FRAC * latest_rtt
            rttvar_sample = abs(smoothed_rtt - latest_rtt)
            rttvar = (1 - RTTVAR_FRAC) * rttvar + \
                RTTVAR_FRAC * rttvar_sample

            local_state["smoothed_rtt"] = smoothed_rtt
            local_state["rttvar"] = rttvar
            local_state["last_rtt_time"] = packet_time

    if flags["PARSE_FRAME"] and quic_header['packet_type'] == "1RTT":  # P20
        frames, result = parse_frames(packet_bytearray, payload_offset)

        if flags["SAVE_ADDITIONAL_INFO"]:  # 010
            info["frames"] = frames
            info["last_frame_result"] = result

        if flags["TRACK_GARBAGE"]:  # T50
            if result:
                status = result["status"]
                if status != 200 and status != 501:  # Either went well, or not implemented
                    print(result)
                    local_state["garbage"]["unparsed"] += 1
                    local_state["garbage"]["avg_time"] = \
                        (1 - GARBAGE_FRAC) * local_state["garbage"]["avg_time"] + \
                        GARBAGE_FRAC * (packet_time - local_state["garbage"]["last_time"])
                    local_state["garbage"]["last_time"] = packet_time

            if frames is not None and frames != []:
                all_padding = True
                for frame in frames:
                    if frame["frame_type"] != PADDING:
                        all_padding = False
                        break
                if all_padding:
                    local_state["garbage"]["all_padding"] += 1

        for frame in frames:
            if "frame_type" not in frame:
                raise ParsingException(f"Invalid frame, no frame type: {frame}")

            if flags["TRACK_STREAMS"] and frame["frame_type"] in STREAM:  # T30
                stream_id = frame["stream_id"]

                if stream_id not in local_state["streams"]:
                    local_state["streams"][stream_id] = {
                        "count": 1,
                        "type": frame["stream_type"],
                        "last_seen": packet_time,
                        "smoothed_len": frame["len"],
                        "open_since": packet_time
                    }
                else:
                    local_state["streams"][stream_id]["count"] += 1
                    local_state["streams"][stream_id]["last_seen"] = packet_time
                    local_state["streams"][stream_id]["smoothed_len"] = \
                        (1 - SMOOTHED_STREAM_LEN_FRAC) * \
                        local_state["streams"][stream_id]["smoothed_len"] + \
                        SMOOTHED_STREAM_LEN_FRAC * frame["len"]

            if flags["TRACK_ACKS"] and frame["frame_type"] in ACK:  # T40
                (ack_delay := frame["ack_delay"])
                (acked := frame["acked"])

                if ack_delay:
                    ack_delay = (2 ** ACK_DELAY_EXPONENT) * ack_delay
                    ack_delay = ack_delay / 1000  # convert to ms

                    if ack_delay > MAX_ACK_DELAY:
                        local_state["ack"]["ack_delay_exceeded"] = True

                # TODO this code may or may not be correct. I don't know.
                # I have to do more tests, including dropping some packets.
                if acked is not None:
                    for rr in acked:
                        current_lower, current_upper = local_state["ack"]["acked"]
                        lower, upper = rr

                        scheduled_for_removal = set()
                        for rrm in local_state["ack"]["missing"]:
                            if current_lower <= rrm <= current_upper:
                                scheduled_for_removal.add(rrm)

                        for rrmd in scheduled_for_removal:
                            local_state["ack"]["missing"].remove(rrmd)

                        if lower < current_lower and upper < current_lower:
                            local_state["ack"]["missing"].update(set(range(upper, current_lower)))
                            local_state["ack"]["acked"] = (lower, current_upper)
                        elif lower < current_lower and current_lower <= upper <= current_upper:
                            local_state["ack"]["acked"] = (lower, current_upper)
                        elif lower < current_lower and current_upper < upper:
                            local_state["ack"]["acked"] = (lower, current_upper)
                        elif current_lower <= lower <= current_upper and current_upper < upper:
                            local_state["ack"]["acked"] = (current_lower, upper)
                        elif current_upper < lower and current_upper < upper:
                            local_state["ack"]["missing"].update(set(range(current_upper, lower)))
                            local_state["ack"]["acked"] = (current_lower, upper)
                        elif current_lower <= lower <= upper <= current_upper:
                            continue
                        else:
                            raise ParsingException(
                                f"Corner case during the parsing of ACKED packets:"
                                f"[{lower}, {upper}], [{current_lower}, {current_upper}]")

            if flags["TRACK_GARBAGE"] and frame["frame_type"] == CONNECTION_CLOSE:  # T50
                # Identify protocol violations
                if frame["error_code"] == 0x0a:
                    local_state["garbage"]["protocol_violation"] = True

            if flags["TRACK_CONN_ID"] and frame["frame_type"] == NEW_CONNECTION_ID:
                (new_conn_id := frame["connection_id"])
                (retire_prior_to := frame["retire_prior_to"])
                (stateless_reset_token := frame["stateless_reset_token"])

                # Calculate the sequence number of the new ID
                sequence_number = len(local_state["alt_conn_ids"]) + 1

                # Insert the new connection id in the local state
                local_state["alt_conn_ids"][new_conn_id] = {
                    "retire_prior_to": retire_prior_to,
                    "stateless_reset_token": stateless_reset_token,
                    "sequence_number": sequence_number
                }

                # Update the map to allow the new connection id to be used
                connection_ids[new_conn_id] = key

            if flags["TRACK_CONN_ID"] and frame["frame_type"] == RETIRE_CONNECTION_ID:
                (sequence_number := frame["sequence_number"])

                for retirable_conn_id in local_state["alt_conn_ids"]:
                    if local_state["alt_conn_ids"][retirable_conn_id]["sequence_number"] == sequence_number:
                        del local_state["alt_conn_ids"][retirable_conn_id]
                        break

            if KILLSWITCH_ENABLED and \
                (frame["frame_type"] == CONNECTION_CLOSE
                    or frame["frame_type"] == APPLICATION_CLOSE):
                # Add killswitch to info
                info["killswitch"] = True

    if flags["SAVE_ADDITIONAL_INFO"]:  # O10
        info["first_byte"] = print_byte(first)
        info["other_layers_data"] = other_layers_data
        if is_from_ingress is not None:
            if is_from_ingress:
                info["packet_direction"] = "ingress"
            else:
                info["packet_direction"] = "egress"
        else:
            info["packet_direction"] = "unknown"

    if flags["ALERT_STREAM_COMMITMENT"]:  # A10; requires T30, T10, T50
        # Alerts on opened streams with suspiciously
        # high numbers, or many streams with low avg data.
        if local_state["streams"] != {}:
            max_stream_id = max(local_state["streams"].keys())

            if max_stream_id > THRESHOLD_MAX_STREAM_ID:
                print_monitor(f"[A10@{key}] High stream ID: {max_stream_id}")

        # open_stream_ids = sorted(local_state["streams"].keys())
        # deltas = []
        # for i in range(len(open_stream_ids) - 1):
        #     deltas.append(open_stream_ids[i + 1] - open_stream_ids[i])

        # for item in deltas:
        #     if item > THRESHOLD_STREAM_DELTA:
        #         print_monitor(f"[A10@{key}] High stream delta: {item}")

            for stream in local_state["streams"].keys():
                if local_state["streams"][stream]["smoothed_len"] < THRESHOLD_STREAM_LEN:
                    print_monitor(f"[A10@{key}] Low stream average length: {stream}")

        if local_state['average_1rtt_length'] < THRESHOLD_PACKET_LEN:
            print_monitor(f"[A10@{key}] Low average 1RTT length: {local_state['average_1rtt_length']}")

        if local_state["garbage"]["all_padding"] > 1:
            print_monitor(f"[A10@{key}] Only-padding packets: {local_state['garbage']['all_padding']}")

    if flags["ALERT_SLOWLORIS"]:  # A30; requires T10, T30
        # Alerts on connections open but rarely used,
        # or streams with few to no data.
        open_stream_ids = sorted(local_state["streams"].keys())
        for stream in open_stream_ids:
            if local_state["streams"][stream]["smoothed_len"] < THRESHOLD_STREAM_LEN:
                print_monitor(f"[A30@{key}] Low stream average length: {stream}")
            if local_state["streams"][stream]["last_seen"] + THRESHOLD_STREAM_TIME < time.time():
                print_monitor(f"[A30@{key}] Stream {stream} open for long")

    if flags["ALERT_STREAM_FRAGMENTATION"]:  # A50; requires T30, T40
        # implementing heuristics based on the age and duration of reassembly holes, or some combination of these.

        # Heuristics for packets still missing
        if len(local_state["ack"]["missing"]) > 1/10 * local_state["ack"]["acked"][1]:
            print_monitor(f"[A50@{key}] Missing a lot of packets: " +
                          f"{len(local_state['ack']['missing'])} versus " +
                          f"maximum received: {local_state['ack']['acked'][1]}")

        # Checking for big holes in reassembly
        current_hole = 0
        missing_list = sorted(local_state["ack"]["missing"])
        for i in range(len(local_state["ack"]["missing"]) - 1):
            if missing_list[i] + 1 == missing_list[i + 1]:
                current_hole += 1
            else:
                if current_hole > THRESHOLD_ACK_HOLE:
                    print_monitor(f"[A50@{key}] Hole of {current_hole} packets")
                current_hole = 0

        # Check stream usage, like SlowLoris
        open_stream_ids = sorted(local_state["streams"].keys())
        for stream in open_stream_ids:
            if local_state["streams"][stream]["smoothed_len"] < THRESHOLD_STREAM_LEN:
                print_monitor(f"[A50@{key}] Low stream average length: {stream}")
            if local_state["streams"][stream]["last_seen"] + THRESHOLD_STREAM_TIME < time.time():
                print_monitor(f"[A50@{key}] Stream {stream} open for long")

    if flags["ALERT_PERFORMANCE_ANOMALY"]:  # A70; requires T20, T40, T50
        pass

    cycle_end = hwcounter.count_end()

    return info, local_state, (cycle_end - cycle_start)
