#!/usr/bin/python3

flags = {
    (_P20 := "PARSE_FRAME"): False,

    (_T10 := "TRACK_PACKET_COUNT"): False,
    (_T20 := "TRACK_RTT"): False,
    (_T30 := "TRACK_STREAMS"): False,
    (_T40 := "TRACK_ACKS"): False,
    (_T50 := "TRACK_GARBAGE"): False,
    (_T60 := "TRACK_CONN_ID"): False,

    (_A10 := "ALERT_STREAM_COMMITMENT"): False,
    (_A30 := "ALERT_SLOWLORIS"): False,
    (_A50 := "ALERT_STREAM_FRAGMENTATION"): False,
    (_A70 := "ALERT_PERFORMANCE_ANOMALY"): False,

    (_O10 := "SAVE_ADDITIONAL_INFO"): False,

    (_L10 := "PRINT_INFO"): False,
    (_L20 := "PRINT_FRAMES"): False,
    (_L30 := "PRINT_TIMES"): False,
    (_L40 := "PRINT_LOCAL_STATE"): False
}


relations = [
    # Alerting -> Tracking
    [_A10, _T10], [_A10, _T30], [_A10, _T50],
    [_A30, _T10], [_A30, _T30],
    [_A50, _T30], [_A50, _T40],
    [_A70, _T20], [_A70, _T40], [_A70, _T50],
    # Tracking -> Parsing
    [_T30, _P20], [_T40, _P20], [_T50, _P20], [_T60, _P20],
    # Misc
    [_L10, _O10], [_L20, _O10], [_L20, _P20]
]


def initialize_flags(*args):
    from util import print_monitor  # Import must be here

    # If flags are provided in the args, set them to True
    if len(args) > 0:
        buf = "Injecting flags: "
        for flag in args:
            exec(f"print_monitor('{flag} aka', _{flag})")
            exec("flags[_" + flag + "] = True")
        print_monitor(buf)

    # Print out relationships explicitly
    buf = ""
    for relation in relations:
        if flags[relation[0]]:
            flags[relation[1]] = True
            buf += f"{'_'.join(relation[0].split('_'))} => {'_'.join(relation[1].split('_'))}; "
    print_monitor("Flag relations: " + buf)

    # Print enabled flags
    buf = ""
    for flag in flags:
        if flags[flag]:
            buf += f"{'_'.join(flag.split('_'))}; "
    print_monitor("Flags: " + buf)
