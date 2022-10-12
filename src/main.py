#!/usr/bin/python3

import datetime
from argparse import ArgumentParser, ArgumentError
import atexit
import ctypes as ct
import threading
import time
from traceback import format_exc
import socket
import os

import pyroute2
from pr2modules.netlink.exceptions import NetlinkError
import pyshark
from scapy.all import Packet, sniff
from scapy.layers.inet import UDP

from util import print_monitor, print_data, initialize_outputs, ParsingException
from pparser import parse_packet, clean_old_entries
from flags import flags, initialize_flags
from config import BPF_FILE, EGRESS_MAGIC, INGRESS_MAGIC, KILLSWITCH_ENABLED

bcc_unavailable = False
try:
    from bcc import BPF
except Exception:
    bcc_unavailable = True


def final_mw_parse_packet(
        packet_bytearray: bytearray,
        packet_time: int,
        cpu: int = None,
        is_from_ingress: bool = None,
        print_newlines: bool = True,
        parse_other_layers: bool = True):
    try:
        info, local_state, cycles = parse_packet(
            packet_bytearray=packet_bytearray,
            packet_time=packet_time,
            is_from_ingress=is_from_ingress,
            parse_other_layers=parse_other_layers
        )

        # Printing ###############################################################

        data = []

        if flags["PRINT_INFO"]:  # R10
            # data.append(json.dumps(info, indent=4))
            data.append(info)

        if flags["PRINT_FRAMES"]:  # R40
            edited_time = datetime.datetime.fromtimestamp(
                packet_time).isoformat().split("T")[1]
            buf = f"A={edited_time} C={cycles} "
            if "frames" in info:
                buf += f"{info['frames']} {info['last_frame_result']}"

            data.append(buf)

        if flags["PRINT_TIMES"]:  # R20
            if cpu is None:
                cpu = "99999"

            if print_newlines:
                data.append(f"\n{cycles},{packet_time},{cpu}\n")
            else:
                data.append(f"{cycles},{packet_time},{cpu}")

        if flags["PRINT_LOCAL_STATE"]:  # R30
            # print(json.dumps(local_state, indent=4))
            data.append(local_state)

        print_data("".join(data))

        if KILLSWITCH_ENABLED and "killswitch" in info and info["killswitch"]:
            # Final packet detected, ending after 3 seconds
            print_monitor(f"Killswitched, detected final packet")
            threading.Timer(3, lambda: os._exit(144)).start()

    except ParsingException as e:
        print_monitor(f"An exception occurred during the parsing of a packet: {e}")
        print_monitor(format_exc())
    except Exception as e:
        print_monitor(f"An exception has occurred: {e}")
        print_monitor(format_exc())
        exit(1)


def packet_mw_ebpf(cpu, data, size, packet_time):
    '''
    Middleware to handle the eBPF threaded call and pass the proper
    arguments to the parser.
    '''
    class SkbEvent(ct.Structure):
        _fields_ = [("magic", ct.c_uint32),
                    ("raw", ct.c_ubyte * (size - ct.sizeof(ct.c_uint32)))]

    skb_event = ct.cast(data, ct.POINTER(SkbEvent)).contents

    packet_time = time.time()

    if skb_event.magic == EGRESS_MAGIC:
        is_from_ingress = False
    elif skb_event.magic == INGRESS_MAGIC:
        is_from_ingress = True
    else:
        print_monitor(f"Got a packet not from Ingress/Egress "
                      "(magic: {skb_event.magic:x}), fix this.")
        return

    # convert packet into bytearray
    packet_bytearray = bytearray(skb_event.raw)

    final_mw_parse_packet(
        packet_bytearray=packet_bytearray,
        packet_time=packet_time,
        is_from_ingress=is_from_ingress,
        cpu=cpu,
        print_newlines=True
    )


def packet_callback_ebpf(cpu, data, size):
    '''
    Function to spawn an independent thread to handle a packet in the Control plane.
    Packets come from eBPF events pushed in the buffer.
    '''
    t = threading.Thread(
        target=packet_mw_ebpf,
        args=(cpu, data, size, time.time(),)
    )
    t.start()


def packet_callback_pyshark(pkt):
    '''
    Function to handle a packet in the Control plane, received from pyshark.
    It then directly calls the parser.
    '''
    if int(pkt.ip.proto) != socket.IPPROTO_UDP:
        raise Exception("Unsupported protocol")

    arr = bytearray.fromhex(pkt["FRAME_RAW"].value)
    # arr = bytearray(pkt.get_raw_packet())

    final_mw_parse_packet(
        packet_bytearray=arr,
        packet_time=float(pkt.sniff_timestamp),
        print_newlines=False,
        # parse_other_layers=False
    )


def packet_callback_scapy(pkt: Packet):
    arr = bytes(pkt)

    final_mw_parse_packet(
        packet_bytearray=arr,
        packet_time=float(pkt.time),
        print_newlines=False,
        # parse_other_layers=False
    )


def monitor_ebpf(mode, device, offload_device, ingress_fn_name):
    print_monitor('Compiling eBPF')

    b = BPF(src_file=BPF_FILE,
            debug=0,
            cflags=["-w", "-DEXECUTE=1"],
            device=offload_device
            )

    ingress_fn = b.load_func(ingress_fn_name, mode, offload_device)
    egress_fn = b.load_func("egress_filter", BPF.SCHED_CLS, offload_device)

    print_monitor('Attaching programs to chain')

    if mode == BPF.XDP:
        b.attach_xdp(device, ingress_fn, 0)

    ip = pyroute2.IPRoute()
    ipdb = pyroute2.IPDB(nl=ip, deprecation_warning=False)
    idx = ipdb.interfaces[device].index

    # create a class to tag the traffic
    try:
        ip.tc("add", "clsact", idx)
    except NetlinkError:
        # Cleanup from eventual failed executions
        try:
            pyroute2.IPRoute().tc("del", "clsact", pyroute2.IPDB(
                nl=pyroute2.IPRoute()).interfaces[device].index)
            pyroute2.IPDB(nl=pyroute2.IPRoute()).release()
        except Exception:
            print_monitor("Previous cleanup failed, attempting to continue")
        finally:
            ip.tc("add", "clsact", idx)

    # ingress tag
    if mode != BPF.XDP:
        ip.tc("add-filter", "bpf", idx, ":1", fd=ingress_fn.fd, name=ingress_fn.name,
              parent="ffff:fff3", classid=1, direct_action=True)

    # egress tag
    egress_parent = "ffff:fff3" if mode == BPF.XDP else "ffff:fff2"
    ip.tc("add-filter", "bpf", idx, ":1", fd=egress_fn.fd, name=egress_fn.name,
          parent=egress_parent, classid=1, direct_action=True)

    b["skb_events"].open_perf_buffer(packet_callback_ebpf)

    clean_old_entries()

    print_monitor("Starting analysis, hit CTRL+C to stop")

    while True:
        try:
            # start listening for buffer events
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            print_monitor("Removing filters from device")
            break

    # remove the programs from device or TC
    if mode == BPF.XDP:
        b.remove_xdp(device, 0)  # , flags)

    ip.tc("del", "clsact", idx)
    ipdb.release()


def monitor_pyshark(device):
    print_monitor("Attaching LiveCapture program to pyshark")
    cap = pyshark.LiveRingCapture(
        interface=device,
        bpf_filter="udp",
        use_json=True,
        use_ek=True,
        include_raw=True,
        ring_file_size=1024 * 20,
        num_ring_files=3
    )

    clean_old_entries()

    print_monitor("Starting LiveCapture program, press Ctrl+C to stop")

    try:
        cap.apply_on_packets(packet_callback_pyshark)
    except KeyboardInterrupt:
        print_monitor(f"Stopping LiveCapture program; remaining: {cap}")
        exit(0)


def monitor_scapy(device):
    print_monitor("Preparing to sniff with scapy...")
    print_monitor("Starting scapy sniff, press Ctrl+C to stop")

    try:
        sniff(filter="udp", prn=packet_callback_scapy, iface=device, store=False)
    except KeyboardInterrupt:
        print_monitor(f"Stopping scapy sniff.")
        exit(0)


def main(args):
    device = args.interface
    mode_str = args.mode
    monitor_file_str = args.monitor_file
    data_file_str = args.data_file
    comment = args.comment
    enabled_flags = args.enabled_flags.split(',')

    if data_file_str == "auto":
        if not os.path.exists("./data/in"):
            os.makedirs("./data/in")
        data_file_str = f"./data/in/{device}_{mode_str}_{','.join(enabled_flags)}"

        if comment:
            data_file_str += f"_{comment}"

        data_file_str += f"_{time.strftime('%Y-%m-%d_%H-%M-%S')}.out"

    initialize_outputs(monitor_file_str, data_file_str)
    atexit.register(lambda: print_monitor("Exiting..."))

    print_monitor(f"== QWIC: QUIC Watchful Information Collector ==")
    print_monitor(f"| Settings:")
    print_monitor(f"|   - mode: {mode_str}")
    print_monitor(f"|   - interface: {device}")
    print_monitor(f"|   - monitor_file: {monitor_file_str}")
    print_monitor(f"|   - data_file: {data_file_str}")
    print_monitor(f"===========================================")

    print_monitor(f"Initializing flags..")
    initialize_flags(*enabled_flags)

    if mode_str == "XDP":
        monitor_ebpf(
            mode=BPF.XDP,
            device=device,
            offload_device=None,
            ingress_fn_name="ingress_filter_xdp"
        )
    elif mode_str == "TC":
        monitor_ebpf(
            mode=BPF.SCHED_CLS,
            device=device,
            offload_device=None,
            ingress_fn_name="ingress_filter_tc"
        )
    elif mode_str == "PY":
        # If the mode is Pyshark, just call the related function
        monitor_pyshark(
            device=device
        )
    elif mode_str == "SC":
        monitor_scapy(
            device=device
        )
    else:
        raise ArgumentError(f"Invalid mode: {mode_str}")


if __name__ == "__main__":
    parser = ArgumentParser(description='QUIC traffic parser')

    if bcc_unavailable:
        choices = ['PY', 'SC']
    else:
        choices = ['XDP', 'TC', 'PY', 'SC']

    parser.add_argument('-i', '--interface',
                        required=True,
                        help='Interface to listen on')
    parser.add_argument('-m', '--mode',
                        required=True,
                        help='Mode to run in',
                        default='TC',
                        choices=choices)
    parser.add_argument('-f', '--monitor-file',
                        required=False,
                        help='File to write the monitor logs to',
                        default=None)
    parser.add_argument('-d', '--data-file',
                        required=False,
                        help='File to write the data logs to; auto to generate a filename',
                        default=None)
    parser.add_argument('-x', '--enabled-flags',
                        help='Comma-separated list of flags to enable',
                        default="L30,P21,P24")
    parser.add_argument('-c', '--comment',
                        help='Comment to add to the data file',
                        default=None)

    args = parser.parse_args()

    # if "," not in args.enabled_flags:
    #     raise ArgumentError("Enabled flags must be separated by commas without spaces")

    main(args)
