#!/bin/env python3

import argparse
import datetime
import re
from textwrap import fill

import matplotlib.pyplot as plt
import matplotlib.ticker as mtick
import numpy as np

# Files are done as follows:

# Files that can be correctly parsed as
# 0.0001246929168701172,1657350960.216636,9
# parsing_time,starting_time,cpu
# will be stored in the local dictionary

# Files that contain the string
# "Possibly lost (.*?) samples"
# are first checked for sanity and
# the string separated with newlines.

# All other lines are then checked for sanity

# Double newlines are removed

TIMESERIES_DIVISION = 1

GLOBAL_LABELS = [
    f"T={(i + 1)/TIMESERIES_DIVISION:.2f}" for i in range(TIMESERIES_DIVISION)]

FIGSIZE = (12, 10)
PREFIX_PATH = "../out/"

QWIC_FLAGS = {
    "P20": "PARSE_FRAME",

    "T10": "TRACK_PACKET_COUNT",
    "T20": "TRACK_RTT",
    "T30": "TRACK_STREAMS",
    "T40": "TRACK_ACKS",
    "T50": "TRACK_GARBAGE",
    "T60": "TRACK_CONN_ID",

    "A10": "ALERT_STREAM_COMMITMENT",
    "A30": "ALERT_SLOWLORIS",
    "A50": "ALERT_STREAM_FRAGMENTATION",
    "A70": "ALERT_PERFORMANCE_ANOMALY",

    "O10": "SAVE_ADDITIONAL_INFO",

    "L10": "PRINT_INFO",
    "L20": "PRINT_FRAMES",
    "L30": "PRINT_TIMES",
    "L40": "PRINT_LOCAL_STATE"
}

BACKENDS = {
    "SC": "Scapy",
    "PY": "Pyshark",
    "TC": "eBPF with TC",
    "XDP": "eBPF with XDP"
}


def parse_lines(lines):
    lost = 0
    samples = []

    __tmp0 = []
    for line in lines:
        if " (DATA) - " in line:
            __tmp0.append(line.split(" (DATA) - ")[1])

    __tmp1 = []
    for line in __tmp0:
        if "Possibly lost" in line:
            # Separate the string with newlines
            # and check if the string is sane
            split_line = line.split("Possibly")
            __tmp1.append(f"{split_line[0]}")
            __tmp1.append(f"Possibly{split_line[1]}")
        elif "samples" in line:
            split_line = line.split("samples")
            __tmp1.append(f"{split_line[0]}samples")
            __tmp1.append(f"{split_line[1]}")
        else:
            __tmp1.append(line.replace("\n\n", "\n").replace("\n", "").strip())

    for line in __tmp1:
        # Remove double newlines
        if line == "\n" or line == "":
            continue

        if line.endswith("\n"):
            line = line[:-1]

        if (result := re.match("Possibly lost (.*?) samples", line)):
            lost += int(result.group(1))
            continue

        if "," in line:
            try:
                samples.append((
                    float(line.split(",")[0]),
                    float(line.split(",")[1]),
                    int(line.split(",")[2])
                ))
            except ValueError:
                pass  # print("Skipping line:", line)
        else:
            pass  # print(f"Skipping line: {line}")

    return lost, samples


def divide_samples(bench):
    # Divide the times to do a box and whisker plot
    sorted_bench = sorted(bench, key=lambda x: x[1])

    base_time = sorted_bench[0][1]
    time_interval = (sorted_bench[-1][1] - base_time) / TIMESERIES_DIVISION
    # print(f"Time interval: {time_interval}")

    divided_samples = []
    for _ in range(TIMESERIES_DIVISION):
        divided_samples.append([])

    i = 0
    for sample in sorted_bench:
        duration, timestamp, _ = sample
        if timestamp - base_time > i * time_interval:
            i += 1
        divided_samples[i - 1].append(duration)

    # for i in range(TIMESERIES_DIVISION):
    #     print(f"{i + 1}: {len(divided_samples[i])}")

    return divided_samples


def plot_box(*args):
    global filename
    # Group samples in a single list
    data_groups = [i["data"] for i in args]

    # Decide where to place information depending on all data
    all_interface = [i["name"]["interface"] for i in args]
    all_backend = [i["name"]["backend"] for i in args]
    all_comment = [i["name"]["comment"].replace("+", " ") for i in args]
    all_active_filters = [i["name"]["active_filters"] for i in args]

    global_comment = args[0]["global_comment"]

    # Generate the plot title and legends
    plot_title = ""

    if len(set(all_interface)) == 1:
        interface = all_interface[0]
        plot_title += f"Interface: {interface}"
    else:
        interface = None

    if len(set(all_backend)) == 1:
        backend = all_backend[0]
        plot_title += f"\nBackend: {BACKENDS[backend]}"
    else:
        backend = None

    if len(set(all_comment)) == 1:
        comment = all_comment[0]
        plot_title += f"\nTraffic type: {comment}"
    else:
        comment = None

    if len(set(all_active_filters)) == 1:
        active_filter = ""
    else:
        active_filter = None

    added_legend = False
    legend_names = []

    for i in range(len(all_active_filters)):
        shorthand = all_active_filters[i]

        flags = shorthand.split(",")

        flag_names = []

        for flag in flags:
            if flag.startswith("L") or flag.startswith("O"):
                continue
            flag_names.append(QWIC_FLAGS[flag].replace("", ""))

        if len(flag_names) == 0:
            flag_names.append("BASELINE")

        legend_name = ""
        if active_filter is None:
            legend_name += ", ".join(flag_names)
        elif not added_legend:
            active_filter = all_active_filters[i]
            plot_title += f"\nActive flags: {fill(', '.join(flag_names), 60)}"
            added_legend = True

        if interface is None:
            if legend_name != "":
                legend_name += " - "
            legend_name += f"{all_interface[i]}"
        if backend is None:
            if legend_name != "":
                legend_name += " - "
            legend_name += f"{all_backend[i]}"
        if comment is None:
            if legend_name != "":
                legend_name += " - "
            legend_name += f"{all_comment[i]}"

        legend_names.append(fill(legend_name, 35))

    # Sanity check if incoeherent data is provided
    lens = [len(i) for i in data_groups]
    if not all(lens):
        print("Not all lists have the same length")
        return

    data_group_len = lens[0]
    length = len(data_groups)

    # LAbel the data
    labels_list = GLOBAL_LABELS[:data_group_len]
    colors = [plt.cm.get_cmap('cool', length)(i) for i in range(length)]
    width = min(1 / len(labels_list), 0.25)
    xlocations = [x * ((1 + length) * width)
                  for x in range(data_group_len)]

    # Calculate ymin and ymax to show only the relevant quantiles
    ymin = +np.Inf
    ymax = -np.Inf

    for option in data_groups:
        # Flatten the list
        option = [item for sublist in option for item in sublist]
        Q1, _, Q3 = np.percentile(np.asarray(option), [25, 50, 75])
        IQR = Q3 - Q1

        loval = Q1 - 1.5 * IQR
        hival = Q3 + 1.5 * IQR

        wiskhi = np.compress(option <= hival, option)
        wisklo = np.compress(option >= loval, option)
        actual_hival = np.max(wiskhi)
        actual_loval = np.min(wisklo)

        actual_hival *= 1.05
        actual_loval *= 0.95

        ymin = min(ymin, actual_loval)
        ymax = max(ymax, actual_hival)

    # Dynamic size if too many data groups are added
    if len(data_groups) > 25:
        plt.figure(figsize=(FIGSIZE[0] + (len(data_groups) - 10), FIGSIZE[1] + (len(data_groups) - 25)))
    elif len(data_groups) > 10:
        plt.figure(figsize=(FIGSIZE[0] + (len(data_groups) - 10), FIGSIZE[1]))
    else:
        plt.figure(figsize=FIGSIZE)

    plt.tight_layout()
    plt.ticklabel_format(style='sci', axis='y', scilimits=(0, 0))
    plt.ylabel('Parsing time (clock cycles)')
    # plt.ylabel('Memory usage (MiB)')
    plt.title(plot_title, fontsize=11)
    # plt.xlabel('X axis label')

    ax = plt.gca()
    ax.set_ylim(ymin, ymax)
    ax.grid(True, linestyle='dotted')
    ax.set_axisbelow(True)
    # ax.yaxis.set_major_formatter(mtick.FormatStrFormatter('%.2e'))

    # Offset the positions per group
    space = max(length / 2, 1)
    # offset = length / 2
    group_positions = []
    for num, dg in enumerate(data_groups):
        _off = (0 - space + (0.5 + num))
        group_positions.append([x+_off * (width + 0.01) for x in xlocations])

    boxes = []

    for dg, pos, c in zip(data_groups, group_positions, colors):
        boxes.append(ax.boxplot(
            dg,
            labels=['']*len(labels_list),
            positions=pos,
            widths=width,
            whis=1.5,
            boxprops=dict(facecolor=c),
            medianprops=dict(color='grey'),
            flierprops=dict(marker=""),
            patch_artist=True)
        )

    if len(labels_list) > 1:
        ax.set_xticks(xlocations)
        ax.set_xticklabels(labels_list, rotation=0)

    types = [box["boxes"][0] for box in boxes]

    box = ax.get_position()
    ax.set_position([box.x0, box.y0, box.width * 0.75, box.height])
    ax.legend(types, legend_names, loc='center left', bbox_to_anchor=(1, 0.5))

    filename = PREFIX_PATH
    if global_comment is not None:
        filename += f"_{global_comment}"
    if interface is not None:
        filename += f"_{interface}"
    if backend is not None:
        filename += f"_{backend}"
    if active_filter is not None:
        filename += f"_{active_filter}"
    if comment is not None:
        filename += f"_{comment}"

    if "/_" in filename:
        filename = filename.replace("/_", "/")

    filename += "_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + ".png"

    plt.savefig(filename)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse output from eBPF")

    # Supports N arguments, one for each file
    parser.add_argument("files", nargs="+", help="Files to parse")
    parser.add_argument("-c", "--comment", required=False, help="Comment to add to the plot")

    args = parser.parse_args()

    # Parse all files
    lost_array = []
    samples_array = []

    for file in args.files:
        with open(file, "r", encoding="ISO-8859-1") as f:
            lines = f.readlines()
            lost, sample = parse_lines(lines)

            # Quick meaan calculation
            array_of_times = [i[0] for i in sample]

            # Normalize file name
            file = file.replace("../in/", "").replace('.out', '')

            _, median, _ = np.percentile(np.asarray(array_of_times), [25, 50, 75])

            sample = {
                "global_comment": args.comment,
                "data": divide_samples(sample),
                "length": len(sample),
                "lost": lost,
                "median": median,
                "name": {
                    "interface": (split_name := file.split("_"))[0],
                    "backend": split_name[1],
                    "active_filters": split_name[2],
                    "date": split_name[3] + "_" + split_name[4] if len(split_name) == 5
                    else split_name[4] + "_" + split_name[5],
                    "comment": split_name[3] if len(split_name) == 6 else ""
                }
            }

            # Try to parse the comment and see if it can be
            # converted directly into a flow value
            try:
                __comment = sample["name"]["comment"].replace("+", " ")
                if "flows" in __comment:
                    # Type like "30 flows * 2M":
                    __comment = __comment.replace("flows", "").replace(" ", "")
                    # Now it should be "30*2M"
                    amount, multiplier = __comment.split("*")

                    if multiplier.endswith("K"):
                        multiplier = multiplier[:-1]
                        multiplier = float(multiplier) * 1000
                    elif multiplier.endswith("M"):
                        multiplier = multiplier[:-1]
                        multiplier = float(multiplier) * 1000000

                    __comment = int(amount) * int(multiplier)

                elif __comment.endswith("K"):
                    __comment = __comment[:-1]
                    __comment = float(__comment) * 1000
                elif __comment.endswith("M"):
                    __comment = __comment[:-1]
                    __comment = float(__comment) * 1000000

                sample["flow_amount"] = __comment
            except Exception as ex:
                print(ex)

            printable_json = sample.copy()
            del printable_json["data"]

            print(
                f"{file}:\n\t{lost} samples lost"
                + f"\n\t{sample['length']} sample parsed"
                + f"\n\t{sample['length'] + lost} total samples"
                + f"\n\t{sample['median']} median time"
                + f"\n\t{printable_json} json"
            )

            samples_array.append(sample)
            lost_array.append(lost)

    samples_array = sorted(samples_array, key=lambda x: (x["flow_amount"], x["median"]))

    plot_box(*samples_array)
