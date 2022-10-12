import math
import matplotlib.pyplot as plt
import numpy as np
import csv

KILOBYTE = 1024
MEGABYTE = KILOBYTE*KILOBYTE
GIGABYTE = MEGABYTE*KILOBYTE
TERABYTE = GIGABYTE*KILOBYTE


def display_human_friendly_amount(bytes):
    # Display a memory amount in a human friendly format.
    # Works with B, KB, MB, GB, TB.
    if bytes < KILOBYTE:
        return str(bytes) + "B"
    elif bytes < MEGABYTE:
        return str(bytes // KILOBYTE) + "KB"
    elif bytes < GIGABYTE:
        return str(bytes // MEGABYTE) + "MB"
    elif bytes < TERABYTE:
        return str(bytes // GIGABYTE) + "GB"


def get_flow_number(flow: str) -> int:
    if "flows" in flow:
        return int(flow.replace(" ", "").replace("flows", "").split("*")[0])
    else:
        return 1


def get_flow_amount(flow: str) -> int:
    if flow == "10K":
        return 10 * KILOBYTE
    elif flow == "100K":
        return 100 * KILOBYTE
    elif flow == "1M":
        return MEGABYTE
    elif "flows" in flow:
        flow = flow.replace(" ", "").replace("flows", "")
        # Now it's in the format "100*1M"
        if "M" in flow:
            count, size = flow.split("*")
            size = size.replace("M", "")
            return int(count) * int(size) * MEGABYTE
        else:
            raise ValueError("Invalid flow amount: " + flow)


if __name__ == "__main__":
    with open("../in/memoryusage.csv", "r") as f:
        # L30+T60,10 flows * 1M,1362691,122888,100.0

        reader = csv.reader(f)
        data = list(reader)

        max_data = []    # Extract uniques points so we can map an offset for each

        current = ("", "", 0, 0)
        for row in data:
            filters, flow, pid, mem, cpu = row
            if current[2] == pid:
                current = (filters, flow, pid, max(mem, current[3]))
            else:
                if current[2] != -1:
                    max_data.append(current)
                current = (filters, flow, pid, mem)

        max_data.append(current)
        max_data.pop(0)
        max_data = sorted(max_data, key=lambda x: get_flow_amount(x[1]))

        x = []
        y = []

        flow_conds = []
        scenario_conds = []
        alert_scenario_conds = []

        for row in max_data:
            filters, flow, pid, mem = row
            # if (get_flow_amount(flow)) != MEGABYTE:
            #     continue

            # print(",".join([filters, flow, str(pid), str(mem)]))  # , end="")
            # print(f" => {display_human_friendly_amount(get_flow_amount(flow))}")

            x.append(get_flow_amount(flow))
            y.append(int(mem) / 1024)

            # Calculate amount of flows
            if "1000 flows" in flow:
                flow_amount = 1000
            elif "100 flows" in flow:
                flow_amount = 100
            elif "10 flows" in flow:
                flow_amount = 10
            else:
                flow_amount = 1

            flow_conds.append(flow_amount)

            # Calculate scenario
            if filters == "L30":
                scenario_conds.append(0)
            elif filters in ("L30+T10", "L30+T20", "L30+T30", "L30+T40", "L30+T50", "L30+T60"):
                scenario_conds.append(10)
            elif filters == "L30+T10+T20+T30+T40+T50+T60":
                scenario_conds.append(11)
            elif filters in ("L30+A10", "L30+A30", "L30+A50", "L30+A70"):
                scenario_conds.append(10)
            elif filters == "L30+A10+A30+A50+A70":
                scenario_conds.append(11)
            else:
                scenario_conds.append(1000)

            if filters == "L30":
                alert_scenario_conds.append(0)
            elif filters == "L30+A10":
                alert_scenario_conds.append(10)
            elif filters == "L30+A30":
                alert_scenario_conds.append(30)
            elif filters == "L30+A50":
                alert_scenario_conds.append(50)
            elif filters == "L30+A70":
                alert_scenario_conds.append(70)
            elif filters == "L30+A10+A30+A50+A70":
                alert_scenario_conds.append(160)
            else:
                alert_scenario_conds.append(1000)

        x = np.array(x)
        y = np.array(y)
        flow_conds = np.array(flow_conds)
        scenario_conds = np.array(scenario_conds)
        alert_scenario_conds = np.array(alert_scenario_conds)

        plt.tight_layout()
        plt.figure(figsize=(12, 10))
        # plt.ylim(17, 30) Limits used for the main graph

        ax = plt.gca()
        ax.set_xscale('log', base=2)

        # z = np.polyfit(x, y, 1)
        # p = np.poly1d(z)
        # plt.plot(x, p(x), "r--")

        conditions = (
            # (flow_conds == 1000), (flow_conds == 100), (flow_conds == 10), (flow_conds == 1),
            # (scenario_conds == 0), (scenario_conds == 10), (scenario_conds == 11),
            (1 == 1),
            # (alert_scenario_conds == 0), (alert_scenario_conds == 10),
            # (alert_scenario_conds == 30), (alert_scenario_conds == 50),
            # (alert_scenario_conds == 70), (alert_scenario_conds == 160),
        )

        # names = ("1000 flows", "100 flows", "10 flows", "1 flow")
        # names = ("Baseline", "Single scenario", "All scenarios")
        names = ("Single run",)
        # names = ("Baseline", "Stream commitment", "SlowLoris",
        # "Stream fragmentation", "Perf. anomaly", "All", "Discarded")

        cmap = plt.cm.get_cmap("inferno", 4)
        # cmap = plt.cm.get_cmap("tab10")
        # cmap = plt.cm.get_cmap("tab10", 10)

        axes = []

        for i in range(len(conditions)):
            axes.append(
                ax.scatter(
                    x[conditions[i]],
                    y[conditions[i]],
                    marker='o',
                    edgecolors='black',
                    s=90,
                    color=cmap(i),
                    alpha=0.85
                )
            )

        box = ax.get_position()
        ax.set_position([box.x0, box.y0, box.width * 0.85, box.height])
        ax.legend(
            axes,
            names,
            scatterpoints=1,
            loc='center left',
            bbox_to_anchor=(1, 0.5)
        )

        ax.set_xticks([
            10*KILOBYTE, 100*KILOBYTE,
            MEGABYTE, 10*MEGABYTE, 100*MEGABYTE,
            GIGABYTE, 10*GIGABYTE
        ])
        ax.set_xticklabels([
            "10KiB", "100KiB",
            "1MiB", "10MiB", "100MiB",
            "1GiB", "10GiB"
        ])

        plt.xlabel('Sum of all flows')
        plt.ylabel('Memory usage (Megabytes)')

        plt.title("Maximum resident memory usage for different flows")

        plt.savefig("../out/__memory.png")
        plt.clf()
        plt.close()
