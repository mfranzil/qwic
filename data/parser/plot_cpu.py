import matplotlib.pyplot as plt
import numpy as np
import csv


def smooth(x, window_len=11, window='hanning'):
    if x.ndim != 1:
        raise ValueError("smooth only accepts 1 dimension arrays.")
    if x.size < window_len:
        raise ValueError("Input vector needs to be bigger than window size.")
    if window_len < 3:
        return x
    if window not in ['flat', 'hanning', 'hamming', 'bartlett', 'blackman']:
        raise ValueError(
            "Window is on of 'flat', 'hanning', 'hamming', 'bartlett', 'blackman'")
    s = np.r_[2*x[0]-x[window_len-1::-1], x, 2*x[-1]-x[-1:-window_len:-1]]
    if window == 'flat':  # moving average
        w = np.ones(window_len, 'd')
    else:
        w = eval('np.'+window+'(window_len)')
    y = np.convolve(w/w.sum(), s, mode='same')
    return y[window_len:-window_len+1]


def get_flow_amount(flow: str) -> int:
    if flow == "10K":
        return 10000
    elif flow == "100K":
        return 100000
    elif flow == "1M":
        return 1000000
    elif flow == "10 flows * 1M":
        return 10 * 1000000
    elif flow == "100 flows * 1M" or flow == "10 flows * 10M":
        return 100 * 1000000
    elif flow == "1000 flows * 1M":
        return 1000 * 1000000


if __name__ == "__main__":
    with open("../in/memoryusage.csv", "r") as f:
        # L30+T60,10 flows * 1M,1362691,122888,100.0

        reader = csv.reader(f)
        data = list(reader)

        per_pid_data = {}

        # Isolate data per-PID
        this_pid = 0
        for i in range(len(data)):
            current_pid = data[i][2]
            if current_pid != this_pid:
                this_pid = current_pid
                pid_data = {
                    "cpu": [],
                    "flow": data[i][1],
                    "filter": data[i][0],
                }
                per_pid_data[current_pid] = pid_data
            try:
                last_cpu = per_pid_data[current_pid]["cpu"][-1]
                if last_cpu == 0.0 and float(data[i][4]) == 0.0:
                    continue
            except IndexError:
                pass

            per_pid_data[this_pid]["cpu"].append(float(data[i][4]))

        # print(per_pid_data)

        plt.tight_layout()
        plt.figure(figsize=(12, 10))

        # Plot everything in a single plot
        ax = plt.gca()

        c = 0

        a1, a2 = None, None

        for pid, data in per_pid_data.items():
            if 100 >= len(data["cpu"]) >= 30:
                for i in range(8):
                    data["cpu"].append(0.0)
                    data["cpu"].insert(0, 0.0)

                #flow_amount = get_flow_amount(data["flow"])
                #log_flow_amount = np.log10(flow_amount)
                #if round(float(log_flow_amount), 0) == 7.0:
                #    continue

                if data["flow"] == "100 flows * 1M":
                    color = 0x1f77b4
                elif data["flow"] == "10 flows * 10M":
                    color = 0xeca02c

                #actual_shifted_color = (color - 10 * (c := c + 1)) % 0xffffff
                color = "#" + hex(color).replace("0x", "").zfill(6)

                cpu = np.array([i for i in data["cpu"]])
                cpu_smooth = smooth(cpu, window_len=10, window='flat')

                tmp = ax.plot(cpu_smooth, label=pid, alpha=0.6, color=color)

                if data["flow"] == "100 flows * 1M":
                    a1 = tmp
                elif data["flow"] == "10 flows * 10M":
                    a2 = tmp
            else:
                pass
                # print("Not enough data for PID {pid} with length {length}".format(pid=pid, length=len(data["cpu"])))

        box = ax.get_position()
        ax.set_position([box.x0, box.y0, box.width * 0.85, box.height])
        ax.legend(
            (a1[0], a2[0]),
            ("100 flows * 1MiB", "10 flows * 10MiB"),
            loc='center left', bbox_to_anchor=(1, 0.5))
        
        plt.xlabel('Time (s)')
        plt.ylabel('CPU usage (%)')

        plt.title("CPU usage for 100 MiB flows")

        plt.savefig("../out/__cpu.png")
