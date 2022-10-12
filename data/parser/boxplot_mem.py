import numpy as np
import csv
from scatterplot_mem import get_flow_number, get_flow_amount, MEGABYTE

if __name__ == "__main__":
    with open("../in/memoryusage.csv", "r") as f:

        reader = csv.reader(f)
        data = list(reader)

        all_data = []

        all_data = sorted(all_data, key=lambda x: np.median(x[3]))

        all_data = [
            all_data[0],
            all_data[4],
            all_data[3],
            all_data[1],
            all_data[2],
            all_data[5]
        ]

        samples = []

        for row in all_data:
            filters, flow, pid, mem = row

            mem *= 0.92

            sample = {
                "global_comment": "memoryboxplot",
                "data": [mem],
                "length": len(mem),
                "lost": 0,
                "median": np.median(mem),
                "name": {
                    "interface": "any",
                    "backend": "SC",
                    "active_filters": filters,
                    "date": "none",
                    "comment": flow
                }
            }

            samples.append(sample)

        from parse_output import plot_box

        plot_box(*samples)
