import json
import numpy as np

from sboxes import SBox


def load(path: str):
    data = json.load(open(path))

    if data.get("input_size") is None:
        raise ValueError("Input size must be specified")
    if data.get("output_size") is None:
        raise ValueError("Output size must be specified")
    if data.get("table") is None:
        raise ValueError("Table must be specified")

    table = data["table"]

    if len(table) != 1 << data["input_size"]:
        raise ValueError("Table size must match input size")

    biggest_possible_output = 1 << data["output_size"]

    final_table = np.empty(len(table), dtype=np.uint64)

    for idx, i in enumerate(data["table"]):
        output = int(i, 0)
        if output > biggest_possible_output or output < 0:
            raise ValueError("Table values must be greater than or equal to 0 and less than or equal to 2^%d" % data["output_size"])
        final_table[idx] = output

    sbox = SBox(data["input_size"], data["output_size"], final_table, data["name"])

    return sbox