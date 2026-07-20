#!/usr/bin/env python3
import argparse
import glob
import json
import os
import pickle
import random
import re
import sys

from pathlib import Path
from typing import Dict, Optional, Set, Tuple

NAS_EMM_IDS = {
    0x42,
    0x44,
    0x45,
    0x46,
    0x49,
    0x4B,
    0x4E,
    0x4F,
    0x50,
    0x52,
    0x54,
    0x55,
    0x5D,
    0x60,
    0x61,
    0x62,
    0x64,
    0x68,
}
NAS_ESM_IDS = {
    0xC1,
    0xC5,
    0xC9,
    0xCD,
    0xD1,
    0xD3,
    0xD5,
    0xD7,
    0xD9,
    0xDB,
    0xDC,
    0xE8,
    0xEA,
    0xEB,
}


def number_parse(s):
    match = re.match(r"^(0x[a-fA-f0-9]+)|([0-9]+)$", s)

    if not match:
        raise argparse.ArgumentTypeError('expected number, got "{}"'.format(s))

    if match.group(1):
        return int(match.group(1), 16)
    elif match.group(2):
        return int(match.group(2), 10)
    else:
        assert 0


def get_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "-i",
        "--in-dir",
        type=str,
        required=True,
        help="Input directory to read solutions",
    )
    parser.add_argument(
        "-o",
        "--out-dir",
        type=str,
        required=True,
        help="Output directory to store samples",
    )
    parser.add_argument(
        "--src-qid", type=number_parse, required=True, help="Source queue ID"
    )
    parser.add_argument(
        "--dst-qid", type=number_parse, required=True, help="Destination queue ID"
    )
    parser.add_argument("-f", type=str, help="Input corpus with NAS messages")
    parser.add_argument(
        "-n", type=int, default=None, help="The iteration index to parse"
    )

    return parser.parse_args()


def random_value_desc(solution: Dict[str, list]):
    _vars = list()
    for k, s in solution.items():
        if k[0] != "VAR":
            continue
        i = random.randrange(len(s))
        if isinstance(s[i], int):
            _vars.append(
                {
                    "addr": k[1],
                    "size": k[2],
                    "value": s[i],
                }
            )
        elif isinstance(s[i], range):
            _vars.append(
                {
                    "addr": k[1],
                    "size": k[2],
                    "value": random.randrange(s[i].start, s[i].stop),
                }
            )
    return _vars


def freeze(d):
    if isinstance(d, dict):
        return frozenset((key, freeze(value)) for key, value in d.items())
    elif isinstance(d, list):
        return tuple(freeze(value) for value in d)
    return d


def get_input_values(solution: Dict[str, list]) -> Tuple[int, int]:
    sht_pd, nas_msg_id = None, None
    for k, v in solution.items():
        if k[0] == "INPUT" and k[3] == "NAS_MSG_ID":
            nas_msg_id = next(iter(v))
        elif k[0] == "INPUT" and k[3] == "SHT_PD":
            sht_pd = next(iter(v))

    assert nas_msg_id is not None
    assert sht_pd is not None
    return sht_pd, nas_msg_id


def load_sample_inputs(input_dir: str, g=4):
    samples = dict()
    for fp in glob.glob(f"{input_dir}/*"):
        with open(fp, "rb") as f:
            data = f.read()
            if g == 4:
                sht_pd = data[0]
                if sht_pd & 0xF == 7:
                    msg_id = data[1]
                elif sht_pd & 0xF == 2:
                    msg_id = data[2]
                else:
                    # Warn
                    continue
            else:
                # Warn
                continue
            samples[f"{sht_pd:02x}{msg_id:02x}"] = data
    return samples


def to_loris_input(
    solution: Dict[str, list],
    samples: Dict[str, bytes],
    use_samples: bool = False,
    src_qid: int = 0xBC,
    dst_qid: int = 0x18,
    memo: Optional[Set[int]] = None,
):
    c = 0
    while c < 2:
        pre_cond = random_value_desc(solution)
        if memo is None:
            memo = set()
        h = hash(freeze(pre_cond))
        if h in memo:
            c += 1
            continue
        else:
            c = 0
            memo.add(h)
        if c == 2:
            break
        post_mem = list()
        sht_pd, nas_msg_id = get_input_values(solution)
        if use_samples:
            grammar_string = samples.get(f"{sht_pd:02x}{nas_msg_id:02x}", b"")
            grammar_string = [b for b in grammar_string]
            assert len(grammar_string) > 0
        elif nas_msg_id in NAS_EMM_IDS:
            grammar_string = [sht_pd, nas_msg_id]
        elif nas_msg_id in NAS_ESM_IDS:
            grammar_string = [sht_pd, 0, nas_msg_id]
        else:
            raise KeyError(f"no such message: {nas_msg_id:#x}")
        payload = [
            {"Array": {"BytesInput": {"bytes": [0, 0, 0, 0]}}},
            {"IndirU32": {"BytesInput": {"bytes": grammar_string}}},
            # {"IndirU32": {"GrammarInput": {"fields": [], "string": grammar_string}}}
        ]
        header_size = 0xC
        msg_id = 0x3C7B
        out = {
            "pre_cond": {"Ensure": pre_cond},
            "post_mem": {"Observe": post_mem},
            "input": {
                "vendor_input": {
                    "ShannonInput": {
                        "Sael3Input": [
                            {
                                "header": {
                                    "op": {
                                        "MBox": {"src_qid": src_qid, "dst_qid": dst_qid}
                                    },
                                    "size": header_size,
                                    "message_group": msg_id,
                                },
                                "payload": payload,
                            }
                        ]
                    }
                }
            },
        }

        yield out


def main():
    args = get_args()
    args.in_dir = Path(args.in_dir)
    args.out_dir = Path(args.out_dir)

    pat = re.compile("(avoid|found).solutions.([0-9]+).([0-9]+).pickle")
    all_files = [f for f in os.listdir(args.in_dir) if pat.match(f)]

    use_samples = False
    samples = dict()
    if args.f:
        samples = load_sample_inputs(args.f)
        use_samples = True

    # Group files by iteration index
    files_by_iter = dict()
    for f in all_files:
        iter_idx = int(pat.search(f).group(2), 10)
        if files_by_iter.get(iter_idx) is None:
            files_by_iter[iter_idx] = set()
        files_by_iter[iter_idx].add(f)

    global_idx = 0
    for iter_idx, files in (
        files_by_iter.items() if args.n is None else [(args.n, files_by_iter[args.n])]
    ):
        out_dir = args.out_dir.joinpath(f"{iter_idx}")
        out_dir.mkdir(parents=True, exist_ok=True)
        total = 0
        for f in files:
            file_count = 0
            with open(args.in_dir.joinpath(f), "rb") as sol:
                solution = pickle.load(sol)
                memo = set()
                for sample in to_loris_input(
                    solution,
                    samples,
                    use_samples=use_samples,
                    src_qid=args.src_qid,
                    dst_qid=args.dst_qid,
                    memo=memo,
                ):
                    file_count += 1
                    with open(
                        out_dir.joinpath(f"idx_{global_idx:08}.json"), "w"
                    ) as samp:
                        json.dump(sample, samp)
                    global_idx += 1

                    if file_count >= 10:
                        break
                total += file_count

    return 0


if __name__ == "__main__":
    sys.exit(main())
