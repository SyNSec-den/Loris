#!/usr/bin/env pypy3
import argparse
import copy
import logging
import resource
import sys
import z3  # type: ignore

import loris_analyzer as loris

log = logging.getLogger("loris_analyzer")


def get_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "-w", "--workspace", type=str, default=None, help="Analysis workspace path"
    )
    parser.add_argument(
        "--goal",
        type=loris.utils.number_parse,
        default=0,
        help="The goal address to execute",
    )
    parser.add_argument(
        "-s", action="store_true", help="Stop analysis if goal is found"
    )
    parser.add_argument(
        "--init-func",
        type=loris.utils.number_parse,
        default=None,
        help="The function to record initialized state variables",
    )
    parser.add_argument(
        "-n", type=int, default=None, help="Number of analysis iterations"
    )
    parser.add_argument(
        "--soft-memory-limit",
        type=int,
        default=32 * 1024,
        help="Per-job resident memory usage threshold (in MiB) at which caches will be cleared to "
        "free memory; if this does not bring memory usage below the limit, the job will "
        "terminate.",
    )
    parser.add_argument(
        "--nas",
        type=loris.utils.number_parse,
        default=None,
        help="Analyze single NAS message ID",
    )
    parser.add_argument(
        "--pd",
        type=loris.utils.number_parse,
        default=7,
        help="Analyze single NAS protocol discriminator",
    )

    loader = parser.add_argument_group("loader")
    loader.add_argument(
        "-b", "--modem_file", type=str, default=None, help="Modem file to analyze"
    )
    loader.add_argument(
        "-t",
        "--task",
        type=str.upper,
        choices=["SAEL3", "NASOT", "EMM"],
        default="SAEL3",
        help="Task name to analyze",
    )
    loader.add_argument("--spec", type=str, help="Modem specific configurations")
    loader.add_argument(
        "--mtk-loader-nv_data", type=str, help="A path to MTK vendor data directory"
    )

    devopts = parser.add_argument_group("developer options")
    devopts.add_argument(
        "--debug", action="store_true", help="Enable Baseband Analyzer debugging"
    )
    devopts.add_argument(
        "--angr-log",
        type=str.upper,
        choices=["INFO", "DEBUG", "WARNING", "ERROR"],
        default=None,
        help="Enable logging for angr",
    )
    devopts.add_argument(
        "--firmwire-log",
        type=str.upper,
        choices=["INFO", "DEBUG", "WARNING", "ERROR"],
        default=None,
        help="Enable logging for FirmWire",
    )

    args = parser.parse_args()

    if not (args.modem_file or args.workspace):
        parser.error("Either `modem_file` or the `workspace` dir is required")

    return args


def main() -> int:
    args = get_args()
    args.rem = args.n if (args.n is not None and args.n > 0) else 1

    loris.setup_logging(
        debug=args.debug,
        angr_loglevel=args.angr_log,
        firmwire_loglevel=args.firmwire_log,
    )

    max_stack_frames = 0x10000
    resource.setrlimit(
        resource.RLIMIT_STACK, (0x100 * max_stack_frames, resource.RLIM_INFINITY)
    )
    sys.setrecursionlimit(max_stack_frames)

    while args.rem > 0:
        loader = loris.load_any(
            args.modem_file,
            args.workspace,
            args.task,
            args.init_func,
        )

        if loader is None:
            log.error("Failed to load project")
            return 1

        if args.n == 0:
            break

        if args.workspace:
            workspace = loris.Workspace(args.workspace)
        else:
            workspace = copy.copy(loader.workspace)

        try:
            analyzer = loris.LorisAnalyzer(
                workspace, args.spec, loader, args.soft_memory_limit
            )
            analyzer.run(args)
            analyzer.log_stats()
        except z3.Z3Exception as ex:
            analyzer.log_stats()
            args.n = args.rem
            log.warning(f"Caught a Z3Exception({ex}). Remaining iterations: {args.n}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
