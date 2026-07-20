import logging
import sys

from typing import Optional

LOG_SIM = 1 << 0
LOG_HEAP = 1 << 1
LOG_MEM = 1 << 2
LOG_CONC = 1 << 3
LOG_PATH = 1 << 4
LOG_EXEC = 1 << 5
LOG_SOLVER = 1 << 6
LOG_LOADER = 1 << 7
LOG_ALL = (1 << 8) - 1

MASK_NAMES = {
    "sim": LOG_SIM,
    "heap": LOG_HEAP,
    "mem": LOG_MEM,
    "conc": LOG_CONC,
    "path": LOG_PATH,
    "exec": LOG_EXEC,
    "solver": LOG_SOLVER,
    "loader": LOG_LOADER,
    "all": LOG_ALL,
}

_mask: int = 0


def parse_mask(mask_str: str) -> int:
    result = 0
    for name in mask_str.split(","):
        name = name.strip().lower()
        if name not in MASK_NAMES:
            available = ", ".join(sorted(MASK_NAMES))
            raise ValueError(f"Unknown log mask: '{name}'. Available: {available}")
        result |= MASK_NAMES[name]
    return result


def log_enabled(mask: int) -> bool:
    return bool(_mask & mask)


def dlog(mask: int, msg: str):
    if _mask & mask:
        logging.getLogger("loris_analyzer").debug(msg)


def setup_logging(
    debug: bool = False,
    mask: int = 0,
    log_file: Optional[str] = None,
    angr_loglevel: Optional[str] = None,
    firmwire_loglevel: Optional[str] = None,
):
    global _mask

    if debug:
        _mask = LOG_ALL
    else:
        _mask = mask

    level = logging.DEBUG if _mask else logging.INFO

    logging.addLevelName(logging.INFO, "INFO")
    logging.addLevelName(logging.WARNING, "WARN")
    logging.addLevelName(logging.ERROR, "ERROR")
    logging.addLevelName(logging.CRITICAL, "CRIT")

    la_log = logging.getLogger("loris_analyzer")
    la_log.setLevel(level)
    la_log.propagate = False

    term_handler = logging.StreamHandler(sys.stdout)
    term_handler.setLevel(logging.INFO if (log_file and _mask) else level)
    term_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    la_log.addHandler(term_handler)

    if log_file and _mask:
        file_handler = logging.FileHandler(log_file, mode="w")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        )
        la_log.addHandler(file_handler)

    angr_log = logging.getLogger("angr")
    if angr_loglevel:
        angr_log.setLevel(angr_loglevel)
    else:
        angr_log.propagate = False

    firmwire_log = logging.getLogger("firmwire")
    if firmwire_loglevel:
        firmwire_log.setLevel(firmwire_loglevel)
    else:
        firmwire_log.propagate = False
