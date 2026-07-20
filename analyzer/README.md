# Loris Analyzer

## Overview

The Loris analyzer uses [angr](https://angr.io/) for symbolic execution of baseband firmware. Since angr is inherently slow ([why](https://docs.angr.io/en/latest/faq.html#why-is-angr-so-slow)), Loris runs it under PyPy3 instead of CPython for roughly 4x faster analysis.

However, preparing the firmware binary for angr requires [FirmWire](https://github.com/FirmWire/FirmWire), which is incompatible with PyPy3. This leads to a two-stage Docker workflow:

1. **Loader snapshot** (CPython + FirmWire) — creates a loader object snapshot (gzipped pickle of the binary blob ready for angr).
2. **Long-run analysis** (PyPy3 + angr) — loads the snapshot and performs symbolic execution. *(Instructions TBD)*

## Creating a Loader Snapshot

The snapshot stage uses `Dockerfile.firmwire` to build a CPython environment with FirmWire and angr. It runs a single analysis iteration to produce the loader snapshot.

From the repository root:

```bash
just analyzer-snapshot <path/to/binary>
```

For example:

```bash
just analyzer-snapshot binaries/oriole-bp3a.250905.014/modem.bin
```

This will:
1. Build the `loris-analyzer:firmwire` Docker image (if not already built)
2. Run the analyzer container with CPython, executing a single iteration (`-n 1`) to generate the snapshot
3. Output the snapshot to `<binary>_workspace/loader.pickle.gz`

## Run Analyzer

Prepare the analyzer container running `just analyze` and from container run:
- The `--goal` function address comes from spec file from `ret_one` list; it's the function with `Warn>Decode Error: 0x%x` comment.
- The `--init-func` for `SAEL3` is called from `SAEL3_Main` before entering while loop. See two examples below.
- Below is the list of 4G NAS mobility management message IDs with protocol discriminator (`--pd`) 7.

```python
NAS_EMM_IDS = {0x42, 0x44, 0x45, 0x46, 0x49, 0x4b, 0x4e, 0x4f, 0x50, 0x52, 0x54,
               0x55, 0x5d, 0x60, 0x61, 0x62, 0x64, 0x68}
```

1. 10 iterations of SAEL3 (4G NAS) analysis for a single message ID on a Pixel 6 image:
```bash
MODEM="oriole-bp3a.250905.014"
NAS="0x42"
WORKSPACE="_output/${MODEM}/0x3c7b.d/0.${NAS}.d/"
mkdir -p "${WORKSPACE}"
cp "/binaries/${MODEM}/modem.bin_workspace/loader.pickle.gz" "${WORKSPACE}/"
./analyzer.py -n 10 -w "${WORKSPACE}" --goal 0x430F96D8 --init-func 0x42A0F104 --spec "vendor_spec/${MODEM}.py" --nas "${NAS}" --pd 7
```

2. Similarly, 10 iterations of SAEL3 (4G NAS) analysis for a single message ID on a Galaxy S21 image:
```bash
MODEM="G991BXXUEGXJE"
NAS="0x54"
WORKSPACE="_output/${MODEM}/0x3c7b.d/0.${NAS}.d/"
mkdir -p "${WORKSPACE}"
cp "/binaries/CP_G991BXXUEGXJE_CP28097318_MQB88157872_REV01_user_low_ship_MULTI_CERT/modem.bin_workspace/loader.pickle.gz" "${WORKSPACE}/"
./analyzer.py -n 10 -w "${WORKSPACE}" --goal 0x418C91D1 --init-func 0x418A6E6A --spec "vendor_spec/${MODEM}.py" --nas "${NAS}" --pd 7 --soft-memory-limit $((60*1024)) > "${WORKSPACE}/output.log" 2>&1
```
