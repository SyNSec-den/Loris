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
