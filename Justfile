emulate: build-firmwire
    docker run --rm -it \
        -v $(pwd)/FirmWire:/firmwire \
        -v $(pwd)/binaries:/binaries \
        --name loris-emulator \
        loris-emulator

analyze:

analyzer-snapshot binary: build-analyzer-firmwire
    rm -f {{binary}}_workspace/loader.pickle.gz
    docker run --rm -it \
        -v $(pwd)/analyzer:/loris_analyzer \
        -v $(pwd)/binaries:/binaries \
        -v $(pwd)/FirmWire:/loris_analyzer_deps/FirmWire \
        --name loris-analyzer-snapshot loris-analyzer:firmwire \
        python3 analyzer.py -n 1 --debug --firmwire-log debug --angr-log info -b /{{binary}}

analyzer-firmwire: build-analyzer-firmwire
    docker run --rm -it \
        -v $(pwd)/analyzer:/loris_analyzer \
        -v $(pwd)/binaries:/binaries \
        -v $(pwd)/FirmWire:/loris_analyzer_deps/FirmWire \
        --name loris-analyzer-firmwire loris-analyzer:firmwire

build-analyzer-firmwire:
    docker image build \
        -t loris-analyzer:firmwire \
        -f analyzer/Dockerfile.firmwire \
        .

build-firmwire: update-submodules
    docker image build \
        -t loris-emulator \
        -f FirmWire/Dockerfile \
        FirmWire

update-submodules:
    git submodule update --init

[default]
default:
    @just --list
