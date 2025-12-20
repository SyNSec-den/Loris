emulate: build-firmwire
    docker run --rm -it \
        -v $(pwd)/FirmWire:/firmwire \
        -v $(pwd)/binaries:/binaries \
        --name loris-emulator \
        loris-emulator

build-firmwire: update-submodules
    docker build -t loris-emulator -f FirmWire/Dockerfile FirmWire

update-submodules:
    git submodule update --init

[default]
default:
    @just --list
