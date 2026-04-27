FROM ubuntu:20.04
LABEL "about"="Loris Analyzer base img"

ARG DEBIAN_FRONTEND=noninteractive
ENV IS_DOCKER="1"

RUN apt-get update && apt-get upgrade -y && \
        apt-get -y install --no-install-suggests --no-install-recommends \
        automake \
        bison flex \
        build-essential cmake \
        chrpath \
        git zip zsh openssh-client \
        clang clang-tools \
        libglib2.0-dev gcc-arm-none-eabi \
        libtool libtool-bin \
        wget curl vim \
        apt-utils apt-transport-https ca-certificates gnupg dialog \
        libpixman-1-dev \
        libc++-dev libcurl4-openssl-dev libelf-dev libffi-dev libdwarf-dev libelf-dev libwiretap-dev wireshark-dev \
        protobuf-compiler protobuf-c-compiler libprotoc-dev libprotobuf-dev libprotobuf-c-dev libjsoncpp-dev \
        gdb-multiarch qemu-utils libcapstone-dev \
    && apt-get update \
    && apt-get install -y gcc-9-mipsel-linux-gnu gcc-9-multilib \
    && update-alternatives --install /usr/bin/mipsel-linux-gnu-gcc mipsel-linux-gnu-gcc /usr/bin/mipsel-linux-gnu-gcc-9 10

RUN wget https://downloads.python.org/pypy/pypy3.11-v7.3.21-linux64.tar.bz2 \
    && tar xf pypy3.11-v7.3.21-linux64.tar.bz2 \
    && mv pypy3.11-v7.3.21-linux64 /opt/pypy3.11

# Install Rust via rustup
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

ENV PATH="/opt/pypy3.11/bin:${PATH}"
RUN pypy3 -m ensurepip

RUN apt-get -y install --no-install-suggests --no-install-recommends \
    libc++-dev libcurl4-openssl-dev libelf-dev libffi-dev libdwarf-dev libelf-dev libwiretap-dev wireshark-dev python3-pycparser \
    protobuf-compiler protobuf-c-compiler libprotoc-dev libprotobuf-dev libprotobuf-c-dev libjsoncpp-dev

RUN pypy3 -m pip install angr==9.2.54 lz4

# Install panda, and deps for Shannon Panda
WORKDIR /firmwire_deps
RUN rm -rf panda \
    && git clone --depth=1 https://github.com/SyNSec-den/panda.git \
    && cd panda \
    && git checkout loris \
    && rm -rf build \
    && mkdir build \
    && cd build \
    && ../configure --disable-werror --target-list=arm-softmmu,mipsel-softmmu \
        --cc=gcc-9 \
        --cxx=g++-9 \
        --disable-sdl \
        --disable-user \
        --disable-linux-user \
        --disable-pyperipheral3 \
        --disable-bsd-user \
        --disable-vte \
        --disable-curses \
        --disable-vnc \
        --disable-vnc-sasl \
        --disable-vnc-jpeg \
        --disable-vnc-png \
        --disable-cocoa \
        --disable-virtfs \
        --disable-xen \
        --disable-xen-pci-passthrough \
        --disable-brlapi \
        --disable-curl \
        --disable-bluez \
        --disable-kvm \
        --disable-hax \
        --disable-rdma \
        --disable-vde \
        --disable-netmap \
        --disable-linux-aio \
        --disable-cap-ng \
        --disable-attr \
        --disable-vhost-net \
        --disable-spice \
        --disable-rbd \
        --disable-gtk \
        --disable-gnutls \
        --disable-gcrypt \
        --disable-libiscsi \
        --disable-libnfs \
        --disable-smartcard \
        --disable-libusb \
        --disable-usb-redir \
        --disable-lzo \
        --disable-snappy \
        --disable-bzip2 \
        --disable-seccomp \
        --disable-coroutine-pool \
        --disable-glusterfs \
        --disable-tpm \
        --disable-libssh2 \
        --disable-numa \
        --disable-tcmalloc \
        --disable-jemalloc \
        --disable-replication \
        --disable-vhost-vsock \
        --disable-opengl \
        --disable-virglrenderer \
        ;
RUN cd panda/build && make -j `nproc` \
    && cd /firmwire_deps/panda/panda/python/core/ \
    && python3 setup.py install

COPY FirmWire /loris_analyzer_deps/FirmWire
RUN pypy3 -m pip install -r /loris_analyzer_deps/FirmWire/requirements.txt
ENV PYTHONPATH="/loris_analyzer_deps/FirmWire/"

COPY analyzer /loris_analyzer
RUN pypy3 -m pip install -r /loris_analyzer/requirements.txt
ENV PYTHONPATH="${PYTHONPATH}:/loris_analyzer/"

RUN pypy3 -m pip install pycparser==2.21 protobuf==3.20.3

WORKDIR /loris_analyzer
CMD [ "/bin/bash" ]
