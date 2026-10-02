# AIS-catcher built from this source tree with SoapySDR and the LiteX-M2SDR Soapy module,
# configured by a JSON config file mounted into the container.
#
# The m2sdr kernel driver is not part of the image: build and load it on the host
# (litex_m2sdr/software/kernel), then pass the device node and the config file to the container
# (docker/aiscatcher.json is an example):
#
#   docker build -t ais-catcher-m2sdr .
#   docker run -d --restart unless-stopped --device /dev/m2sdr0 \
#       -v /etc/aiscatcher:/etc/aiscatcher:ro ais-catcher-m2sdr
#
# The entrypoint runs AIS-catcher -X off -C $AISCATCHER_CONFIG; arguments starting with '-'
# are appended (e.g. -v 60). Anything else runs as a command, e.g. to check the board:
#
#   docker run --rm --device /dev/m2sdr0 ais-catcher-m2sdr SoapySDRUtil --probe=driver=LiteXM2SDR
#   docker run --rm --device /dev/m2sdr0 ais-catcher-m2sdr m2sdr_util -d /dev/m2sdr0 info

ARG DEBIAN_RELEASE=bookworm

FROM debian:${DEBIAN_RELEASE}-slim AS build

# pinned for reproducible builds; any commit or branch of enjoy-digital/litex_m2sdr works
ARG LITEX_M2SDR_REF=31c1923aab81ef2283452cabd713c26a3a4c05f1
ARG RUN_NUMBER=0

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential cmake pkg-config git ca-certificates \
        libsoapysdr-dev libssl-dev zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*

# LiteX-M2SDR: static libm2sdr, m2sdr_util and the SoapySDR module (PCIe and Ethernet transports)
WORKDIR /opt/litex_m2sdr
RUN git init -q . && \
    git fetch -q --depth 1 https://github.com/enjoy-digital/litex_m2sdr.git "${LITEX_M2SDR_REF}" && \
    git checkout -q FETCH_HEAD && \
    make -C litex_m2sdr/software/user -j"$(nproc)" INTERFACE=USE_LITEPCIE libm2sdr/libm2sdr.a m2sdr_util && \
    install -D -m 755 litex_m2sdr/software/user/m2sdr_util /staging/usr/bin/m2sdr_util && \
    cmake -S litex_m2sdr/software/soapysdr -B build-soapy -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr && \
    cmake --build build-soapy -j"$(nproc)" && \
    DESTDIR=/staging cmake --install build-soapy

# AIS-catcher from this source tree
WORKDIR /src
COPY . .
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DSOAPYSDR=ON -DRUN_NUMBER=${RUN_NUMBER} && \
    cmake --build build -j"$(nproc)" && \
    install -D -m 755 build/AIS-catcher /staging/usr/bin/AIS-catcher && \
    install -D -m 755 docker/entrypoint.sh /staging/usr/local/bin/entrypoint.sh

FROM debian:${DEBIAN_RELEASE}-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libsoapysdr0.8 soapysdr-tools libssl3 zlib1g ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /staging/ /

# config file read by the entrypoint; mount it (or its directory) from the host
ENV AISCATCHER_CONFIG=/etc/aiscatcher/aiscatcher.json

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
