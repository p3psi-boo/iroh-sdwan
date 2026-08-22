FROM debian:trixie-slim

RUN DEBIAN_FRONTEND=noninteractive apt-get update \
    && apt-get install -y --no-install-recommends \
       iproute2 iputils-ping jq tcpdump tshark \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/bin/bash"]
