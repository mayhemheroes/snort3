# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile (SMALL form) — builds ON TOP of the org C/C++ base image
# (ghcr.io/mayhemheroes/base). The base provides debian + clang/llvm + libFuzzer/afl++ + the
# identities + the build-contract ENV; this adds snort3's (heavy) dependency closure plus the
# per-commit fuzz/test build.
#
# Build (from the repo root):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) \
#       [--build-arg SOURCE_DATE_EPOCH=$(date +%s)] \
#       -t snort3-commit:test .

FROM ghcr.io/mayhemheroes/base:20260621

ARG COMMIT
ARG REPO_URL
# SOURCE_DATE_EPOCH stays an ARG (available to build.sh); never bake it as ENV.
ARG SOURCE_DATE_EPOCH

# Sanitizer override: undefaulted so an unset arg lets the base's SANITIZER_FLAGS ENV flow through.
ARG SANITIZER_FLAGS
ARG MAYHEM_JOBS=

# ── snort3's dependency closure ──────────────────────────────────────────────────────────────────
# Everything EXCEPT libdaq is a pinned Debian -dev package. libdaq is snort3's OWN packet-I/O
# library (github.com/snort3/libdaq, "DAQ v3" — a completely different, newer library/API than
# Debian's ancient libdaq-dev v2 package, which does not satisfy snort3's >=3.0.27 requirement and
# is not even offered on this Debian release) — there is no apt package for it, so it's built from
# source here, ONCE, at image-build time (the only point this Dockerfile touches the network).
# mayhem/build.sh itself never touches the network — it only configures/builds against the
# already-installed libdaq — so the air-gapped `docker run --network none ... build.sh` re-run
# (§6.2 item 9) succeeds.
USER root
RUN [ -n "$SOURCE_DATE_EPOCH" ] && repro-sources-list.sh || true; \
    apt-get update && apt-get install -yq --no-install-recommends \
      libpcap-dev libpcre2-dev libdumbnet-dev libhwloc-dev libluajit-5.1-dev \
      libfl-dev liblzma-dev libcpputest-dev libnuma-dev \
      autoconf automake libtool pkg-config \
    && rm -rf /var/lib/apt/lists/*

ARG LIBDAQ_VERSION=v3.0.27
RUN set -eux; \
    git clone --depth 1 --branch "$LIBDAQ_VERSION" https://github.com/snort3/libdaq.git /tmp/libdaq; \
    cd /tmp/libdaq; \
    ./bootstrap; \
    ./configure --prefix=/usr --disable-static \
      --disable-afpacket-module --disable-bpf-module --disable-divert-module \
      --disable-netmap-module --disable-nfq-module --disable-gwlb-module; \
    make -j"$(nproc)"; \
    make install; \
    ldconfig; \
    rm -rf /tmp/libdaq
USER mayhem

# Source enters from the build CONTEXT (the CI checkout): the FULL repo (incl. .git history) is
# copied to /mayhem as `mayhem`; build.sh builds in place.
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

RUN bash mayhem/build.sh

RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
