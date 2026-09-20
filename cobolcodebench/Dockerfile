# Shared sandbox image for the COBOL evals (CobolCodeBench, NIST COBOL85 conversion).
# Same contract as eval-livecodebench's image: /usr/local/bin/python3, GNU timeout,
# procps pkill, dmesg/hostname for provenance, UID/GID 65532 reserved for candidates.
FROM python:3.12-slim-trixie
RUN apt-get update \
    && apt-get install -y --no-install-recommends procps util-linux hostname \
       gnucobol openjdk-21-jdk-headless \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 cobol-candidate \
    && useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin cobol-candidate
USER 0:0
RUN command -v dmesg && command -v hostname && cobc --version && javac -version && java -version && python3 --version
