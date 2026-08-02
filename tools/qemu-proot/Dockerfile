FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS builder

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        build-essential \
        ca-certificates \
        clang \
        curl \
        gcc-aarch64-linux-gnu \
        libtalloc-dev \
        libc6-dev-arm64-cross \
        lld \
    && rm -rf /var/lib/apt/lists/*

ARG PROOT_COMMIT=58aad2cb1c36ea6af7b32d76ccd5bf8d0a967939
ARG PROOT_ARCHIVE_SHA256=0e132e306214adba900479d3262058f179577856f375d786d3e062498ca957fd
ARG ANDROID_ASHMEM_HEADER_COMMIT=797351fd3bbb8fe517afafdd5095fd740387e7a4
ARG ANDROID_ASHMEM_HEADER_SHA256=1806e49478167732a5511c87a229b5ff1df4bc4d26fbaf5282df313dab0df974
RUN mkdir -p /build \
    && curl --fail --location --show-error --silent \
        --output /build/proot.tar.gz \
        "https://github.com/termux/proot/archive/${PROOT_COMMIT}.tar.gz" \
    && printf '%s  %s\n' "${PROOT_ARCHIVE_SHA256}" /build/proot.tar.gz \
        | sha256sum --check --strict \
    && tar -xzf /build/proot.tar.gz -C /build \
    && curl --fail --location --show-error --silent \
        "https://android.googlesource.com/platform/development/+/${ANDROID_ASHMEM_HEADER_COMMIT}/ndk/platforms/android-L/include/linux/ashmem.h?format=TEXT" \
        | base64 --decode \
        > /build/android-ashmem.h \
    && printf '%s  %s\n' \
        "${ANDROID_ASHMEM_HEADER_SHA256}" \
        /build/android-ashmem.h \
        | sha256sum --check --strict \
    && mkdir -p "/build/proot-${PROOT_COMMIT}/src/linux" \
    && { printf '#include <linux/types.h>\n'; cat /build/android-ashmem.h; } \
        > "/build/proot-${PROOT_COMMIT}/src/linux/ashmem.h" \
    && printf '#!/bin/sh\nprintf "v5.1.107.72\\n"\n' > /build/pinned-proot-version \
    && chmod 0755 /build/pinned-proot-version \
    && make -C "/build/proot-${PROOT_COMMIT}/src" \
        CC='clang -fuse-ld=lld' \
        GIT=/build/pinned-proot-version \
    && "/build/proot-${PROOT_COMMIT}/src/proot" --version \
        | grep -q 'v5\.1\.107\.72'

COPY deny-af-netlink.c network-probe.c /build/
RUN cc -O2 -Wall -Wextra -Werror \
        -o /build/deny-af-netlink /build/deny-af-netlink.c \
    && aarch64-linux-gnu-gcc -O2 -Wall -Wextra -Werror \
        -o /build/network-probe-aarch64 /build/network-probe.c

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates \
        curl \
        libtalloc2 \
        qemu-user-static \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/proot-58aad2cb1c36ea6af7b32d76ccd5bf8d0a967939/src/proot /usr/local/bin/proot
COPY --from=builder /build/proot-58aad2cb1c36ea6af7b32d76ccd5bf8d0a967939/COPYING /usr/share/licenses/termux-proot/COPYING
COPY --from=builder /build/deny-af-netlink /usr/local/bin/deny-af-netlink
COPY --from=builder /build/network-probe-aarch64 /usr/local/libexec/liskov-network-probe-aarch64
COPY run.sh /usr/local/bin/run-liskov-qemu-proot

RUN chmod 0755 \
    /usr/local/bin/deny-af-netlink \
    /usr/local/bin/proot \
    /usr/local/bin/run-liskov-qemu-proot \
    /usr/local/libexec/liskov-network-probe-aarch64

ENTRYPOINT ["/usr/local/bin/run-liskov-qemu-proot"]
