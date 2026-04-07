FROM stagex/core-binutils@sha256:72e606de19add996ddff23946d2b2d8349d34530a668a5d0d4a5706741e197c8 AS core-binutils
FROM stagex/core-ca-certificates@sha256:6f1b69f013287af74340668d7a6f14de8ff5555e60e7c4ef1a643a78ed1629bd AS core-ca-certificates
FROM stagex/core-gcc@sha256:2a12ad577ed0cbc63b3bffa89f17aa21fbedc2ec4f4e239b6fa194930f0f674b AS core-gcc
FROM stagex/core-git@sha256:441316b17e020eb28d31ccaec2197d61646519bb564da8af3e5eea7642363034 AS core-git
FROM stagex/core-zlib@sha256:7d9dbe4ca873b75f3c7c8e35105f8d273db66a179e9678704c0510dc441ae4ca AS core-zlib
FROM stagex/core-llvm@sha256:d9d611f8db790113a5a70655d01dd47e72b10ce32b073493bba2303926c52ecb AS core-llvm
FROM stagex/core-openssl@sha256:a42aaff7895410d7823913e27c680b6b85ce2cb91489a5f4c875fa17e5d0aa5b AS core-openssl
FROM stagex/core-rust@sha256:a531ef1d2bca71d46ffe532679a8a9ae52ad29a5dafdc93f3a1e94b43522a278 AS core-rust
FROM stagex/core-musl@sha256:fe241a40ee103f34e8e2bc5054de9bf67ffe00593d7412b6d61e6d2795425f7c AS core-musl
FROM stagex/core-libunwind@sha256:f996cd69924786b142e3545023018682240138fba1b690d7109d015f44b2fa63 AS core-libunwind
FROM stagex/core-pkgconf@sha256:8531798376b4a4a68d7d22eeda7d86cd7818746a742f8a99c5bb35f8fb1ebb14 AS core-pkgconf
FROM stagex/core-busybox@sha256:4f3e3849acb54972e7c4f1d08c320526e0f8b314130bda68f83f821b02b4890b AS core-busybox
FROM stagex/core-libzstd@sha256:c6ff15d1b2cf240d68c42c0614b675b60b9a0943b92ac326d3866d87af7d18fb AS core-libzstd
FROM stagex/core-cmake@sha256:64d057d580f26d096603e13d1714619a4eb105a09023f26ce77ec90679bdb5be AS core-cmake
FROM stagex/core-make@sha256:45523d7f448c58a2a1159b578a0c838010dac9b9a59bdd02f1e4dc533e618de6 AS core-make
FROM stagex/user-eif_build@sha256:4cac953996e839b6202d85e6fe1f67db33c10432c43fceff13dfbf5d7e665574 AS user-eif_build
FROM stagex/user-gen_initramfs@sha256:74d3581ed47022807b658bb38e8cdc05068472928c45c170f78054a27e97b634 AS user-gen_initramfs
FROM stagex/linux-nitro@sha256:073c4603686e3bdc0ed6755fee3203f6f6f1512e0ded09eaea8866b002b04264 AS user-linux-nitro
FROM stagex/user-cpio@sha256:9802cf7909c70e779ba8fe4923b0e190241c4d6ad329f3f0720c2a7f1d97cf37 AS user-cpio
FROM stagex/user-socat@sha256:91cd7505fb97593e5790bdbb0ca62d5fd2bae0d70fda025d46871d0a36410f7d AS user-socat

# ── Node 22 musl runtime (for TS sidecar) ────────────────────────────────────
# node:22-alpine uses musl libc, so the binary + its C++ runtime deps
# (libstdc++.so.6, libgcc_s.so.1) are all musl-linked and can be copied
# directly into the stagex initramfs which also runs on musl.
FROM node:22-alpine AS node-build
RUN node --version && npm --version

# ── Workspace base (stagex) ──────────────────────────────────────────────────
FROM scratch as base
ENV TARGET=x86_64-unknown-linux-musl
ENV RUSTFLAGS="-C target-feature=+crt-static"
ENV CARGOFLAGS="--no-default-features --release --target ${TARGET}"

COPY --from=core-busybox . /
COPY --from=core-musl . /
COPY --from=core-libunwind . /
COPY --from=core-openssl . /
COPY --from=core-zlib . /
COPY --from=core-ca-certificates . /
COPY --from=core-libzstd . /
COPY --from=core-binutils . /
COPY --from=core-pkgconf . /
COPY --from=core-git . /
COPY --from=core-rust . /
COPY --from=user-gen_initramfs . /
COPY --from=user-eif_build . /
COPY --from=core-llvm . /
COPY --from=core-gcc . /
COPY --from=core-cmake . /
COPY --from=core-make . /
COPY --from=user-cpio . /
COPY --from=user-linux-nitro /bzImage .
COPY --from=user-linux-nitro /nsm.ko .
COPY --from=user-linux-nitro /linux.config .

# ── TS sidecar npm deps ────────────────────────────────────────────────────────
FROM node-build AS ts-build
COPY src/relayer/scripts /scripts
WORKDIR /scripts
RUN npm ci --omit=dev

# ── Rust workspace + relayer build ───────────────────────────────────────────
FROM base as build
COPY . .

# Build workspace crates (init, aws, system)
RUN cargo build --workspace --no-default-features --release --target x86_64-unknown-linux-musl

# Build memwal-relayer with AWS NSM support
WORKDIR /src/relayer
ENV RUSTFLAGS="-C target-feature=+crt-static -C relocation-model=static"
RUN cargo build --locked --release --target x86_64-unknown-linux-musl --features aws

# ── Pack initramfs ────────────────────────────────────────────────────────────
WORKDIR /build_cpio
ENV KBUILD_BUILD_TIMESTAMP=1
RUN mkdir initramfs/

COPY --from=user-linux-nitro /nsm.ko initramfs/nsm.ko
COPY --from=core-busybox . initramfs
COPY --from=core-musl . initramfs
COPY --from=core-zlib . initramfs
COPY --from=core-ca-certificates /etc/ssl/certs initramfs/etc/ssl/certs/
COPY --from=core-busybox /bin/sh initramfs/sh
COPY --from=user-socat /bin/socat initramfs/

# Rust enclave binaries
RUN cp /target/${TARGET}/release/init initramfs/
RUN cp /src/relayer/target/${TARGET}/release/memwal_server initramfs/
RUN cp /src/relayer/run.sh initramfs/

# Node runtime + TS sidecar deps
# Copy the node binary, its musl C++ runtime libs, and the npm-installed scripts.
# libstdc++.so.6 and libgcc_s.so.1 are the musl-linked versions from Alpine —
# required by the node binary at runtime inside the enclave.
RUN mkdir -p initramfs/usr/local/bin initramfs/usr/local/lib initramfs/scripts initramfs/usr/lib \
    initramfs/proc initramfs/sys initramfs/dev initramfs/dev/pts initramfs/dev/shm initramfs/run
COPY --from=node-build /usr/local/bin/node initramfs/usr/local/bin/node
COPY --from=node-build /usr/local/lib/ initramfs/usr/local/lib/
COPY --from=node-build /usr/lib/libstdc++.so.6 initramfs/usr/lib/libstdc++.so.6
COPY --from=node-build /usr/lib/libgcc_s.so.1 initramfs/usr/lib/libgcc_s.so.1
COPY --from=ts-build /scripts initramfs/scripts

RUN <<-EOF
    set -eux
    cd initramfs
    find . -exec touch -hcd "@0" "{}" +
    find . -print0 \
    | sort -z \
    | cpio \
        --null \
        --create \
        --verbose \
        --reproducible \
        --format=newc \
    | gzip --best \
    > /build_cpio/rootfs.cpio
EOF

WORKDIR /build_eif
RUN eif_build \
	--kernel /bzImage \
	--kernel_config /linux.config \
	--ramdisk /build_cpio/rootfs.cpio \
	--pcrs_output /nitro.pcrs \
	--output /nitro.eif \
	--cmdline 'reboot=k initrd=0x2000000,3228672 root=/dev/ram0 panic=1 pci=off nomodules console=ttyS0 i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd'

FROM base as install
WORKDIR /rootfs
COPY --from=build /nitro.eif .
COPY --from=build /nitro.pcrs .
COPY --from=build /build_cpio/rootfs.cpio .

FROM scratch AS package
COPY --from=install /rootfs .
