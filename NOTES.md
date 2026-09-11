# Google Patch Rewards — libpcap local draft notes

**Date:** 2026-09-11 (America/Chicago)  
**Do not claim yet:** need upstream merge + ≥30 days, then https://bughunters.google.com/report/patch_rewards

## Chosen target + why

- **Project:** libpcap (the-tcpdump-group/libpcap, branch `master`)
- **Upstream:** https://github.com/the-tcpdump-group/libpcap (GitHub PR)
- **Local clone:** `/workspace/google-patch-libpcap`
- **Branch:** `local/buffer-fbounds-safety`
- **Why this target:**
  1. Tier-1 **Core infrastructure data parsers** (3× memory-safety multiplier through end-2026).
  2. Clear, mergeable first-CL scope: one struct field pair (`buffer` / `bufsize`) on `pcap_t` — savefile/live read buffer path — not a whole-library sweep.
  3. Same pattern as libpng / libwebp / libjpeg-turbo / libtiff: **inert macros** when the flag is off; experimental Clang `-fbounds-safety` only when explicitly enabled.
  4. `bufsize` is already declared before `buffer` (no field reorder / ABI churn).
  5. Not already done upstream (no `__counted_by` / `-fbounds-safety` in tree).
  6. AI CONTRIBUTING gate clear (no AI ban in CONTRIBUTING.md).

## Security benefit

`pcap_t.buffer` holds bytes for packet/savefile block parsing on offline and many live backends. The library already tracks capacity in `bufsize`, but the compiler cannot see that relationship.

This draft:

1. Introduces `pcap_bounds_safety.h` with `PCAP_COUNTED_BY` / `PCAP_COUNTED_BY_OR_NULL` (empty by default).
2. Annotates `buffer` with `PCAP_COUNTED_BY_OR_NULL(bufsize)` (nullable; size may be 0).
3. Keeps `bufsize` **before** `buffer` (already true) so the named count is in scope for the attribute.
4. Makes key update sites **capacity-then-pointer** (and clear sites **pointer-null then size 0**) so counted-by invariants hold under a real `-fbounds-safety` build; also records grown capacity in the pcapng block-grow path.
5. Wires optional CMake `ENABLE_FBOUNDS_SAFETY` (OFF by default) and Makefile `ENABLE_FBOUNDS_SAFETY=1` → `-DPCAP_SUPPORT_FBOUNDS_SAFETY` + `-fbounds-safety`.

**Default builds are unchanged:** macros expand to nothing; no new runtime checks without the experimental flag.

## Files changed

| File | Change |
|------|--------|
| `pcap_bounds_safety.h` | **New** — inert / Clang bounds macros |
| `pcap-int.h` | Include header; annotate `pcap_t.buffer` |
| `sf-pcap.c` | Capacity-first `grow_buffer` |
| `sf-pcapng.c` | Capacity-first grow; set `bufsize` on realloc |
| `savefile.c` | Null pointer then zero size on cleanup |
| `pcap.c` | Null pointer then zero size in live cleanup |
| `CMakeLists.txt` | `ENABLE_FBOUNDS_SAFETY` option OFF |
| `Makefile.in` | Header in `HDR`; `ENABLE_FBOUNDS_SAFETY` hook |
| `NOTES.md` | This file |

## How to build / test

Default (macros inert — must stay green):

```sh
cmake -S . -B build-draft -DBUILD_SHARED_LIBS=OFF
cmake --build build-draft -j
# optional: ctest / testprogs if configured
```

Or autoconf:

```sh
./autogen.sh && ./configure && make -j
```

With experimental bounds-safety toolchain (maintainers / CI; **not** available on this box — no Clang/`ptrcheck.h`):

```sh
cmake -S . -B build-fbs -DENABLE_FBOUNDS_SAFETY=ON \
  -DCMAKE_C_COMPILER=<clang-with-fbounds-safety> \
  -DBUILD_SHARED_LIBS=OFF
cmake --build build-fbs -j
```

## Upstream submit plan

1. Open a focused GitHub PR against `the-tcpdump-group/libpcap` branch `master`.
2. Proposed title: `pcap: add optional -fbounds-safety annotation for pcap_t.buffer`
3. Frame as secure-by-design / Safe Buffers-style systematization of an existing size+pointer pair; cite libwebp/libpng prior art and Google Patch Rewards Tier-1 parser goals.
4. Emphasize: default build behavior unchanged; flag OFF; no PoC / no CVE claim.
5. Do **not** claim on https://bughunters.google.com/report/patch_rewards until **merge + ≥30 days**.

## Follow-ups (separate CLs)

- Linux TPACKET path: `buffer` is a frame-pointer ring sized by `cc`, while `bufsize` is frame size — needs a dedicated capacity field or backend-local annotation before enabling `-fbounds-safety` there.
- BPF zerocopy paths that alias `buffer` into mmapped regions (null without size clear).
- `bp` / `cc` cursor pair (pointer-into-buffer; different annotation shape).
- Other live backends’ allocate sites (most already capacity-then-pointer).

## Status

**IN PROGRESS — local draft only; no GitHub upload, no push, no claim.**
