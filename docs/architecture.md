# Architecture and data contracts

The live CLI combines a read-only physical reader, Windows address translation,
exact-build introspection, and PE reconstruction. Guest input is untrusted;
binary reads check bounds and decode little-endian integers byte by byte.
No host struct is reinterpreted as a guest PE or kernel object.

## Components and lifetimes

| Component | Responsibility |
| --- | --- |
| `platform.cpp` | RAII RAM descriptor, bounded host commands, domain XML, validated `pc.ram` aliases, exclusive output publication. |
| `windows.cpp` | ISF loading, CodeView identity, page tables/software PTEs, process lists, native/WOW64 modules, shared-image VADs, low-stub discovery. |
| `pe.cpp` | PE validation, export indexing, import recovery, `.imprec`, relocated backing bytes, file layout, JSON reports. |
| `backing.cpp` | NTFS path/device selection, read-only copying, WOF metadata/chunks, optional native decoders. |
| `common.cpp` | Checked bytes, SHA-256, JSON values and parsing preserving unsigned 64-bit addresses. |
| `dump.cpp` | Streaming raw ranges and stored ZIP64 resident-process archives. |
| `rsp.cpp`, `legacy.cpp` | Separate explicitly gated debugger and GDB listener helper. |

`Physical` owns its descriptor. `Windows` references a caller-owned `Profile`
and its physical read callback; both must outlive it. `Target` references its
`Windows` and is immovable because its VAD resolver captures its address.
`PE` and `ExportIndex` retain read callbacks, whose captured storage must remain
alive. `BackingImage` owns a virtual image and immutable relocation metadata.
No core object assumes shared ownership or background worker threads.

Public headers live under `include/qpd/`. Recoverable errors throw `qpd::Error`;
signal cancellation throws `qpd::Cancelled`. `PageUnavailable` carries the PTE
and optional evidence authorizing file recovery. The CLI catches failures at
its outer boundary, reports them on stderr, and returns 1; cancellation returns
130. Argument validation failures also return 1. `--help` returns 0.

## Live acquisition guarantees

The live QMP allowlist contains `query-cpus-fast` and `human-monitor-command`
with exactly `info ramblock` or `info mtree -f`. Domain queries use `domstate`
and `dumpxml`. The process UUID, executable name, process start time, and
writable host RAM ranges are checked before accepting a read-only
`O_RDONLY | O_CLOEXEC` descriptor. Physical reads reject MMIO/SMM holes.
The descriptor is closed by RAII, including on exceptions.

Each virtual page walk records every observed page-table entry. Software
prototype and VAD metadata reads join that check set. The reader rechecks
these values after reading bytes and retries a changed mapping up to three
times. Whole process/module list traversals also retry up to three times.
Process PID, DTB, PEB, and available creation time are checked to detect exit,
replacement, and reuse. QEMU identity is checked before publication.

Only an explicitly committed demand-zero PTE yields synthetic zero bytes during
normal translation. An empty PTE can resolve through a shared image VAD; private
VADs and pagefile PTEs cannot authorize original-file substitution. Prototype
subsection records are file-backing metadata, never interpreted as RAM frames.

These checks detect some races; they do not turn multiple live reads into an
atomic snapshot. The legacy debugger has different execution semantics and
does not participate in the live capture path.

## Reconstruction and output publication

Capturing reads all selected section ranges, retaining resident RAM as the
authority. Eligible missing shared-image bytes may come from a PE whose headers
match byte-for-byte. The only accepted normalization changes ImageBase to the
actual live mapping; the original preferred base remains the relocation base.
Relocations support x64 DIR64 and x86 HIGHLOW/HIGH/LOW/HIGHADJ. Malformed,
overlapping, header-targeting, and unsupported relocations fail recovery.

Imports use original names/ordinals where available, otherwise a lazy loaded
export index. Forwarders themselves are skipped; actual exported addresses can
resolve through destination modules. Multiple aliases require overrides.
Automatic IAT scanning requires bounded runs of at least two known pointers
in non-executable sections. Original IAT slot RVAs remain unchanged.

The output adds `.imprec`, rebuilds raw section offsets, repairs debug record
file offsets, sets ImageBase/OEP, and clears certificates, bound imports, and
checksum. If a debug directory cannot be mapped safely, its directory entry is
cleared. Certificates and file overlays cannot be recovered from loaded RAM.

On Linux, each file is written to a same-directory temporary file, flushed,
and published with an exclusive hard link. An existing destination is never
overwritten. Failure to publish the report removes the newly published binary.
Temporary files are removed on ordinary exceptions/cancellation. A binary/report
pair is **not one atomic filesystem transaction**; a crash or SIGKILL between
publications can leave only the binary. Output directories may remain after a
failed capture. Hard links must be supported by the destination filesystem.

## Report contract

Reports use `format: "vmidbg-pe-dump"`, `version: 1`, with an `implementation`
field identifying this port. Addresses/RVAs are exact unsigned JSON integers;
consumers using JavaScript should avoid converting 64-bit addresses to `Number`.

| Fields | Meaning |
| --- | --- |
| `process` | PID, name, EPROCESS, DTB, user DTB, PEB observed during selection. |
| `image_base`, `entry_point_rva`, `architecture` | Loaded base, selected entry RVA, x86/x64 PE architecture. |
| `size`, `sha256` | Published binary byte count and SHA-256. |
| `guest_pause_requested`, `guest_memory_writes` | Both false for live/offline PE capture. |
| `capture_consistency` | `live, non-atomic`; conservative even for offline input. |
| `capture_sources` | `memory` or `memory and backing file`. |
| `imports`, `imports_rebuilt` | Final slot/DLL/name/ordinal choices and whether rebuilding ran. |
| `export_read_errors` | Module export reads that failed during lazy reverse resolution. |
| `missing_pages` | Zero-filled address/size/error ranges explicitly accepted by the user. |
| `shared_image_pages_recovered` | User-page addresses recovered from resident shared prototypes. |
| `file_recovered_pages` | Substituted address/RVA/size/source ranges. |
| `backing_file` | Source, hash, header adjustments, bases, relocation count; null if unused. |
| `sections` | Rebuilt name/RVA/size/raw offset/raw size records. |
| `duration_milliseconds`, `limits` | Capture elapsed time and interpretive limitations. |

`backing_file.relocation_delta_modulo_2_64` represents subtraction modulo
2^64 so negative ASLR deltas never cause signed overflow. This and timing units
differ from the Python report; see [migration](migration.md).

## Supported layouts

The Windows kernel must be AMD64 with four-level paging and an exact ISF.
User images can be x86 or x64; WOW64 loader traversal is included. Live host
mapping discovery supports one validated `pc.ram` RAMBlock and system-memory
aliases. NUMA/hotplug, encrypted guest RAM, five-level kernel paging, and 32-bit
Windows kernels are unsupported. No code assumes the host shares guest
endianness or guest struct layout.

Linux x64 is the verification host. Linux ARM64, Windows x64/ARM64, and macOS
x64/ARM64 have not been tested. Non-Linux branches provide offline file access
and output publication, and explicitly reject Linux host commands/live RAM,
legacy sockets, and compressed WOF decoding. No verified non-Linux deployment
or full cross-platform support is claimed. The Makefile is the Linux build
entry point; other toolchains must supply the same dependency/include settings.
