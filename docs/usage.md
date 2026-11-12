# Capture a Windows executable from QEMU

Build the program as described in the [README](../README.md). Run commands
from the repository root. For live access the domain must already be running;
the capture backend never starts or resumes it.

## Select the VM and profile

```sh
./run-dumper.sh --domain windows11-hardware --uri qemu:///system --list
./run-dumper.sh --list --profile /path/to/matching-kernel.json.xz
```

The bundled profile identifies `ntkrnlmp.pdb`, GUID
`B661C6FE72991D160FE37C48B8BC5470`, age 1, AMD64. The program verifies all
four identity fields against the kernel's in-memory CodeView record.
Profiles may be JSON, gzip (`.gz`), or XZ (`.xz`). Compressed/uncompressed
profile input is bounded; decompressed text is limited to 128 MiB.

If low-stub discovery fails, supply both addresses from the **current boot**:

```sh
./run-dumper.sh --kernel-base 0xfffff80000000000 --kernel-cr3 0x100000 --list
```

Those numbers are placeholders. Obtain valid current addresses independently;
do not reuse addresses from another boot. The program still verifies kernel
identity and System PID 4 before accepting them.

## Select a module

```sh
./run-dumper.sh --pid 4242 --modules
./run-dumper.sh --pid 4242 --module example.dll --output example.dump.dll
./run-dumper.sh --pid 4242 --base 0x140000000 --output mapped.exe
```

Module matching is case-insensitive and must be unique. `--module` and
`--base` are mutually exclusive. `--base` requires readable PE headers.
Use `--json` for machine-readable process/module lists. Progress and errors
are written to stderr; successful dump summaries are JSON on stdout.

`--output` supplies a filename. Any parent directory in the argument is
discarded, matching the source workflow: `/tmp/sample.exe` still becomes
`outputs/sample/sample.exe` under this installation. The final extension is
removed only for the directory name. The report appends `.json` to the full
output filename. Without `--output`, the filename is `NAME.PID.dump.exe`.

## Rebuild imports

Ordinary import recovery uses original lookup tables. When they are unavailable,
it resolves loaded exports and refuses ambiguous aliases. With destroyed import
metadata, supply explicit IAT bounds:

```sh
./run-dumper.sh --pid 4242 --iat-rva 0x32000 --iat-size 0x800 \
  --oep 0x12340 --output fixed.exe
```

All three numbers are RVAs/sizes, not virtual addresses. Both IAT arguments
are required together; size must be positive and divisible by the image's
pointer width. OEP must lie inside the original image.

For hooks, unresolved pointers, or aliases, save this example as `imports.json`,
replacing the example DLL/API and slots with the desired imports:

```json
[
  {"slot": "0x32000", "dll": "KERNEL32.dll", "name": "GetCurrentProcessId"},
  {"slot": "0x32008", "dll": "example.dll", "ordinal": 9}
]
```

```sh
./run-dumper.sh --pid 4242 --iat-rva 0x32000 --iat-size 0x800 \
  --import-map imports.json --output fixed.exe
```

Slots must belong to captured headers or sections. Duplicate slots, invalid
ASCII names, and ordinals outside 1..65535 are refused. Overrides select slots
encountered during import recovery; they do not create an arbitrary new IAT.

`--no-imports` exports loaded sections without repairing resolved IAT pointers.
It is useful for inspection and does not produce a guaranteed runnable PE.

## Recover nonresident image pages

Automatic recovery runs only when a shared-image VAD confirms a file-backed
nonresident page in the selected image. It reads the process module's path
from its loader metadata and queries only that VM's attached block disks.
`ntfsls` resolves stored path capitalization, and `ntfscat` reads without
mounting the disk. WOF FILE-provider XPRESS4K/8K/16K and LZX streams are
decoded using the installed NTFS system-compression plugin.

After privilege dropping, the automatic helper uses `sudo -n`; it never prompts
while capture is running. The normal launcher's sudo authentication must still
be valid. Disk copying runs in a separate bounded subprocess. A backing PE is
accepted only after header matching and supported relocation processing.

For a separately obtained original executable:

```sh
./run-dumper.sh --pid 4242 --backing-file original.exe --output recovered.exe
```

To copy the guest file explicitly:

```sh
sudo ./bin/qemu-process-dumper copy-guest-file \
  --path 'C:\Windows\System32\example.exe' --output original.exe
sudo ./bin/qemu-process-dumper copy-guest-file \
  --pid 4242 --output original.exe
```

Here `--output` is the exact host destination and its parent must exist.
`--pid` verifies copied headers against the live main image; `--path` validates
that the result parses as a PE. An optional `--partition /dev/DEVICE` restricts
the search to a partition already found on the selected domain's block disks.
Image-file disks, encrypted volumes, and controller passthrough need a
separately obtained backing file. Files and reconstructed images are limited
to 1 GiB. Recovery buffers data in host memory, so allow room for multiple
copies of large images and their backing files.

File recovery is a mixed memory/file reconstruction. It cannot recreate
historical private changes, pagefile contents, or the Windows compression store.
The report discloses every substituted range and the backing file hash.

## Missing pages and troubleshooting

```sh
./run-dumper.sh --pid 4242 --allow-missing --output incomplete.exe
```

This deliberately zero-fills unreadable section bytes and records their errors.
It disables automatic disk recovery; an explicit `--backing-file` remains usable
for eligible shared-image pages. Unavailable required import metadata is never
silently treated as zero. Headers must remain readable in every mode.

| Failure | Action |
| --- | --- |
| Cannot open read-only RAM | Run on the actual Linux host with sufficient `/proc/PID/mem` permission; check host ptrace policy. |
| Domain is not running | Start/resume it separately before capture. |
| Kernel/profile mismatch | Supply the exact profile for the running kernel. |
| Kernel not found | Supply current boot addresses or inspect whether the low stub was overwritten. |
| Repeatedly changed mappings/list mismatch | Retry capture; the running guest can change structures. |
| Cannot resolve or ambiguous import | Supply IAT bounds and explicit import overrides. |
| Backing headers differ | Obtain the matching original file; do not bypass verification. |
| ASLR adjustment has no relocations | That backing file cannot safely reconstruct pages at this live base. |
| Output/report already exists | Choose a new output filename. |

Successful capture does not verify execution, signatures, overlays, or a coherent
point-in-time snapshot. See [supported layouts](architecture.md#supported-layouts).
