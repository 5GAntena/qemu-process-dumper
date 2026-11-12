# Contributing

Read any local `AGENTS.md` instructions and the [architecture](docs/architecture.md) first.
Use C++20, the existing Makefile, explicit ownership, checked little-endian byte
access, and narrow changes. Keep Linux host operations in platform branches.
Guest addresses are unsigned 64-bit values, including in JSON reports.

Install the development dependencies listed in the [README](README.md), then
run the checks relevant to the files you change. No dependency downloads or
system interpreter installation are performed by the Makefile.

## Verification

```sh
make check
make test
```

`check` syntax-checks every production C++ translation unit with warnings enabled.
`test` compiles a separate native test executable and runs focused assertions
covering JSON address precision, malformed binary data, page translation/races,
kernel identity/process reuse, VAD recovery eligibility, PE/import layout,
backing matching/relocation, publication failures, WOF validation, and RSP
decoding. It does not require privileges, a running VM, or the Python project.
Run from the repository root so the bundled profile is found.

For memory-safety changes, when compiler runtimes are installed:

```sh
make sanitize
```

This rebuilds the native tests using AddressSanitizer and UndefinedBehaviorSanitizer.
Missing sanitizer libraries are an unavailable check, not a passing check.
No clang-format/clang-tidy configuration or binaries were supplied in this
workspace; use the local style and do not claim those tools ran.

The end-to-end check builds the application and boots a disposable TCG guest:

```sh
make integration
```

It requires Linux `/proc` memory access, Python 3, QEMU, and GNU binutils. It
verifies offline CLI selection, rebuilt PE output, overwrite refusal, the legacy
pause gate, file-backed page provenance, and the production live RAM reader.
A strict libvirt proxy forwards only read queries to that temporary QEMU.
A synthetic in-guest counter must advance during listing and capture.
Results are saved to ignored `test-results/integration.json`. Firmware, TCG,
or host `/proc` restrictions can make this check unavailable.

These fixtures contain synthetic Windows-shaped structures and PE bytes; they
do not run Windows. Real Windows/KVM capture, NTFS block-device discovery,
installed WOF native decoders, and active legacy GDB sessions require separate
host verification. Neither a compilation nor a synthetic test proves that a
reconstructed executable runs correctly on Windows. Other OS/architecture
targets are unverified, as described in the architecture document.

Do not run a full build unless the task authorizes it, in accordance with
AGENTS.md. Build commands are documented for maintainers and are not implied
verification claims. The ordinary build target is `make`; `make clean` removes
only `bin/`.

## Reporting a problem

Include the compiler/host architecture, command with private paths redacted,
stderr, exact kernel PDB identity, and relevant report fields. Describe whether
input was live or offline and whether backing bytes were used. Do not upload
RAM captures, proprietary executables, credentials, or sensitive process data
in a public issue. There is no configured issue tracker URL in the supplied
source, so no tracker or license URL is invented here.
