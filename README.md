# QEMU process dumper

A native C++20 port of the Python dumper in `../dumper`. It lists Windows
processes and reconstructs a selected executable or DLL from QEMU memory,
including PE sections, imports, and eligible nonresident image pages.
The live capture command reads RAM without asking QEMU to pause or resume.
The original Python project is left untouched; Python is used only by the
optional integration-test driver.

## Requirements and build

- A C++20 compiler, GNU Make, and `pkg-config`.
- Development headers/libraries for OpenSSL (`openssl`), libxml2
  (`libxml-2.0`), liblzma (`liblzma`), zlib (`zlib`), and ICU (`icu-uc`).
- For live capture: Linux, libvirt's `virsh`, a running x86-64 QEMU guest,
  and permission to read that QEMU process's `/proc/PID/mem`.
- An exact AMD64 Windows kernel symbol profile. One profile is bundled;
  Windows kernel updates require a matching profile.
- For automatic file recovery: `sudo`, `lsblk`, `ntfsls`, `ntfscat`, and
  a guest NTFS disk attached as a host block device. Compressed WOF files
  additionally need the `ntfs-3g-system-compression` plugin.

From this repository's root:

```sh
make
./bin/qemu-process-dumper --help
```

The binary expects `profiles/` and writes `outputs/` beside its parent `bin/`
directory. Keep that directory layout when moving the executable. There is
no dependency on the Python project's location or files.

## List and capture

The default libvirt domain is `windows11-hardware`:

```sh
./run-dumper.sh --list
./run-dumper.sh --pid 4242 --output example.exe
```

Replace `4242` with a current PID from the list. The second command saves
`outputs/example/example.exe` and `outputs/example/example.exe.json`.
Existing files, reports, and dangling symlinks are preserved. Running the
launcher without arguments lists processes and prompts for a PID.
The launcher requests sudo; the dumper drops to the sudo caller after opening
the read-only RAM descriptor so captured files belong to that caller.

For an offline guest-physical RAM image, run without sudo:

```sh
./bin/qemu-process-dumper --image /path/to/ram.bin --list --json
./bin/qemu-process-dumper --image /path/to/ram.bin --pid 4242 --output offline.exe
```

Both paths require a discoverable kernel and its exact symbol profile.
Captures are non-atomic. Private paged-out/compressed pages cannot be replaced
with original executable bytes. Missing pages fail capture unless explicitly
accepted with `--allow-missing`; missing import metadata still causes an error.
Reconstruction does not guarantee that the resulting executable will run.

## Documentation and checks

- [Usage and troubleshooting](docs/usage.md)
- [Architecture, contracts, and capture reports](docs/architecture.md)
- [Migration and compatibility](docs/migration.md)
- [Legacy pausing debugger](docs/legacy.md)
- [Contributing and verification](CONTRIBUTING.md)

```sh
make check        # C++ syntax and warning checks, without linking the application
make test         # Focused native regression tests
make sanitize     # Same native tests with ASan and UBSan; runtimes required
make integration  # Builds the CLI; synthetic RAM + disposable running QEMU
```

Integration needs Python 3, `qemu-system-x86_64`, GNU `as`, `ld`, and `objcopy`.
It uses synthetic Windows structures and never contacts an existing VM.
See [verification details](CONTRIBUTING.md#verification) for test limits.

No license file was present in the supplied source project. This port does not
invent a license grant; confirm the licensing before redistributing it.
