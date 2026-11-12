# Migration from the Python project

The original `/home/kemerios/Documents/dumper` directory remains unchanged.
This repository contains native implementations; it does not embed Python,
invoke Python modules, or delegate capture to the reference project.
The bundled exact kernel profile and synthetic test data are preserved.

| Python entry point | C++ entry point |
| --- | --- |
| `python3 -m vmidbg.dumper ...` | `./bin/qemu-process-dumper ...` |
| `tools/copy-guest-file.py ...` | `./bin/qemu-process-dumper copy-guest-file ...` |
| `python3 -m vmidbg --allow-vm-pause ...` | `./bin/qemu-process-dumper legacy --allow-vm-pause ...` |
| `tools/attach-domain.py ...` | `./bin/qemu-process-dumper attach-domain ...` |

The launcher remains `./run-dumper.sh`. The domain/URI defaults, output folder
selection, exact profile requirement, import options, missing-page policy, and
shared-image recovery eligibility follow the Python live workflow.
Options and subcommands have explicit `--help` text.

The C++ reports retain the main Python PE report fields but add `implementation`.
Elapsed time is `duration_milliseconds` rather than `duration_seconds`.
Backing relocation delta is `relocation_delta_modulo_2_64`, an unsigned modular
value, rather than a signed `relocation_delta`. Copy-helper summaries are
smaller; the capture report remains the authoritative backing-byte provenance.
Argument errors return 1 rather than argparse's 2. Integers accept decimal
or a `0x` hexadecimal prefix. Legacy continue timeouts use whole seconds.

The `dump_process` ZIP64 helper is available through `qpd/dump.hpp`, with an
explicit caller-established halted-guest precondition. As in the Python
frontend, the terminal exposes raw range export through `dump`, not a process
archive command. C++ headers are a new source interface;
Python module imports and Python class APIs are not preserved.

The legacy debugger and host helpers are Linux platform branches. Portable
offline code is present, but macOS/Windows and ARM64 builds remain unverified.
The original source's real Windows/archive test claims are historical evidence
for that implementation, not validation of this port.

See [contributing](../CONTRIBUTING.md) for the checks actually available here.
