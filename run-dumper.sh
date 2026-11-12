#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ ! -x "$root/bin/qemu-process-dumper" ]; then
    echo 'Executable missing. Run make first.' >&2
    exit 1
fi
exec sudo -- "$root/bin/qemu-process-dumper" "$@"
