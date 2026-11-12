# Legacy debugger: explicitly pausing QEMU

Use the live capture CLI for ordinary process listing and PE reconstruction.
The separate `legacy` command connects to QEMU's GDB stub and halts the whole
VM. It refuses to construct a transport without `--allow-vm-pause`.

Inspect or enable a loopback listener on the selected already-started domain:

```sh
./bin/qemu-process-dumper attach-domain --domain windows11-hardware
./bin/qemu-process-dumper attach-domain --enable-gdb --port 12345
```

The helper does not edit persistent XML or restart the VM. It refuses to replace
an existing GDB channel. Enabling a listener and connecting a debugger are
separate actions. The helper requires host libvirt permissions.

```sh
./bin/qemu-process-dumper legacy --allow-vm-pause \
  --endpoint tcp:127.0.0.1:12345 --pid 4242
```

`unix:/absolute/socket/path` is also accepted. Exact profile/kernel discovery
requirements still apply; pass current `--kernel-base`/`--kernel-cr3` if needed.
Only four-level AMD64 kernel paging is supported.

| Command | Behavior |
| --- | --- |
| `ps`, `attach PID` | Enumerate/select Windows process. |
| `threads`, `modules` | Traverse selected process metadata. |
| `cpu [ID]`, `regs` | Select/list QEMU vCPUs and inspect scalar registers. |
| `read VA SIZE` | Hex-dump a virtual range. |
| `dump VA SIZE FILE` | Publish a raw range without overwriting a file. |
| `disasm VA [SIZE]` | Run host `objdump` on a temporary copy, default 64 bytes. |
| `bp VA`, `bc VA`, `bl` | Add/remove/list hardware execute breakpoints (up to four). |
| `continue [SECONDS]` | Run with CR3 filtering until a selected target breakpoint, other stop, or deadline. |
| `step` | Advance the selected vCPU by one instruction. |
| `quit` or EOF | Remove owned breakpoints and disconnect, leaving the VM halted. |
| `resume` | Remove breakpoints, detach, resume the VM, and exit. |

Use `--command 'ps' --command 'resume'` for batch commands. Batch errors return
nonzero. `--resume-on-exit` also requests detach/resume after initialization or
command errors. Without it, exceptions leave the VM halted after cleanup.
The legacy path therefore has different cancellation semantics from live capture.
Always inspect host VM state if transport cleanup itself fails.

After detaching, disable the runtime listener if desired:

```sh
./bin/qemu-process-dumper attach-domain --disable-gdb
```

The live dumper never calls either legacy command or uses a GDB endpoint.
