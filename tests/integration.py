#!/usr/bin/env python3
"""Exercise the native CLI against synthetic RAM and a disposable running QEMU.

Python is a test driver only. The executable never imports the Python reference.
No existing VM is contacted. libvirt queries are routed through a strict proxy.
"""

import json
import os
from pathlib import Path
import re
import select
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time

from fixtures import Fixture, HIGH, KERNEL, TARGET, PID, PROFILE_PATH
from pe_fixture import BASE, DLL, loaded_pe

ROOT = Path(__file__).resolve().parents[1]
UUID = "b712fc4f-487c-48ca-a3da-fc2cf33f23f7"
COUNTER = 0x1A00000


def fixture():
    state = Fixture()
    p = state.profile
    state.write(BASE, loaded_pe())
    state.write(DLL, loaded_pe(dll=True))
    state.u64(TARGET + p.offset("_EPROCESS", "SectionBaseAddress"), BASE)
    state.u64(TARGET + p.offset("_EPROCESS", "CreateTime"), 12345)
    state.u64(0x70000, 0x00000001000600E9)
    state.u64(0x70070, KERNEL + 0x12345)
    state.u64(0x700A0, 0x1000)
    state.list(0x1901000 + p.offset("_PEB_LDR_DATA", "InLoadOrderModuleList"),
               [0x1902000, 0x1904000])
    state.u32(0x1902000 + p.offset("_LDR_DATA_TABLE_ENTRY", "SizeOfImage"), 0x4000)
    entry = 0x1904000
    state.u64(entry + p.offset("_LDR_DATA_TABLE_ENTRY", "DllBase"), DLL)
    state.u32(entry + p.offset("_LDR_DATA_TABLE_ENTRY", "SizeOfImage"), 0x4000)
    name = "fixture.dll".encode("utf-16-le")
    string = entry + p.offset("_LDR_DATA_TABLE_ENTRY", "BaseDllName")
    state.write(string, struct.pack("<H", len(name)))
    state.u64(string + p.offset("_UNICODE_STRING", "Buffer"), 0x1905000)
    state.write(0x1905000, name)
    return state


def disk_image(image):
    return image[:0x400] + image[0x1000:0x4000]


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(binary, *args, env=None, success=True):
    result = subprocess.run([str(binary), *map(str, args)], capture_output=True,
                            text=True, timeout=60, env=env, check=False)
    check((result.returncode == 0) == success,
          f"CLI status {result.returncode}: {result.stderr}")
    return json.loads(result.stdout) if success else result


def verify_output(summary):
    data = Path(summary["file"]).read_bytes()
    pe = struct.unpack_from("<I", data, 60)[0]
    count = struct.unpack_from("<H", data, pe + 6)[0]
    table = pe + 24 + struct.unpack_from("<H", data, pe + 20)[0]
    sections = [struct.unpack_from("<8sIIII", data, table + i * 40)
                for i in range(count)]
    check(count == 4 and sections[-1][0].rstrip(b"\0") == b".imprec",
          "Missing rebuilt section")
    report = json.loads(Path(summary["report"]).read_text(encoding="utf-8"))
    check([(item["dll"], item["name"], item["ordinal"], item["slot"])
           for item in report["imports"]] ==
          [("fixture.dll", "Alpha", 0, 0x20A0),
           ("fixture.dll", None, 9, 0x20A8)], "Wrong imports")
    check(not report["guest_pause_requested"] and not report["guest_memory_writes"],
          "Unexpected guest writes or pause")
    return report


def main():
    checks = {}
    with tempfile.TemporaryDirectory(prefix="qpd-integration-") as directory:
        root = Path(directory)
        (root / "bin").mkdir()
        (root / "profiles").mkdir()
        binary = root / "bin/qemu-process-dumper"
        shutil.copy2(ROOT / "bin/qemu-process-dumper", binary)
        shutil.copy2(PROFILE_PATH, root / "profiles" / PROFILE_PATH.name)
        state = fixture()
        image = root / "ram.bin"
        image.write_bytes(state.data)
        processes = run(binary, "--image", image, "--list", "--json")
        checks["offline_processes"] = [p["pid"] for p in processes] == [4, PID]
        modules = run(binary, "--image", image, "--pid", PID, "--modules", "--json")
        checks["offline_modules"] = [m["name"] for m in modules] == ["fixture.exe", "fixture.dll"]
        summary = run(binary, "--image", image, "--pid", PID, "--output", "offline.exe")
        verify_output(summary)
        checks["offline_pe_and_imports"] = summary["missing_ranges"] == 0
        run(binary, "--image", image, "--pid", PID, "--output", "offline.exe", success=False)
        checks["existing_output_preserved"] = Path(summary["file"]).exists()
        result = run(binary, "legacy", "--endpoint", "tcp:127.0.0.1:1", success=False)
        checks["legacy_pause_gate"] = "--allow-vm-pause" in result.stderr
        # The shared-image VAD makes .text genuinely file-backed/nonresident.
        p = state.profile
        state.u64(0x3000 + 2 * 8, 0x6003)
        for i in range(512):
            state.u64(0x6000 + i * 8, (BASE + i * 4096) | 3)
        state.u64(0x6008, 0)
        vad, proto = HIGH + 0x1B00000, HIGH + 0x1B01000
        state.u64(TARGET + p.offset("_EPROCESS", "VadRoot"), vad)
        state.u32(vad + p.offset("_MMVAD_SHORT", "StartingVpn"), BASE >> 12)
        state.u32(vad + p.offset("_MMVAD_SHORT", "EndingVpn"), (BASE + 0x3FFF) >> 12)
        state.u32(vad + p.offset("_MMVAD_SHORT", "u"), 2 << 4)
        state.u64(vad + p.offset("_MMVAD", "FirstPrototypePte"), proto)
        state.u64(vad + p.offset("_MMVAD", "LastContiguousPte"), proto + 24)
        state.u64(proto + 8, 0xAD8181472D580460)
        image.write_bytes(state.data)
        backing = root / "original.exe"
        backing.write_bytes(disk_image(loaded_pe()))
        # Offline capture also exercises resident/shared/private recovery rules.
        run(binary, "--image", image, "--pid", PID, "--output", "absent.exe", success=False)
        summary = run(binary, "--image", image, "--pid", PID, "--output", "backed.exe",
                      "--backing-file", backing)
        report = verify_output(summary)
        checks["verified_nonresident_file_recovery"] = (summary["file_recovered_ranges"] == 1
                                                       and report["capture_sources"] == "memory and backing file")
        # Firmware clears low RAM; boot code writes the low stub once in long mode.
        source = Path(__file__).with_name("boot.S").read_text(encoding="utf-8")
        source = source.replace("incq 0x400100", f"incq {COUNTER:#x}")
        source = source.replace("ready:\n", "ready:\n"
                                "    movabs $0x00000001000600e9, %rax\n"
                                "    mov %rax, 0x70000\n"
                                f"    movabs ${KERNEL + 0x12345:#x}, %rax\n"
                                "    mov %rax, 0x70070\n"
                                "    movq $0x1000, 0x700a0\n")
        (root / "boot.S").write_text(source, encoding="utf-8")
        for cmd in (["as", "--64", "-o", root / "boot.o", root / "boot.S"],
                    ["ld", "-m", "elf_x86_64", "-Ttext", "0x7c00", "-o", root / "boot.elf", root / "boot.o"],
                    ["objcopy", "-O", "binary", root / "boot.elf", root / "boot.bin"]):
            subprocess.run(cmd, check=True, capture_output=True)
        boot = bytearray(1440 * 1024)
        boot[:512] = (root / "boot.bin").read_bytes()
        (root / "boot.img").write_bytes(boot)
        with image.open("ab") as stream:
            stream.truncate(64 * 1024 * 1024)
        qemu_args = [os.environ.get("QEMU", "qemu-system-x86_64"), "-accel", "tcg", "-cpu", "qemu64",
                     "-m", "64M", "-smp", "2", "-uuid", UUID, "-nodefaults", "-display", "none",
                     "-serial", "none", "-monitor", "none", "-no-reboot", "-boot", "a",
                     "-drive", f"file={root / 'boot.img'},if=floppy,format=raw,readonly=on",
                     "-object", f"memory-backend-file,id=pc.ram,mem-path={image},size=64M,share=on",
                     "-machine", "memory-backend=pc.ram", "-qmp", "stdio"]
        with (root / "qemu.log").open("wb") as log:
            child = subprocess.Popen(qemu_args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=log, bufsize=0)
            requests = []
            lock = threading.Lock()

            def receive():
                line = bytearray()
                deadline = time.monotonic() + 10
                while not line.endswith(b"\n"):
                    check(select.select([child.stdout], [], [], max(0, deadline - time.monotonic()))[0],
                          "QMP response timeout")
                    value = os.read(child.stdout.fileno(), 1)
                    check(value, "QEMU exited: " + (root / "qemu.log").read_text(encoding="utf-8"))
                    line.extend(value)
                return json.loads(line)

            def qmp(request):
                with lock:
                    requests.append(request)
                    child.stdin.write((json.dumps(request) + "\n").encode())
                    while True:
                        result = receive()
                        if "return" in result or "error" in result:
                            return result

            server = socket.socket(socket.AF_UNIX)
            proxy = root / "proxy.sock"
            server.bind(str(proxy))
            server.listen()
            server.settimeout(0.1)
            stopped = threading.Event()
            thread = None
            observer = -1
            try:
                check("QMP" in receive(), "Missing QMP greeting")
                qmp({"execute": "qmp_capabilities"})
                block = qmp({"execute": "human-monitor-command", "arguments": {"command-line": "info ramblock"}})["return"]
                host = int(re.search(r"pc\.ram\s+\d+\s+\w+\s+0x\w+\s+0x\w+\s+0x\w+\s+(0x\w+)", block)[1], 16)
                observer = os.open(f"/proc/{child.pid}/mem", os.O_RDONLY)

                def counter():
                    return int.from_bytes(os.pread(observer, 8, host + COUNTER), "little")

                deadline = time.monotonic() + 10
                while counter() == 0 and time.monotonic() < deadline:
                    time.sleep(0.01)
                check(counter() > 0, "Synthetic guest did not boot")

                def serve():
                    while not stopped.is_set():
                        try:
                            connection, _ = server.accept()
                        except TimeoutError:
                            continue
                        with connection, connection.makefile("rwb") as stream:
                            try:
                                args = json.loads(stream.readline())
                                if args == ["domstate", "windows11-hardware"]:
                                    value = "running" if qmp({"execute": "query-status"})["return"]["running"] else "paused"
                                elif args == ["dumpxml", "windows11-hardware"]:
                                    value = f"<domain><uuid>{UUID}</uuid></domain>"
                                else:
                                    check(args[:2] == ["qemu-monitor-command", "windows11-hardware"] and len(args) == 3,
                                          "Unexpected libvirt command")
                                    request = json.loads(args[2])
                                    check(request["execute"] == "query-cpus-fast" or
                                          (request["execute"] == "human-monitor-command" and
                                           request["arguments"]["command-line"] in ("info ramblock", "info mtree -f")),
                                          "Execution control attempted")
                                    value = json.dumps(qmp(request))
                                result = {"status": 0, "output": value}
                            except (RuntimeError, ValueError, KeyError, OSError) as exc:
                                result = {"status": 1, "output": str(exc)}
                            stream.write((json.dumps(result) + "\n").encode())
                            stream.flush()

                thread = threading.Thread(target=serve)
                thread.start()
                shim = root / "bin/virsh"
                shim.write_text("#!/usr/bin/env python3\n"
                                "import json, os, socket, sys\n"
                                "with socket.socket(socket.AF_UNIX) as s:\n"
                                "    s.connect(os.environ['QPD_PROXY_SOCKET'])\n"
                                "    s.sendall((json.dumps(sys.argv[3:])+'\\n').encode())\n"
                                "    with s.makefile('r') as f: result=json.loads(f.readline())\n"
                                "print(result['output'])\n"
                                "sys.exit(result['status'])\n", encoding="utf-8")
                shim.chmod(0o700)
                env = dict(os.environ, PATH=str(root / "bin") + os.pathsep + os.environ["PATH"],
                           QPD_PROXY_SOCKET=str(proxy))
                start = counter()
                processes = run(binary, "--list", "--json", env=env)
                checks["live_processes"] = [p["pid"] for p in processes] == [4, PID]
                checks["running_during_listing"] = counter() > start
                start = counter()
                summary = run(binary, "--pid", PID, "--output", "live.exe", "--backing-file", backing, env=env)
                verify_output(summary)
                checks["running_during_dump"] = counter() > start
                checks["live_nonresident_recovery"] = summary["file_recovered_ranges"] == 1
                checks["qemu_still_running"] = qmp({"execute": "query-status"})["return"]["running"]
                checks["no_gdb_stub"] = "-gdb" not in qemu_args and "-S" not in qemu_args
                checks["only_read_queries"] = all(r["execute"] in ("qmp_capabilities", "query-status", "query-cpus-fast", "human-monitor-command") for r in requests)
            finally:
                stopped.set()
                if thread:
                    thread.join(timeout=15)
                server.close()
                if observer >= 0:
                    os.close(observer)
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
                child.stdin.close()
                child.stdout.close()
    result = {"checks": checks, "all_passed": all(checks.values()),
              "guest": "synthetic Windows structures, not a real Windows VM",
              "production_vm_touched": False, "real_windows_kvm_validated": False}
    destination = ROOT / "test-results"
    destination.mkdir(exist_ok=True)
    (destination / "integration.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
