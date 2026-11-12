"""Synthetic guest state only: no real Windows kernel or proprietary code."""

from pathlib import Path
import struct
import uuid

import json


class Profile:
    """Only fixture metadata access; production parsing is C++."""

    def __init__(self, data):
        self.data = data
        self.pdb = data["metadata"]["windows"]["pdb"]

    @classmethod
    def load(cls, path):
        return cls(json.loads(path.read_text(encoding="utf-8")))

    def offset(self, structure, field):
        return self.data["user_types"][structure]["fields"][field]["offset"]

    def symbol(self, name):
        return self.data["symbols"][name]["address"]

ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "profiles/B661C6FE72991D160FE37C48B8BC5470-1.json"
HIGH = 0xFFFF800000000000
KERNEL = HIGH + 0x200000
SYSTEM = HIGH + 0x1800000
TARGET = HIGH + 0x1802000
PID = 4242


class Fixture:
    def __init__(self):
        self.data = bytearray(32 * 1024 * 1024)
        self.profile = Profile.load(PROFILE_PATH)
        p = self.profile
        # Two roots map the same memory, allowing real CR3 context changes.
        for root in (0x1000, 0x5000):
            self.u64(root, 0x2003)
            self.u64(root + 256 * 8, 0x2003)
        self.u64(0x2000, 0x3003)
        for i in range(16):
            self.u64(0x3000 + i * 8, i * 0x200000 | 0x83)

        self.write(KERNEL, b"MZ")
        self.u32(KERNEL + 0x3C, 0x80)
        self.write(KERNEL + 0x80, b"PE\0\0")
        self.write(KERNEL + 0x84, struct.pack("<H", 0x8664))
        self.write(KERNEL + 0x94, struct.pack("<H", 0xF0))
        opt = KERNEL + 0x98
        self.write(opt, struct.pack("<H", 0x20B))
        self.u32(opt + 56, 0x1600000)
        self.u32(opt + 108, 16)
        self.write(opt + 112 + 6 * 8, struct.pack("<II", 0x1000, 28))
        identity = (b"RSDS" + uuid.UUID(p.pdb["GUID"]).bytes_le +
                    struct.pack("<I", p.pdb["age"]) + p.pdb["database"].encode() + b"\0")
        self.write(KERNEL + 0x1000, struct.pack("<IIHHIIII", 0, 0, 0, 0, 2, len(identity), 0x1100, 0))
        self.write(KERNEL + 0x1100, identity)
        head = KERNEL + p.symbol("PsActiveProcessHead")
        link = p.offset("_EPROCESS", "ActiveProcessLinks")
        self.list(head, [SYSTEM + link, TARGET + link])
        for address, pid, name, dtb in ((SYSTEM, 4, b"System", 0x1000), (TARGET, PID, b"fixture.exe", 0x5000)):
            self.u64(address + p.offset("_EPROCESS", "UniqueProcessId"), pid)
            self.write(address + p.offset("_EPROCESS", "ImageFileName"), name + b"\0")
            pcb = address + p.offset("_EPROCESS", "Pcb")
            self.u64(pcb + p.offset("_KPROCESS", "DirectoryTableBase"), dtb)
            self.u64(pcb + p.offset("_KPROCESS", "UserDirectoryTableBase"), dtb | 0xABC)
            self.list(address + p.offset("_EPROCESS", "ThreadListHead"), [])
        self.u64(KERNEL + p.symbol("PsInitialSystemProcess"), SYSTEM)

        # One native thread and a PEB loader entry exercise semantic traversal.
        thread = HIGH + 0x1804000
        self.list(TARGET + p.offset("_EPROCESS", "ThreadListHead"),
                  [thread + p.offset("_ETHREAD", "ThreadListEntry")])
        cid = thread + p.offset("_ETHREAD", "Cid")
        self.u64(cid + p.offset("_CLIENT_ID", "UniqueProcess"), PID)
        self.u64(cid + p.offset("_CLIENT_ID", "UniqueThread"), 4343)
        peb, ldr, entry, name = 0x1900000, 0x1901000, 0x1902000, 0x1903000
        self.u64(TARGET + p.offset("_EPROCESS", "Peb"), peb)
        self.u64(peb + p.offset("_PEB", "Ldr"), ldr)
        self.list(ldr + p.offset("_PEB_LDR_DATA", "InLoadOrderModuleList"),
                  [entry + p.offset("_LDR_DATA_TABLE_ENTRY", "InLoadOrderLinks")])
        self.u64(entry + p.offset("_LDR_DATA_TABLE_ENTRY", "DllBase"), 0x400000)
        self.u32(entry + p.offset("_LDR_DATA_TABLE_ENTRY", "SizeOfImage"), 0x1000)
        text = "fixture.exe".encode("utf-16-le")
        string = entry + p.offset("_LDR_DATA_TABLE_ENTRY", "BaseDllName")
        self.write(string + p.offset("_UNICODE_STRING", "Length"), struct.pack("<H", len(text)))
        self.u64(string + p.offset("_UNICODE_STRING", "Buffer"), name)
        self.write(name, text)
        self.write(0x400000, b"\x90\x90\xc3fixture-memory\0")

    @staticmethod
    def physical(address):
        return address - HIGH if address >= HIGH else address

    def write(self, address, data):
        address = self.physical(address)
        assert 0 <= address <= len(self.data) - len(data)
        self.data[address:address + len(data)] = data

    def u64(self, address, value):
        self.write(address, struct.pack("<Q", value))

    def u32(self, address, value):
        self.write(address, struct.pack("<I", value))

    def list(self, head, nodes):
        all_nodes = [head] + nodes
        for i, node in enumerate(all_nodes):
            self.u64(node, all_nodes[(i + 1) % len(all_nodes)])
            self.u64(node + 8, all_nodes[i - 1])

    def read_physical(self, address, size):
        if address < 0 or address + size > len(self.data):
            raise RuntimeError("Fixture physical read out of bounds")
        return bytes(self.data[address:address + size])
