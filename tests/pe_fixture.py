"""Small synthetic loaded PE images, including named and ordinal imports."""
import struct

BASE = 0x400000
DLL = 0x700000


def loaded_pe(width=8, dll=False, original_thunks=True):
    data = bytearray(0x4000)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    optional_size = 240 if width == 8 else 224
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664 if width == 8 else 0x14C,
                     3, 0, 0, 0, optional_size, 0x2022 if dll else 0x22)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x20B if width == 8 else 0x10B)
    struct.pack_into("<I", data, opt + 16, 0x1000)
    struct.pack_into("<Q" if width == 8 else "<I", data, opt + (24 if width == 8 else 28), DLL if dll else BASE)
    struct.pack_into("<II", data, opt + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, opt + 56, 0x4000, 0x400)
    directory = opt + (112 if width == 8 else 96)
    struct.pack_into("<I", data, directory - 4, 16)
    sections = [(b".text", 0x1000, 0x60000020), (b".rdata", 0x2000, 0x40000040), (b".data", 0x3000, 0xC0000040)]
    for i, (name, rva, flags) in enumerate(sections):
        struct.pack_into("<8sIIIIIIHHI", data, opt + optional_size + 40 * i,
                         name, 0x1000, rva, 0x1000, 0x400 + i * 0x1000, 0, 0, 0, 0, flags)
    data[0x1000:0x2000] = b"\x90" * 4096
    if dll:
        struct.pack_into("<II", data, directory, 0x2000, 0x100)
        struct.pack_into("<IIHHIIIIIII", data, 0x2000, 0, 0, 0, 0, 0x2080, 8, 2, 1, 0x20A0, 0x20B0, 0x20C0)
        data[0x2080:0x208C] = b"fixture.dll\0"
        struct.pack_into("<II", data, 0x20A0, 0x1000, 0x1100)
        struct.pack_into("<I", data, 0x20B0, 0x20D0)
        struct.pack_into("<H", data, 0x20C0, 0)
        data[0x20D0:0x20D6] = b"Alpha\0"
    else:
        struct.pack_into("<II", data, directory + 8, 0x2000, 40)
        struct.pack_into("<II", data, directory + 12 * 8, 0x20A0, width * 3)
        struct.pack_into("<5I", data, 0x2000, 0x2080 if original_thunks else 0, 0, 0, 0x2050, 0x20A0)
        data[0x2050:0x205C] = b"fixture.dll\0"
        fmt = "<Q" if width == 8 else "<I"
        struct.pack_into(fmt, data, 0x2080, 0x2200)
        struct.pack_into(fmt, data, 0x2080 + width, (1 << (width * 8 - 1)) | 9)
        struct.pack_into(fmt, data, 0x20A0, DLL + 0x1000)
        struct.pack_into(fmt, data, 0x20A0 + width, DLL + 0x1100)
        data[0x2200:0x2208] = b"\0\0Alpha\0"
    return data
