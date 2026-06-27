#!/usr/bin/env python3
"""
Generate deterministic PE fixtures for StealthLib tests.

Outputs (in the supplied build directory):
- tiny_null.dll       : minimal PE64 DLL with NO exports, export directory empty
                       (NumberOfFunctions=0, NumberOfNames=0). Exercises
                       get_proc() returning nullptr on empty export dir.
- is_forwarder.dll    : minimal PE64 DLL with one FORWARDED export ("B" -> "kernel32.GetProcAddress")
                       Exercises export directory parsing and forwarder detection.
- corrupt_header.bin  : bytes that begin with "MZ" but e_lfanew points OFF the file.
                       Exercises fali-closed nullpointer return from get_nt().

These are NOT loader-runnable binaries (they lack .text execution and the
correct ImageBase config); they exist solely as deterministic inputs for the
PE-parsing unit tests in StealthLib. They are generated from scratch in
pure Python (zero deps) so the toolchain does not need Windows or MinGW.
"""
from __future__ import annotations
import os
import struct
import sys


MZ_MAGIC = b"MZ"
PE_MAGIC = b"PE\0\0"


def align(offset: int, alignment: int) -> int:
    return ((offset + alignment - 1) // alignment) * alignment


def tiny_null_dll(path: str) -> None:
    """Minimal PE64 DLL with empty export directory."""
    file_alignment = 0x200
    section_alignment = 0x200
    header_size = 0x200

    # Layout
    dos_header_size = 0x40
    pe_sig_size = 4
    file_header_size = 20
    opt_header_size = 240  # 32-bit: 224 + 8 magic guard, 64-bit: 240 (112 + 128 data dirs)
    opt_header_64_size = 112 + 128  # standard fields + 16 DataDirectory entries
    size_of_headers = align(dos_header_size + pe_sig_size + file_header_size + opt_header_64_size, file_alignment)

    # Sections: .rdata only (small) with empty export directory
    export_dir_rva = size_of_headers
    export_dir_size = 40
    rdata_data = bytearray(export_dir_size)
    rdata_data[0:4] = struct.pack("<I", 0)        # Characteristics
    rdata_data[4:8] = struct.pack("<I", 0)        # TimeDateStamp
    rdata_data[8:10] = struct.pack("<H", 0)       # MajorVersion
    rdata_data[10:12] = struct.pack("<H", 0)      # MinorVersion
    rdata_data[12:16] = struct.pack("<I", 0)       # Name
    rdata_data[16:20] = struct.pack("<I", 1)      # Base
    rdata_data[20:24] = struct.pack("<I", 0)      # NumberOfFunctions = 0
    rdata_data[24:28] = struct.pack("<I", 0)      # NumberOfNames = 0
    rdata_data[28:32] = struct.pack("<I", 0)      # AddressOfFunctions
    rdata_data[32:36] = struct.pack("<I", 0)      # AddressOfNames
    rdata_data[36:40] = struct.pack("<I", 0)      # AddressOfNameOrdinals

    rdata_raw_size = len(rdata_data)
    rdata_raw = align(rdata_raw_size, file_alignment)
    rdata_virt_size = align(rdata_raw_size, section_alignment)

    # DataDirectory[0] (Export) must point to our rdata
    # DOS header stub
    out = bytearray()
    # DOS header (64 bytes): e_magic=MZ, e_lfanew at offset 0x3C
    out += bytearray(dos_header_size)
    out[0:2] = MZ_MAGIC
    out[0x3C:0x40] = struct.pack("<I", dos_header_size)  # e_lfanew
    out[2:0x3C] = b"\x90" * (0x3C - 2)  # NOP padding

    # PE signature
    out += PE_MAGIC

    # IMAGE_FILE_HEADER (20 bytes)
    file_header = struct.pack("<HHIIIHH",
        0x8664,      # Machine: AMD64
        1,           # NumberOfSections
        0xDEADBEEF,  # TimeDateStamp (deterministic)
        0,           # PointerToSymbolTable
        0,           # NumberOfSymbols
        opt_header_64_size,  # SizeOfOptionalHeader
        0x2022,      # Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE | DLL
    )
    out += file_header

    # IMAGE_OPTIONAL_HEADER64 (240 bytes = 112 + 128 (16 DataDirectory))
    # Fields layout: H BB IIIII Q II HHHHHH IIII HH QQQQ II  = 29 fields, 112 bytes
    std_fields = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20b,        # Magic: PE32+
        14,           # MajorLinkerVersion
        0,            # MinorLinkerVersion
        0,            # SizeOfCode
        0,            # SizeOfInitializedData
        0,            # SizeOfUninitializedData
        0,            # AddressOfEntryPoint
        0,            # BaseOfCode
        0x180000000,  # ImageBase
        section_alignment,  # SectionAlignment
        file_alignment,     # FileAlignment
        6, 0,        # OS Version
        0, 0,        # Image Version
        6, 0,        # Subsystem Version
        0,           # Win32VersionValue
        size_of_headers + rdata_virt_size,  # SizeOfImage
        size_of_headers,                     # SizeOfHeaders
        0,           # CheckSum
        3,           # Subsystem: WINDOWS_CUI
        0x4160,      # DllCharacteristics: HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT
        0x100000,    # SizeOfStackReserve
        0x1000,      # SizeOfStackCommit
        0x100000,    # SizeOfHeapReserve
        0x1000,      # SizeOfHeapCommit
        0,           # LoaderFlags
        16,          # NumberOfRvaAndSizes
    )
    out += std_fields

    # 16 DataDirectory entries (128 bytes total); entry[0] = Export, rest zero
    dd = bytearray(128)
    dd[0:8] = struct.pack("<II", export_dir_rva, export_dir_size)  # Export Table
    out += dd

    # Section table (one section) -- part of the headers, before the pad.
    section_header = b".rdata\x00\x00\x00"  # Name (8)
    section_header += struct.pack("<I", rdata_virt_size)    # VirtualSize
    section_header += struct.pack("<I", export_dir_rva)     # VirtualAddress
    section_header += struct.pack("<I", rdata_raw_size)     # SizeOfRawData
    section_header += struct.pack("<I", size_of_headers)    # PointerToRawData == VirtualAddress (flat)
    section_header += struct.pack("<IIIII",
        0, 0, 0, 0, 0  # PointerToRelocations ... NumberOfLineNumbers
    )
    section_header += struct.pack("<I", 0x40000040)  # Characteristics: INITIALIZED_DATA | READ
    out += section_header

    # Pad to size_of_headers so section data begins at export_dir_rva (flat).
    if len(out) < size_of_headers:
        out += b"\x00" * (size_of_headers - len(out))

    # Section data (.rdata)
    out += rdata_data
    if len(out) < size_of_headers + rdata_raw_size:
        out += b"\x00" * (size_of_headers + rdata_raw_size - len(out))

    with open(path, "wb") as f:
        f.write(out)


def is_forwarder_dll(path: str) -> None:
    """Minimal FLAT PE64 DLL with one FORWARDED export ("A" -> kernel32.GetProcAddress).

    Flat = SectionAlignment == FileAlignment, so every RVA equals its file
    offset. The parser addresses exports via base+RVA (as it does for real
    loaded images), so a flat raw fixture lets it read the bytes correctly.
    """
    file_alignment = 0x200
    section_alignment = 0x200  # flat: RVA == file offset

    dos_header_size = 0x40
    file_header_size = 20
    opt_header_64_size = 112 + 128
    size_of_headers = align(dos_header_size + 4 + file_header_size + opt_header_64_size + 40, file_alignment)

    export_dir_rva = size_of_headers  # section begins here; RVA == file offset

    # Contiguous .rdata layout (offset from rdata start == RVA - export_dir_rva):
    #   0..40   IMAGE_EXPORT_DIRECTORY (40 bytes)
    #   40..42  name string "A\0"
    #   42..44  pad
    #   44..48  AddressOfNames[1]      (uint32) -> RVA of "A"
    #   48..52  AddressOfFunctions[1]  (uint32) -> RVA of forwarder string
    #   52..54  AddressOfNameOrdinals[1] (uint16) = 0
    #   54..    forwarder string "kernel32.GetProcAddress\0"
    name_off = 40
    names_off = 44
    funcs_off = 48
    ordinals_off = 52
    fwd_off = 54
    forwarder_string = b"kernel32.GetProcAddress\x00"

    rdata = bytearray(40)  # export directory placeholder
    while len(rdata) < name_off:
        rdata += b"\x00"
    rdata += b"A\x00"
    while len(rdata) < names_off:
        rdata += b"\x00"
    rdata += struct.pack("<I", export_dir_rva + name_off)  # names[0] -> "A"
    while len(rdata) < funcs_off:
        rdata += b"\x00"
    rdata += struct.pack("<I", export_dir_rva + fwd_off)   # functions[0] -> forwarder
    while len(rdata) < ordinals_off:
        rdata += b"\x00"
    rdata += struct.pack("<H", 0)                          # ordinals[0] = 0
    while len(rdata) < fwd_off:
        rdata += b"\x00"
    rdata += forwarder_string

    # Fill the export directory (first 40 bytes of rdata).
    rdata[16:20] = struct.pack("<I", 1)  # Base = 1
    rdata[20:24] = struct.pack("<I", 1)  # NumberOfFunctions
    rdata[24:28] = struct.pack("<I", 1)  # NumberOfNames
    rdata[28:32] = struct.pack("<I", export_dir_rva + funcs_off)     # AddressOfFunctions
    rdata[32:36] = struct.pack("<I", export_dir_rva + names_off)     # AddressOfNames
    rdata[36:40] = struct.pack("<I", export_dir_rva + ordinals_off)  # AddressOfNameOrdinals

    rdata_raw = align(len(rdata), file_alignment)
    rdata_virt = align(len(rdata), section_alignment)
    rdata += b"\x00" * (rdata_raw - len(rdata))

    # DOS header
    out = bytearray()
    out += bytearray(dos_header_size)
    out[0:2] = MZ_MAGIC
    out[0x3C:0x40] = struct.pack("<I", dos_header_size)
    out[2:0x3C] = b"\x90" * (0x3C - 2)

    out += PE_MAGIC

    file_header = struct.pack("<HHIIIHH",
        0x8664, 1, 0xCAFEBABE, 0, 0, opt_header_64_size, 0x2022)
    out += file_header

    std_fields = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20b, 14, 0,
        0, 0, 0, 0, 0,
        0x180000000,
        section_alignment, file_alignment,
        6, 0, 0, 0, 6, 0,
        0,
        size_of_headers + rdata_virt,  # SizeOfImage
        size_of_headers, 0,
        3, 0x4160,
        0x100000, 0x1000, 0x100000, 0x1000,
        0, 16,
    )
    out += std_fields

    dd = bytearray(128)
    dd[0:8] = struct.pack("<II", export_dir_rva, 40)  # Export Table (rva, size)
    out += dd

    section_header = b".rdata\x00\x00\x00"
    section_header += struct.pack("<I", rdata_virt)        # VirtualSize
    section_header += struct.pack("<I", export_dir_rva)    # VirtualAddress
    section_header += struct.pack("<I", rdata_raw)         # SizeOfRawData
    section_header += struct.pack("<I", size_of_headers)   # PointerToRawData == VirtualAddress (flat)
    section_header += struct.pack("<IIIII", 0, 0, 0, 0, 0)
    section_header += struct.pack("<I", 0x40000040)        # INITIALIZED_DATA | READ
    out += section_header

    # Pad to size_of_headers so section data begins at export_dir_rva (flat).
    if len(out) < size_of_headers:
        out += b"\x00" * (size_of_headers - len(out))

    out += rdata
    if len(out) < size_of_headers + rdata_raw:
        out += b"\x00" * (size_of_headers + rdata_raw - len(out))

    with open(path, "wb") as f:
        f.write(out)


def corrupt_header(path: str) -> None:
    """MZ header with e_lfanew pointing FAR past the file end -> get_nt() == nullptr."""
    buf = bytearray(0x40)
    buf[0:2] = MZ_MAGIC
    buf[0x3C:0x40] = struct.pack("<I", 0xFFFFFFFF)  # invalid e_lfanew
    with open(path, "wb") as f:
        f.write(buf)


def main() -> int:
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <out-dir>", file=sys.stderr)
        return 2
    out_dir = sys.argv[1]
    os.makedirs(out_dir, exist_ok=True)

    tiny_null_dll(os.path.join(out_dir, "tiny_null.dll"))
    is_forwarder_dll(os.path.join(out_dir, "is_forwarder.dll"))
    corrupt_header(os.path.join(out_dir, "corrupt_header.bin"))

    print(f"[fixtures] wrote 3 files into {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
