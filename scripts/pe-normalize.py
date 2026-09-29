#!/usr/bin/env python3
"""
pe-normalize.py FILE EPOCH — makes a launch4j-built .exe reproducible: sets the PE header's
TimeDateStamp to EPOCH (the release's fixed build time) and recomputes the PE checksum, so the
same source and toolchain give the same bytes. Nothing else in the file is touched.
"""
import struct
import sys


def pe_checksum(data, checksum_offset):
    total = 0
    n = len(data)
    for i in range(0, n - n % 4, 4):
        if i == checksum_offset:
            continue
        total += struct.unpack_from("<I", data, i)[0]
        total = (total & 0xFFFFFFFF) + (total >> 32)
    if n % 4:
        total += int.from_bytes(data[n - n % 4:] + b"\0" * (4 - n % 4), "little")
        total = (total & 0xFFFFFFFF) + (total >> 32)
    total = (total & 0xFFFF) + (total >> 16)
    total = total + (total >> 16)
    return ((total & 0xFFFF) + n) & 0xFFFFFFFF


def main(path, epoch):
    data = bytearray(open(path, "rb").read())
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        sys.exit(f"{path}: not a PE file")
    struct.pack_into("<I", data, pe + 8, epoch)            # COFF TimeDateStamp
    checksum_offset = pe + 24 + 64                           # OptionalHeader.CheckSum (PE32 and PE32+)
    struct.pack_into("<I", data, checksum_offset, 0)
    struct.pack_into("<I", data, checksum_offset, pe_checksum(data, checksum_offset))
    open(path, "wb").write(data)


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]))
