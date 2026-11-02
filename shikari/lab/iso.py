"""
Read-only inspection of a Windows installation ISO, enough to decide whether the file the
user downloaded is a Windows 11 ARM64 installer before Shikari builds a VM from it.

Pure ISO9660: no mounting, no privileges, no third-party library. Joliet and UDF are
ignored — the names we look for (SOURCES, INSTALL.WIM, EFI/BOOT/BOOTAA64.EFI) all fit the
primary descriptor's 8.3 form, so the primary volume descriptor alone answers the question.

This verifies the ISO is a genuine Windows ARM64 installer; it is not a signature or hash
check — Microsoft publish no stable per-build hash, so a forged image with the right layout
would pass. The ISO is downloaded by the user from Microsoft, so that is the trust anchor.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO, Dict, Optional, Tuple

SECTOR = 2048
_PVD_SECTOR = 16  # ISO9660 volume descriptors start after the 16-sector system area

# A directory entry: (extent LBA, data length, is_dir).
_Entry = Tuple[int, int, bool]


@dataclass
class IsoReport:
    path: str
    is_iso: bool  # a readable ISO9660 image
    is_windows: bool  # carries a Windows installer (sources/install.{wim,esd})
    arch: Optional[str]  # "arm64", "x64" or None (from the EFI boot loader)
    volume_id: str  # the primary descriptor's volume identifier, trimmed
    detail: str  # one line for the UI

    @property
    def ok_arm64(self) -> bool:
        return self.is_iso and self.is_windows and self.arch == "arm64"

    def as_dict(self) -> Dict:
        return {
            "is_iso": self.is_iso, "is_windows": self.is_windows, "arch": self.arch,
            "volume_id": self.volume_id, "ok_arm64": self.ok_arm64, "detail": self.detail,
        }


def _read(f: BinaryIO, lba: int, sectors: int = 1) -> bytes:
    f.seek(lba * SECTOR)
    return f.read(SECTOR * sectors)


def _parse_record(data: bytes, off: int):
    """One ISO9660 directory record at `off`; returns (entry, name, next_off) or (None, ...)."""
    length = data[off]
    if length == 0:  # padding to the next sector
        return None, None, off
    ext_lba = struct.unpack_from("<I", data, off + 2)[0]  # little-endian half of the both-endian field
    size = struct.unpack_from("<I", data, off + 10)[0]
    is_dir = bool(data[off + 25] & 0x02)
    name_len = data[off + 32]
    name = data[off + 33: off + 33 + name_len]
    return (ext_lba, size, is_dir), name, off + length


def _list_dir(f: BinaryIO, lba: int, size: int) -> Dict[str, _Entry]:
    """Map upper-cased, version-stripped names to entries for one directory extent."""
    out: Dict[str, _Entry] = {}
    data = _read(f, lba, (size + SECTOR - 1) // SECTOR)
    off = 0
    while off < size:
        entry, name, nxt = _parse_record(data, off)
        if entry is None:  # jump to the next sector; records never cross the boundary
            off = ((off // SECTOR) + 1) * SECTOR
            continue
        if name not in (b"\x00", b"\x01"):  # skip . and ..
            key = name.split(b";", 1)[0].decode("ascii", "replace").upper()
            out[key] = entry
        off = nxt
    return out


def _detect_arch(f: BinaryIO, top: Dict[str, _Entry], volume_id: str) -> Optional[str]:
    efi = top.get("EFI")
    if efi and efi[2]:
        boot = _list_dir(f, efi[0], efi[1]).get("BOOT")
        if boot and boot[2]:
            names = _list_dir(f, boot[0], boot[1])
            if "BOOTAA64.EFI" in names:
                return "arm64"
            if "BOOTX64.EFI" in names:
                return "x64"
    vid = volume_id.upper()  # fall back to the release's volume label token
    if "A64FRE" in vid or "ARM64" in vid:
        return "arm64"
    if "X64FRE" in vid:
        return "x64"
    return None


def inspect(path: str) -> IsoReport:
    try:
        with open(path, "rb") as f:
            pvd = _read(f, _PVD_SECTOR)
            if len(pvd) < 190 or pvd[0] != 1 or pvd[1:6] != b"CD001":
                return IsoReport(path, False, False, None, "", "Not an ISO image.")
            volume_id = pvd[40:72].decode("ascii", "replace").replace("\x00", " ").strip()
            root = pvd[156:190]
            root_lba = struct.unpack_from("<I", root, 2)[0]
            root_size = struct.unpack_from("<I", root, 10)[0]
            top = _list_dir(f, root_lba, root_size)

            src = top.get("SOURCES")
            is_windows = bool(src and src[2]) and bool(
                {"INSTALL.WIM", "INSTALL.ESD"} & set(_list_dir(f, src[0], src[1])))
            arch = _detect_arch(f, top, volume_id)
    except (OSError, struct.error) as exc:
        return IsoReport(path, False, False, None, "", f"Can't read the ISO: {exc}")

    if not is_windows:
        detail = "A valid ISO, but not a Windows installer (no sources/install.wim)."
    elif arch != "arm64":
        detail = f"A Windows installer, but {arch or 'an unknown architecture'}, not ARM64."
    else:
        detail = f"Windows ARM64 installer ({volume_id})." if volume_id else "Windows ARM64 installer."
    return IsoReport(path, True, is_windows, arch, volume_id, detail)
