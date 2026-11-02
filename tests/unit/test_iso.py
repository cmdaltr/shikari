"""Tests for shikari.lab.iso — the Windows-ISO inspector, driven by synthetic ISO9660 images."""

import struct

import pytest

from shikari.lab import iso
from shikari.lab.iso import SECTOR

# Sector map for the fixtures below.
_ROOT, _SOURCES, _EFI, _BOOT = 20, 21, 22, 23


def _record(name: bytes, lba: int, size: int, is_dir: bool) -> bytes:
    rec_len = 33 + len(name)
    rec_len += rec_len % 2  # records are padded to an even length
    rec = bytearray(rec_len)
    rec[0] = rec_len
    struct.pack_into("<I", rec, 2, lba)
    struct.pack_into("<I", rec, 10, size)
    rec[25] = 0x02 if is_dir else 0x00
    rec[32] = len(name)
    rec[33:33 + len(name)] = name
    return bytes(rec)


def _dir(entries) -> bytes:
    recs = [_record(b"\x00", 0, 0, True), _record(b"\x01", 0, 0, True)]  # . and ..
    recs += [_record(n, lba, SECTOR, d) for (n, lba, d) in entries]
    data = b"".join(recs)
    return data + b"\x00" * (SECTOR - len(data))


def _pvd(volume_id: str) -> bytes:
    p = bytearray(SECTOR)
    p[0] = 1
    p[1:6] = b"CD001"
    p[6] = 1
    p[40:72] = volume_id.encode("ascii").ljust(32)[:32]
    root = bytearray(34)
    root[0] = 34
    struct.pack_into("<I", root, 2, _ROOT)
    struct.pack_into("<I", root, 10, SECTOR)
    root[25] = 0x02
    root[32] = 1
    p[156:190] = root
    return bytes(p)


def _write_iso(path, *, volume_id="CCCOMA_A64FRE_EN-US_DV9", install="INSTALL.WIM",
               boot_loader="BOOTAA64.EFI", with_sources=True, with_efi=True):
    sectors = [b"\x00" * SECTOR] * 24
    sectors[_PVD := iso._PVD_SECTOR] = _pvd(volume_id)

    top = []
    if with_sources:
        top.append((b"SOURCES", _SOURCES, True))
        sectors[_SOURCES] = _dir([(install.encode(), 30, False)] if install else [])
    if with_efi:
        top.append((b"EFI", _EFI, True))
        sectors[_EFI] = _dir([(b"BOOT", _BOOT, True)])
        sectors[_BOOT] = _dir([(boot_loader.encode(), 31, False)] if boot_loader else [])
    sectors[_ROOT] = _dir(top)

    path.write_bytes(b"".join(sectors))
    return str(path)


def test_arm64_windows_iso_is_ok(tmp_path):
    report = iso.inspect(_write_iso(tmp_path / "win.iso"))
    assert report.is_iso and report.is_windows
    assert report.arch == "arm64"
    assert report.ok_arm64
    assert "ARM64" in report.detail


def test_x64_windows_iso_is_not_ok(tmp_path):
    path = _write_iso(tmp_path / "win.iso", volume_id="CCCOMA_X64FRE_EN-US_DV9",
                      boot_loader="BOOTX64.EFI")
    report = iso.inspect(path)
    assert report.is_windows and report.arch == "x64"
    assert not report.ok_arm64
    assert "not ARM64" in report.detail


def test_non_windows_iso(tmp_path):
    report = iso.inspect(_write_iso(tmp_path / "x.iso", with_sources=False))
    assert report.is_iso and not report.is_windows
    assert not report.ok_arm64
    assert "not a Windows installer" in report.detail


def test_sources_without_install_is_not_windows(tmp_path):
    report = iso.inspect(_write_iso(tmp_path / "x.iso", install=""))
    assert report.is_iso and not report.is_windows


def test_install_esd_counts_as_windows(tmp_path):
    report = iso.inspect(_write_iso(tmp_path / "x.iso", install="INSTALL.ESD"))
    assert report.is_windows and report.ok_arm64


def test_arch_falls_back_to_volume_id(tmp_path):
    # No EFI tree, so arch comes from the volume label token.
    report = iso.inspect(_write_iso(tmp_path / "x.iso", with_efi=False))
    assert report.arch == "arm64" and report.ok_arm64


def test_not_an_iso(tmp_path):
    path = tmp_path / "junk.iso"
    path.write_bytes(b"\x00" * (SECTOR * 18))  # right size, no CD001 signature
    report = iso.inspect(str(path))
    assert not report.is_iso
    assert report.detail == "Not an ISO image."


def test_missing_file(tmp_path):
    report = iso.inspect(str(tmp_path / "nope.iso"))
    assert not report.is_iso
    assert "Can't read" in report.detail
