"""
The first-boot seed for a Linux cloud image on Hyper-V or libvirt: a cloud-init NoCloud ISO
(volume label `cidata`, files `user-data` and `meta-data`) attached as a CD-ROM.

The user-data makes the guest Shikari can drive: a `shikari` user with passwordless sudo and
Shikari's SSH key, the QEMU guest agent (libvirt runs commands through it), the Hyper-V KVP
daemon (Hyper-V reports the guest's address through it), and an autologin serial console (the
browser Console on libvirt is `virsh console`).

The ISO is written here in pure Python (ISO9660 plus a Joliet tree, so the names keep their
lower case and hyphens) because neither host reliably has genisoimage: Windows has no ISO
builder at all, and Mount-VHD, the alternative, needs an elevated Shikari. Read back by
shikari.lab.iso's parser in the tests.
"""

import json
import struct
import time
from typing import Dict, List, Optional, Tuple

SECTOR = 2048
LABEL = "cidata"
GUEST_USER = "shikari"


def user_data(hostname: str, ssh_pubkey: str = "", engine: str = "libvirt") -> str:
    """The #cloud-config for a lab guest. cloud-init reads it once, on the first boot."""
    packages = ["qemu-guest-agent"] if engine == "libvirt" else []
    runcmd: List = []
    if engine == "libvirt":
        runcmd.append(["systemctl", "enable", "--now", "qemu-guest-agent"])
        # The browser Console attaches to ttyS0; log the shikari user straight in, like docker exec
        runcmd.append(["sh", "-c",
                       "mkdir -p /etc/systemd/system/serial-getty@ttyS0.service.d && printf '%s\\n' "
                       "'[Service]' 'ExecStart=' "
                       f"'ExecStart=-/sbin/agetty --autologin {GUEST_USER} --keep-baud 115200,38400,9600 %I $TERM' "
                       "> /etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf && "
                       "systemctl daemon-reload && systemctl restart serial-getty@ttyS0"])
    if engine == "hyperv":
        # hv_kvp_daemon reports the address to Get-VMNetworkAdapter; the kernel-matched package has it
        runcmd.append(["sh", "-c", "apt-get update -y && apt-get install -y linux-cloud-tools-$(uname -r) "
                                   "linux-cloud-tools-common || true"])
    user = {"name": GUEST_USER, "shell": "/bin/bash", "sudo": "ALL=(ALL) NOPASSWD:ALL",
            "groups": ["sudo"], "lock_passwd": True}
    if ssh_pubkey:
        user["ssh_authorized_keys"] = [ssh_pubkey.strip()]
    doc = {"hostname": hostname, "users": ["default", user], "ssh_pwauth": False,
           "package_update": bool(packages), "packages": packages, "runcmd": runcmd}
    # JSON is a subset of YAML, so cloud-init reads this as-is and nothing needs PyYAML
    return "#cloud-config\n" + json.dumps(doc, indent=2) + "\n"


def meta_data(hostname: str) -> str:
    return f"instance-id: {hostname}\nlocal-hostname: {hostname}\n"


# --- ISO9660 + Joliet, two files in the root ---------------------------------------------

def _both16(n: int) -> bytes:
    return struct.pack("<H", n) + struct.pack(">H", n)


def _both32(n: int) -> bytes:
    return struct.pack("<I", n) + struct.pack(">I", n)


def _dir_date(t: time.struct_time) -> bytes:
    return bytes([t.tm_year - 1900, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec, 0])


def _vol_date(t: time.struct_time) -> bytes:
    return time.strftime("%Y%m%d%H%M%S", t).encode() + b"00\x00"


def _record(name: bytes, lba: int, size: int, is_dir: bool, t: time.struct_time) -> bytes:
    rec = (bytes([0, 0]) + _both32(lba) + _both32(size) + _dir_date(t)
           + bytes([2 if is_dir else 0, 0, 0]) + _both16(1) + bytes([len(name)]) + name)
    if len(name) % 2 == 0:
        rec += b"\x00"  # records are an even length
    return bytes([len(rec)]) + rec[1:]


def _path_table(root_lba: int, big_endian: bool) -> bytes:
    lba = struct.pack(">I" if big_endian else "<I", root_lba)
    parent = struct.pack(">H" if big_endian else "<H", 1)
    return bytes([1, 0]) + lba + parent + b"\x00\x00"


def _text(s: str, n: int, joliet: bool) -> bytes:
    raw = s.encode("utf-16-be") if joliet else s.encode("ascii")
    pad = " ".encode("utf-16-be") if joliet else b" "
    while len(raw) < n:
        raw += pad
    return raw[:n]


def _descriptor(kind: int, root: bytes, total: int, lpath: int, mpath: int, ptsize: int,
                t: time.struct_time, joliet: bool) -> bytes:
    d = bytearray(SECTOR)
    d[0] = kind
    d[1:7] = b"CD001\x01"
    d[8:40] = _text("", 32, joliet)
    d[40:72] = _text(LABEL, 32, joliet)
    d[80:88] = _both32(total)
    if joliet:
        d[88:91] = b"%/E"  # UCS-2 level 3
    d[120:124] = _both16(1)
    d[124:128] = _both16(1)
    d[128:132] = _both16(SECTOR)
    d[132:140] = _both32(ptsize)
    d[140:144] = struct.pack("<I", lpath)
    d[148:152] = struct.pack(">I", mpath)
    d[156:190] = root
    for start, n in ((190, 128), (318, 128), (446, 128), (574, 128), (702, 37), (739, 37), (776, 37)):
        d[start:start + n] = _text("", n, joliet)
    d[813:830] = _vol_date(t)
    d[830:847] = _vol_date(t)
    d[847:864] = b"0" * 16 + b"\x00"
    d[864:881] = b"0" * 16 + b"\x00"
    d[881] = 1
    return bytes(d)


def build_iso(files: Dict[str, str], when: Optional[float] = None) -> bytes:
    """An ISO image holding `files` (name -> text) in its root, labelled cidata."""
    t = time.gmtime(when if when is not None else time.time())
    names = sorted(files)
    data = [files[n].encode("utf-8") for n in names]
    # Sectors: 16 system, 16 PVD, 17 Joliet SVD, 18 terminator, 19-22 path tables,
    # 23 primary root, 24 Joliet root, 25+ file data (shared by both trees)
    proot, jroot, lba = 23, 24, 25
    extents: List[Tuple[int, int]] = []
    for blob in data:
        extents.append((lba, len(blob)))
        lba += max(1, (len(blob) + SECTOR - 1) // SECTOR)
    total = lba + 150  # the customary 300 KB tail pad: some readers read ahead past the last file

    def root_dir(own: int, joliet: bool) -> bytes:
        out = _record(b"\x00", own, SECTOR, True, t) + _record(b"\x01", own, SECTOR, True, t)
        for name, (start, size) in zip(names, extents):
            if joliet:
                ident = (name + ";1").encode("utf-16-be")
            else:  # ISO level 1 d-characters; Linux and Windows read the Joliet names instead
                stem = "".join(c if c.isalnum() else "_" for c in name.upper())[:8]
                ident = (stem + ".;1").encode("ascii")
            out += _record(ident, start, size, False, t)
        return out.ljust(SECTOR, b"\x00")

    ptsize = len(_path_table(0, False))
    img = bytearray(SECTOR * 16)
    img += _descriptor(1, _record(b"\x00", proot, SECTOR, True, t), total, 19, 20, ptsize, t, False)
    img += _descriptor(2, _record(b"\x00", jroot, SECTOR, True, t), total, 21, 22, ptsize, t, True)
    img += bytes([255]) + b"CD001\x01" + bytes(SECTOR - 7)
    for root, big in ((proot, False), (proot, True), (jroot, False), (jroot, True)):
        img += _path_table(root, big).ljust(SECTOR, b"\x00")
    img += root_dir(proot, False)
    img += root_dir(jroot, True)
    for blob in data:
        img += blob.ljust(max(1, (len(blob) + SECTOR - 1) // SECTOR) * SECTOR, b"\x00")
    img += bytes(SECTOR * (total - lba))
    return bytes(img)


def nocloud_iso(hostname: str, ssh_pubkey: str = "", engine: str = "libvirt") -> bytes:
    return build_iso({"user-data": user_data(hostname, ssh_pubkey, engine),
                      "meta-data": meta_data(hostname)})
