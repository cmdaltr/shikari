"""The Hyper-V and libvirt engines, and the cloud-init seed they share: output parsing, the
commands and PowerShell they build, detection and wiring. run() is patched throughout, so neither
Hyper-V nor libvirt is needed."""

import base64
import io
import json
import re

import pytest

from shikari.lab import engines, hosts, iso, machines, seed, templates
from shikari.lab.runner import LabError


@pytest.fixture
def reg(monkeypatch, tmp_path):
    """A throwaway registry, with the password encryption swapped for something reversible."""
    import shikari.lab.registry as registry

    monkeypatch.setattr(registry, "_PATH", str(tmp_path / "machines.json"))
    monkeypatch.setattr(registry, "LAB_DIR", str(tmp_path))
    monkeypatch.setattr("shikari.auth.encryption.encrypt_api_key", lambda s: "enc:" + s[::-1])
    monkeypatch.setattr("shikari.auth.encryption.decrypt_api_key", lambda s: s[4:][::-1])
    return registry


def _decode_ps(argv):
    """The script inside a ps_argv command line."""
    assert argv[:2] == ["powershell", "-NoProfile"] and argv[-2] == "-EncodedCommand"
    return base64.b64decode(argv[-1]).decode("utf-16-le")


# --- the seed --------------------------------------------------------------------------------

def test_seed_iso_is_cidata_with_lowercase_joliet_names():
    img = seed.nocloud_iso("shi-ubu24", "ssh-ed25519 AAAA test", engine="libvirt")
    f = io.BytesIO(img)
    pvd, svd = img[16 * 2048:17 * 2048], img[17 * 2048:18 * 2048]
    assert pvd[1:6] == b"CD001" and pvd[40:72].decode().strip() == "cidata"
    assert svd[0] == 2 and svd[88:91] == b"%/E"                    # Joliet, UCS-2 level 3
    assert svd[40:72].decode("utf-16-be").strip() == "cidata"
    size = int.from_bytes(pvd[80:84], "little")
    assert len(img) == size * 2048                                   # the declared size is the real one
    root = svd[156:190]
    lba, length = int.from_bytes(root[2:6], "little"), int.from_bytes(root[10:14], "little")
    data, off, files = img[lba * 2048:lba * 2048 + length], 0, {}
    while off < length and data[off]:
        (ext, n, _), name, off = iso._parse_record(data, off)
        if name not in (b"\x00", b"\x01"):
            files[name.decode("utf-16-be").split(";")[0]] = img[ext * 2048:ext * 2048 + n].decode()
    assert set(files) == {"meta-data", "user-data"}
    assert "instance-id: shi-ubu24" in files["meta-data"]
    assert files["user-data"].startswith("#cloud-config\n")
    # the primary tree is readable by the existing ISO parser too
    assert set(iso._list_dir(f, 23, 2048)) == {"META_DAT.", "USER_DAT."}


def test_user_data_per_engine():
    def doc(engine):
        text = seed.user_data("shi-ubu24", "ssh-ed25519 AAAA k", engine)
        return json.loads(text.split("\n", 1)[1])  # JSON is YAML, so cloud-init reads it as is

    kvm, hv = doc("libvirt"), doc("hyperv")
    user = kvm["users"][1]
    assert user["name"] == "shikari" and user["ssh_authorized_keys"] == ["ssh-ed25519 AAAA k"]
    assert user["sudo"].endswith("NOPASSWD:ALL") and user["lock_passwd"] is True
    assert "qemu-guest-agent" in kvm["packages"]
    assert any("--autologin shikari" in " ".join(c) for c in kvm["runcmd"])
    assert hv["packages"] == [] and any("linux-cloud-tools" in " ".join(c) for c in hv["runcmd"])


# --- Hyper-V: PowerShell building and parsing -----------------------------------------------

def test_psq_and_encoded_command():
    assert engines.psq("it's") == "'it''s'"
    script = _decode_ps(engines.ps_argv("Get-VM | Out-Null"))
    assert script.startswith("$ErrorActionPreference='Stop'") and script.endswith("Get-VM | Out-Null")


def test_parse_hyperv_vms_handles_one_many_none_and_numeric_states():
    many = json.dumps([{"Name": "shi-ubu24", "State": "Running", "Uptime": "00:12:03.5", "Notes": "shikari.lab=1"},
                       {"Name": "other", "State": "Off", "Uptime": "00:00:00", "Notes": ""}])
    rows = engines.parse_hyperv_vms(many)
    assert [(r["name"], r["state"], r["shikari_made"]) for r in rows] == [
        ("shi-ubu24", "running", True), ("other", "stopped", False)]
    assert rows[0]["detail"] == "running, up 00:12:03" and rows[0]["engine"] == "hyperv"
    one = engines.parse_hyperv_vms(json.dumps({"Name": "solo", "State": 2}))  # PS 5.1 enum as number
    assert one[0]["state"] == "running" and one[0]["detail"].startswith("running")
    assert engines.parse_hyperv_vms(json.dumps({"Name": "s", "State": 6}))[0]["detail"] == "saved"
    assert engines.parse_hyperv_vms("") == [] and engines.parse_hyperv_vms("not json") == []


def test_parse_hyperv_address_prefers_kvp_then_neighbours():
    kvp = json.dumps({"ips": ["fe80::1", "172.20.1.5"], "neighbours": ["172.20.1.9"], "mac": "00155D"})
    assert engines.parse_hyperv_address(kvp) == "172.20.1.5"
    nb = json.dumps({"ips": [], "neighbours": ["169.254.3.3", "172.20.1.9"], "mac": "00155D"})
    assert engines.parse_hyperv_address(nb) == "172.20.1.9"
    assert engines.parse_hyperv_address(json.dumps({"ips": None, "neighbours": []})) == ""


def test_hyperv_create_script_from_a_base_disk_is_differencing_with_a_seed():
    s = engines.hyperv_create_script("shi-ubu24", r"C:\lab\shi-ubu24", base=r"C:\img\noble.vhdx",
                                     seed=r"C:\lab\shi-ubu24\seed.iso", linux=True)
    assert r"New-VHD -Path 'C:\lab\shi-ubu24\shi-ubu24.vhdx' -ParentPath 'C:\img\noble.vhdx' -Differencing" in s
    assert "-Generation 2" in s and "-SwitchName 'Default Switch'" in s
    assert "-CheckpointType Standard" in s and "-AutomaticCheckpointsEnabled $false" in s
    assert "MicrosoftUEFICertificateAuthority" in s
    assert r"Add-VMDvdDrive -VMName 'shi-ubu24' -Path 'C:\lab\shi-ubu24\seed.iso'" in s
    assert "FirstBootDevice" not in s and "Enable-VMTPM" not in s


def test_hyperv_create_script_from_an_iso_boots_it_and_gives_windows_a_tpm():
    s = engines.hyperv_create_script("shi-win11", r"C:\lab\shi-win11", iso=r"C:\Users\O'Neil\Win11.iso",
                                     linux=False, memory_mb=4096, cpus=4)
    assert "-SizeBytes 64GB -Dynamic" in s and "-MemoryStartupBytes 4096MB" in s and "-Count 4" in s
    assert r"-Path 'C:\Users\O''Neil\Win11.iso' -Passthru" in s  # the apostrophe can't end the string
    assert "-FirstBootDevice $dvd" in s and "Enable-VMTPM" in s and "-EnableSecureBoot On" in s


def test_hyperv_a_vhd_parent_makes_a_generation_1_vm():
    s = engines.hyperv_create_script("shi-ws22", r"C:\lab\shi-ws22", base=r"C:\img\ws2022.vhd", linux=False)
    assert "-Generation 1" in s and r"-Path 'C:\lab\shi-ws22\shi-ws22.vhd' -ParentPath" in s
    assert "Set-VMFirmware" not in s  # Generation 1 has BIOS, not UEFI firmware


def test_powershell_direct_script_carries_argv_as_data_and_no_password():
    argv = ["powershell", "-NoProfile", "-Command", "Write-Output 'a'; $x = \"b\""]
    s = engines.hyperv_direct_script("shi-win11", "Administrator", argv, has_input=True)
    elements = re.search(r"\$argv = @\(@\(([^)]*)\)", s).group(1)
    assert [base64.b64decode(e.strip("'")).decode() for e in elements.split(",")] == argv
    assert "Invoke-Command -VMName 'shi-win11' -Credential $cred" in s
    assert "PSCredential('Administrator'" in s and "$true -ScriptBlock" in s
    assert "Write-Output" not in s  # the command is only ever inside the base64
    assert "exit $r.code" in s


def test_ssh_argv_quotes_each_element_for_the_remote_shell():
    a = engines.ssh_argv("shikari", "172.20.1.5", "/k/id", ["bash", "-lc", "echo $HOME; id"])
    assert a[0] == "ssh" and "BatchMode=yes" in a and "shikari@172.20.1.5" in a
    assert a[a.index("--") + 1] == "bash -lc 'echo $HOME; id'"


# --- Hyper-V: the engine with run() patched ---------------------------------------------------

@pytest.fixture
def ps(monkeypatch):
    """Record every command; answer PowerShell from `replies` (a list of (substring, output))."""
    calls, replies = [], []

    def fake_run(argv, timeout=120, check=True, input_text=None):
        script = _decode_ps(argv) if argv[0] == "powershell" else ""
        calls.append({"argv": list(argv), "script": script, "input": input_text, "check": check})
        for needle, out in replies:
            if needle in script or needle in " ".join(argv):
                if isinstance(out, Exception):
                    raise out
                return out
        return ""

    monkeypatch.setattr("shikari.lab.engines.run", fake_run)
    return calls, replies


def test_hyperv_lifecycle_commands(ps, reg):
    calls, replies = ps
    hv = engines.HyperV()
    hv.start("shi-ubu24")
    hv.snapshot("shi-ubu24", "clean")
    hv.revert("shi-ubu24", "clean")
    hv.stop("shi-ubu24")
    hv.delete("shi-ubu24")
    scripts = [c["script"] for c in calls]
    assert "Start-VM -Name 'shi-ubu24'" in scripts[0]
    assert "Remove-VMCheckpoint" in scripts[1] and "Checkpoint-VM -Name 'shi-ubu24' -SnapshotName 'clean'" in scripts[1]
    assert "Restore-VMCheckpoint" in scripts[2] and "Start-VM" in scripts[2]  # resumes a Saved restore
    assert "-TurnOff" in scripts[3] and calls[3]["check"] is False
    assert "Remove-VM -VM $vm -Force" in scripts[4] and "Remove-Item -Recurse" in scripts[4]
    assert reg.LAB_DIR in scripts[4]  # only Shikari's own folder for the machine


def test_hyperv_revert_to_a_missing_checkpoint(ps, reg):
    calls, replies = ps
    replies.append(("Restore-VMCheckpoint", LabError("powershell failed", engines.NO_SNAPSHOT)))
    with pytest.raises(LabError) as e:
        engines.HyperV().revert("shi-ubu24", "nope")
    assert e.value.message == "No such snapshot"


def test_hyperv_create_linux_from_a_vhdx_writes_the_seed(ps, reg, monkeypatch, tmp_path):
    calls, _ = ps
    base = tmp_path / "noble.vhdx"
    base.write_bytes(b"x")
    monkeypatch.setattr(engines, "ssh_key", lambda: "ssh-ed25519 AAAA shikari-lab")
    engines.HyperV().create("shi-ubu24", str(base), os_name="linux")
    seed_path = tmp_path / "hyperv" / "shi-ubu24" / "seed.iso"
    assert seed_path.is_file() and b"cidata" in seed_path.read_bytes()[16 * 2048:17 * 2048]
    assert "-Differencing" in calls[-1]["script"] and str(seed_path) in calls[-1]["script"]


def test_hyperv_create_converts_a_cloud_image_once(ps, reg, monkeypatch, tmp_path):
    calls, _ = ps
    img = tmp_path / "noble.img"
    img.write_bytes(b"q")
    monkeypatch.setattr(engines, "ssh_key", lambda: "ssh-ed25519 AAAA k")
    engines.HyperV().create("shi-ubu24", str(img), os_name="linux")
    conv = [c["argv"] for c in calls if c["argv"][0] == "qemu-img"]
    assert conv and conv[0][:4] == ["qemu-img", "convert", "-O", "vhdx"] and conv[0][-1].endswith("noble.vhdx")


def test_hyperv_refuses_an_unknown_image_type(ps, reg, tmp_path):
    f = tmp_path / "disk.vmdk"
    f.write_bytes(b"v")
    with pytest.raises(LabError):
        engines.HyperV().create("x1", str(f))


def test_hyperv_windows_exec_needs_a_login_then_sends_it_on_stdin(ps, reg):
    calls, _ = ps
    reg.record("hyperv", "shi-win11", "hyperv-vm", "windows", "")
    with pytest.raises(LabError) as e:
        engines.HyperV().exec("shi-win11", ["cmd", "/c", "echo", "ok"], timeout=30)
    assert e.value.message == "Set the guest login first"
    reg.set_access("hyperv", "shi-win11", user="labadmin", password="S3cret!")
    assert "S3cret" not in json.dumps(reg._load())  # kept encrypted
    engines.HyperV().exec("shi-win11", ["cmd", "/c", "echo", "ok"], timeout=30, input_text="data")
    last = calls[-1]
    assert "Invoke-Command -VMName 'shi-win11'" in last["script"] and "'labadmin'" in last["script"]
    assert last["input"] == "S3cret!\ndata" and "S3cret" not in last["script"]


def test_hyperv_linux_exec_is_ssh_to_the_reported_address(ps, reg, monkeypatch):
    calls, replies = ps
    reg.record("hyperv", "shi-ubu24", "ubuntu-hyperv", "linux", "")
    monkeypatch.setattr(engines, "ssh_key", lambda: "ssh-ed25519 AAAA k")
    replies.append(("Get-VMNetworkAdapter", json.dumps({"ips": ["172.20.1.5"], "neighbours": []})))
    engines.HyperV().exec("shi-ubu24", ["id"], timeout=30)
    assert calls[-1]["argv"][0] == "ssh" and "shikari@172.20.1.5" in calls[-1]["argv"]
    reg.set_access("hyperv", "shi-ubu24", user="ben", host="172.20.9.9", key="/k/mine")
    engines.HyperV().exec("shi-ubu24", ["id"], timeout=30)
    a = calls[-1]["argv"]
    assert "ben@172.20.9.9" in a and a[a.index("-i") + 1] == "/k/mine"


def test_hyperv_linux_exec_without_an_address_says_so(ps, reg, monkeypatch):
    _, replies = ps
    reg.record("hyperv", "shi-ubu24", "ubuntu-hyperv", "linux", "")
    monkeypatch.setattr(engines, "ssh_key", lambda: "k")
    replies.append(("Get-VMNetworkAdapter", json.dumps({"ips": [], "neighbours": []})))
    with pytest.raises(LabError) as e:
        engines.HyperV().exec("shi-ubu24", ["id"], timeout=30)
    assert "no address" in e.value.message


# --- libvirt: parsing and building ------------------------------------------------------------

def test_parse_virsh_list():
    out = (" Id   Name          State\n"
           "------------------------------\n"
           " 3    shi-ubu24     running\n"
           " -    shi-win11     shut off\n"
           " -    other-vm      paused\n\n")
    rows = engines.parse_virsh_list(out)
    assert [(r["name"], r["state"], r["detail"]) for r in rows] == [
        ("shi-ubu24", "running", "running"), ("shi-win11", "stopped", "shut off"), ("other-vm", "stopped", "paused")]
    assert all(r["engine"] == "libvirt" for r in rows) and engines.parse_virsh_list("") == []


def test_parse_domifaddr_domdisplay_and_domblklist():
    ifa = (" Name       MAC address          Protocol     Address\n"
           "-------------------------------------------------------------------------------\n"
           " lo         00:00:00:00:00:00    ipv4         127.0.0.1/8\n"
           " enp1s0     52:54:00:aa:bb:cc    ipv4         192.168.122.57/24\n"
           " -          -                    ipv6         fe80::5054:ff:feaa:bbcc/64\n")
    assert engines.parse_domifaddr(ifa) == ["192.168.122.57"]
    assert engines.parse_domdisplay("vnc://127.0.0.1:0\n") == ("127.0.0.1", 5900, "vnc")
    assert engines.parse_domdisplay("vnc://localhost:3") == ("127.0.0.1", 5903, "vnc")
    assert engines.parse_domdisplay("spice://127.0.0.1:5930") == ("127.0.0.1", 5930, "spice")
    assert engines.parse_domdisplay("") is None
    blk = (" Type   Device   Target   Source\n"
           "------------------------------------------------------------\n"
           " file   disk     vda      /var/lib/libvirt/images/shi-ubu24.qcow2\n"
           " file   cdrom    sda      /var/lib/libvirt/images/shi-ubu24-seed.iso\n"
           " file   cdrom    sdb      -\n")
    disks = engines.parse_domblklist(blk)
    assert [(d["device"], d["target"], d["source"]) for d in disks] == [
        ("disk", "vda", "/var/lib/libvirt/images/shi-ubu24.qcow2"),
        ("cdrom", "sda", "/var/lib/libvirt/images/shi-ubu24-seed.iso"), ("cdrom", "sdb", "-")]


def test_guest_agent_commands_and_replies():
    cmd = json.loads(engines.guest_exec_command(["bash", "-lc", "id"], input_text="hi"))
    assert cmd["execute"] == "guest-exec"
    assert cmd["arguments"]["path"] == "bash" and cmd["arguments"]["arg"] == ["-lc", "id"]
    assert cmd["arguments"]["capture-output"] is True
    assert base64.b64decode(cmd["arguments"]["input-data"]) == b"hi"
    assert json.loads(engines.agent_command("guest-file-write", handle=7, buf_b64="QQ=="))["arguments"] == {
        "handle": 7, "buf-b64": "QQ=="}
    done = json.dumps({"return": {"exited": True, "exitcode": 0,
                                  "out-data": base64.b64encode(b"uid=0(root)\n").decode()}})
    st = engines.parse_exec_status(done)
    assert st["exited"] and st["code"] == 0 and st["out"] == "uid=0(root)\n"
    assert engines.parse_exec_status(json.dumps({"return": {"exited": False}}))["exited"] is False
    with pytest.raises(LabError):
        engines.parse_agent_return(json.dumps({"error": {"class": "GenericError", "desc": "no agent"}}))
    with pytest.raises(LabError):
        engines.parse_agent_return("garbage")


def test_virt_install_imports_a_volume_or_installs_from_an_iso():
    imp = engines.virt_install_argv("shi-ubu24", disk="shi-ubu24.qcow2", seed="shi-ubu24-seed.iso",
                                    osinfo="ubuntu24.04")
    assert imp[:3] == ["virt-install", "--connect", engines.LIBVIRT_URI] and "--import" in imp
    assert f"vol={engines.LIBVIRT_POOL}/shi-ubu24.qcow2,bus=virtio" in imp
    assert f"vol={engines.LIBVIRT_POOL}/shi-ubu24-seed.iso,device=cdrom" in imp
    assert "unix,target_type=virtio,name=org.qemu.guest_agent.0" in imp
    assert "vnc,listen=127.0.0.1" in imp and imp[imp.index("--osinfo") + 1] == "ubuntu24.04"
    assert "--boot" not in imp  # BIOS, so internal snapshots work
    win = engines.virt_install_argv("shi-win11", iso="/pool/Win11.iso", windows=True)
    assert "--cdrom" in win and "--import" not in win
    assert any(a.endswith("bus=sata") for a in win) and any("model=e1000e" in a for a in win)
    assert win[win.index("--osinfo") + 1] == "detect=on,require=off"


# --- libvirt: the engine with run() patched ---------------------------------------------------

@pytest.fixture
def vsh(monkeypatch):
    calls, replies = [], []

    def fake_run(argv, timeout=120, check=True, input_text=None):
        calls.append(list(argv))
        line = " ".join(argv)
        for needle, out in replies:
            if needle in line:
                if isinstance(out, Exception):
                    raise out
                return out() if callable(out) else out
        return ""

    monkeypatch.setattr("shikari.lab.engines.run", fake_run)
    monkeypatch.setattr("shikari.lab.engines.run_ok", lambda argv, **k: False)
    monkeypatch.setattr("shikari.lab.engines.time.sleep", lambda s: None)
    return calls, replies


def test_libvirt_create_from_a_cloud_image(vsh, reg, monkeypatch, tmp_path):
    calls, _ = vsh
    img = tmp_path / "noble-server-cloudimg-amd64.img"
    img.write_bytes(b"qcow2")
    monkeypatch.setattr(engines, "ssh_key", lambda: "ssh-ed25519 AAAA k")
    engines.Libvirt().create("shi-ubu24", str(img), os_name="linux", osinfo="ubuntu24.04")
    base = "shikari-base-noble-server-cloudimg-amd64.img"
    lines = [" ".join(c) for c in calls]
    assert any(f"vol-upload --pool default {base}" in l for l in lines)
    assert any("vol-create-as default shi-ubu24.qcow2 20G --format qcow2 --backing-vol " + base in l for l in lines)
    assert any("vol-upload --pool default shi-ubu24-seed.iso" in l for l in lines)
    assert calls[-1][0] == "virt-install" and "--import" in calls[-1]


def test_libvirt_exec_polls_the_guest_agent(vsh, reg):
    calls, replies = vsh
    states = iter([{"exited": False}, {"exited": True, "exitcode": 0,
                                       "out-data": base64.b64encode(b"ok\n").decode()}])
    replies.append(("guest-exec-status", lambda: json.dumps({"return": next(states)})))
    replies.append(('"guest-exec"', json.dumps({"return": {"pid": 42}})))
    assert engines.Libvirt().exec("shi-ubu24", ["echo", "ok"], timeout=30) == "ok\n"
    status_calls = [c for c in calls if "guest-exec-status" in " ".join(c)]
    assert len(status_calls) == 2 and json.loads(status_calls[0][-1])["arguments"] == {"pid": 42}
    assert calls[0][:5] == ["virsh", "-c", engines.LIBVIRT_URI, "qemu-agent-command", "shi-ubu24"]


def test_libvirt_exec_failure_carries_stderr(vsh, reg):
    _, replies = vsh
    replies.append(("guest-exec-status", json.dumps({"return": {
        "exited": True, "exitcode": 2, "err-data": base64.b64encode(b"no such file").decode()}})))
    replies.append(('"guest-exec"', json.dumps({"return": {"pid": 1}})))
    with pytest.raises(LabError) as e:
        engines.Libvirt().exec("shi-ubu24", ["cat", "/nope"], timeout=30)
    assert e.value.detail == "no such file"


def test_libvirt_exec_without_an_agent_says_what_it_needs(vsh, reg):
    _, replies = vsh
    replies.append(("guest-exec", LabError("virsh failed", "Guest agent is not responding")))
    with pytest.raises(LabError) as e:
        engines.Libvirt().exec("shi-ubu24", ["true"], timeout=30)
    assert "qemu-guest-agent" in e.value.detail


def test_libvirt_push_file_writes_in_chunks(vsh, reg, tmp_path):
    calls, replies = vsh
    replies.append(("guest-file-open", json.dumps({"return": 5})))
    replies.append(("guest-file-", json.dumps({"return": {}})))
    f = tmp_path / "big.ps1"
    f.write_bytes(b"A" * (engines.AGENT_CHUNK * 2 + 10))
    engines.Libvirt().push_file("shi-ubu24", str(f), "/tmp/big.ps1")
    cmds = [json.loads(c[-1]) for c in calls if "qemu-agent-command" in c]
    assert [c["execute"] for c in cmds] == ["guest-file-open"] + ["guest-file-write"] * 3 + ["guest-file-close"]
    assert cmds[0]["arguments"] == {"path": "/tmp/big.ps1", "mode": "wb"}
    assert all(len(json.dumps(c)) < 128 * 1024 for c in cmds)
    assert b"".join(base64.b64decode(c["arguments"]["buf-b64"]) for c in cmds[1:4]) == f.read_bytes()


def test_libvirt_snapshot_revert_and_delete(vsh, reg):
    calls, replies = vsh
    lv = engines.Libvirt()
    lv.snapshot("shi-ubu24", "clean")
    assert calls[-1][3:] == ["snapshot-create-as", "--domain", "shi-ubu24", "--name", "clean", "--atomic"]
    with pytest.raises(LabError) as e:
        lv.revert("shi-ubu24", "clean")  # run_ok is False: no such snapshot
    assert e.value.message == "No such snapshot"
    replies.append(("domblklist", " Type Device Target Source\n------\n file disk vda /p/a.qcow2\n"
                                  " file cdrom sda /p/Win11.iso\n"))
    calls.clear()
    lv.delete("shi-ubu24")
    verbs = [c[3] for c in calls]
    assert verbs.index("change-media") < verbs.index("undefine")  # the ISO is ejected before storage goes
    undef = next(c for c in calls if c[3] == "undefine")
    assert "--remove-all-storage" in undef and "--snapshots-metadata" in undef
    assert calls[-1][3:] == ["vol-delete", "--pool", "default", "shi-ubu24-seed.iso"]


def test_libvirt_stop_falls_back_to_destroy(vsh, reg):
    calls, replies = vsh
    replies.append(("domstate", "running\n"))
    engines.Libvirt().stop("shi-ubu24")
    assert calls[0][3] == "shutdown" and calls[-1][3] == "destroy"


# --- detection, templates, wiring -------------------------------------------------------------

def test_parse_hyperv_probe():
    assert engines and hosts.parse_hyperv_probe('{"module":true,"host":false,"version":"10.0.26100.1"}') == {
        "installed": True, "running": False, "version": "10.0.26100.1"}
    assert hosts.parse_hyperv_probe("") == {"installed": False, "running": False, "version": ""}


def test_hyperv_detected_on_windows_only(monkeypatch):
    monkeypatch.setattr(hosts.platform, "system", lambda: "Windows")
    monkeypatch.setattr(hosts.platform, "machine", lambda: "AMD64")
    monkeypatch.setattr(hosts, "which", lambda t: "C:/ps.exe" if t == "powershell" else None)
    monkeypatch.setattr(hosts, "_hyperv_probe", lambda: {"installed": True, "running": True, "version": "10.0"})
    caps = hosts.capabilities()
    e = {x["key"]: x for x in caps["engines"]}
    assert e["hyperv"]["supported"] and e["hyperv"]["running"] and "hyperv" in caps["ready"]
    assert not e["libvirt"]["supported"] and not e["tart"]["supported"]
    monkeypatch.setattr(hosts, "_hyperv_probe", lambda: {"installed": False, "running": False, "version": ""})
    e = {x["key"]: x for x in hosts.capabilities()["engines"]}["hyperv"]
    assert not e["installed"] and "Microsoft-Hyper-V-All" in e["install"]


def test_libvirt_detected_on_linux_when_virsh_answers(monkeypatch):
    monkeypatch.setattr(hosts.platform, "system", lambda: "Linux")
    monkeypatch.setattr(hosts.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(hosts, "which", lambda t: "/usr/bin/virsh" if t == "virsh" else None)
    monkeypatch.setattr(hosts, "run", lambda argv, timeout=15, check=False: "10.0.0\n")
    seen = []
    monkeypatch.setattr(hosts, "run_ok", lambda argv, timeout=20: seen.append(argv) or True)
    e = {x["key"]: x for x in hosts.capabilities()["engines"]}
    assert e["libvirt"]["running"] and e["libvirt"]["version"] == "10.0.0"
    assert any(a[:3] == ["virsh", "-c", engines.LIBVIRT_URI] for a in seen)
    assert not e["hyperv"]["supported"] and hosts.engine_supported("libvirt")


def _caps(os_name, ready):
    keys = ["docker", "tart", "utm", "hyperv", "libvirt"]
    sup = {"macos": {"docker", "tart", "utm"}, "linux": {"docker", "libvirt"}, "windows": {"docker", "hyperv"}}
    return {"os": os_name, "arch": "amd64", "ready": ready,
            "engines": [{"key": k, "name": k, "supported": k in sup[os_name], "installed": k in ready,
                         "running": k in ready} for k in keys]}


def test_templates_follow_the_hypervisor():
    linux = {t["id"] for t in templates.offered(_caps("linux", ["docker", "libvirt"]))}
    assert linux == {"ubuntu-container", "rocky-container", "ubuntu-kvm"}
    win = {t["id"]: t for t in templates.offered(_caps("windows", ["hyperv"]))}
    assert "ubuntu-hyperv" in win and win["ubuntu-hyperv"]["ready"] and not win["ubuntu-container"]["ready"]
    assert "ubuntu-kvm" not in win
    assert templates.BY_ID["ubuntu-kvm"]["image"]["amd64"].endswith("noble-server-cloudimg-amd64.img")


def test_create_passes_the_template_options(monkeypatch, reg):
    seen = {}
    monkeypatch.setattr(hosts.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(engines.Libvirt, "create", lambda self, name, image, **kw: seen.update(kw, image=image))
    machines.create("ubuntu-kvm", "shi-ubu24", owner=3)
    assert seen["osinfo"] == "ubuntu24.04" and seen["os_name"] == "linux"
    assert reg.get("libvirt", "shi-ubu24")["owner"] == 3


def test_create_from_image_only_where_the_engine_takes_one(monkeypatch, reg):
    monkeypatch.setattr(engines.HyperV, "create", lambda self, name, image, os_name="linux", **kw: None)
    r = machines.create_from_image("hyperv", "shi-win11", r"C:\vhd\ws2022.vhdx", "windows", owner=1,
                                   access={"user": "Administrator", "password": "pw", "junk": "x"})
    assert r == {"name": "shi-win11", "engine": "hyperv", "os": "windows"}
    acc = reg.get_access("hyperv", "shi-win11")
    assert acc == {"user": "Administrator", "password": "pw"}
    with pytest.raises(LabError):
        machines.create_from_image("docker", "box", "ubuntu:24.04", "linux")


def test_unclaimed_hyperv_and_libvirt_vms_are_an_admins_to_adopt(monkeypatch, reg):
    for cls in (engines.Docker, engines.Tart, engines.UTM):
        monkeypatch.setattr(cls, "list", lambda self: [])
    monkeypatch.setattr(engines.HyperV, "list", lambda self: [
        {"engine": "hyperv", "name": "hand-built", "kind": "vm", "image": "", "os": "", "state": "stopped", "detail": ""}])
    monkeypatch.setattr(engines.Libvirt, "list", lambda self: [])
    assert machines.listing(["hyperv"], user_id=1, is_admin=False) == []
    rows = machines.listing(["hyperv"], user_id=9, is_admin=True)
    assert rows and rows[0]["adopted"] is False and rows[0]["manageable"]
    machines.adopt("hyperv", "hand-built", "windows", owner=1, access={"user": "u", "password": "p"})
    rows = machines.listing(["hyperv"], user_id=1, is_admin=False)
    assert rows and rows[0]["os"] == "windows"
    machines.adopt("hyperv", "hand-built", "windows", owner=1)  # Set OS again, no login given
    assert reg.get_access("hyperv", "hand-built")["password"] == "p"  # the stored login is kept


def test_console_argv_for_the_new_engines():
    from shikari.lab.console import console_argv

    assert console_argv("libvirt", "shi-ubu24") == ["virsh", "-c", engines.LIBVIRT_URI, "console", "shi-ubu24", "--force"]
    with pytest.raises(ValueError):
        console_argv("libvirt", "shi-win11", windows=True)
    with pytest.raises(ValueError):
        console_argv("hyperv", "shi-win11")


def test_caldera_enrol_paths_for_the_new_engines(monkeypatch, reg):
    from shikari.lab import caldera

    ran = []
    monkeypatch.setattr(engines.HyperV, "exec", lambda self, n, argv, timeout, input_text=None: ran.append(("hv", argv)))
    monkeypatch.setattr(engines.Libvirt, "exec", lambda self, n, argv, timeout, input_text=None: ran.append(("kvm", argv)))
    caldera.enrol_agent("hyperv", "shi-win11", "windows", "winlab", "http://10.0.0.2:8888", say=lambda s: None)
    caldera.enrol_agent("libvirt", "shi-ubu24", "linux", "disposable", "http://10.0.0.2:8888", say=lambda s: None)
    assert "Register-ScheduledTask" in ran[0][1][-1] and "-paw shi-win11" in ran[0][1][-1]
    assert "systemd-run" in ran[1][1][-1]
    with pytest.raises(LabError):
        caldera.enrol_agent("libvirt", "x", "macos", "maclab", "http://h:8888", say=lambda s: None)


def test_dependency_matrix_lists_hyperv_and_kvm():
    from unittest.mock import patch

    from shikari import capabilities

    caps = _caps("linux", ["docker", "libvirt"])
    for e in caps["engines"]:
        e.update(version="", note="", install="", blurb="", runs="")
    caps["label"] = "Linux x86_64"
    with patch.object(capabilities.hosts, "capabilities", return_value=caps):
        rows = {r["name"]: r for r in capabilities.dependency_matrix()["rows"]}
    assert rows["KVM (libvirt)"]["status"] == "installed" and rows["Hyper-V"]["status"] == "na"
