# Hyper-V and KVM engine tests on real hosts

The unit tests (`tests/unit/test_lab_vm_engines.py`) check every command the `hyperv` and `libvirt` engines build and every output they parse, but nothing in them touches a hypervisor. This kit is the other half: two nested hosts on the Mac Mini, each running Shikari, each taking a small guest through the whole lifecycle.

```
Mac Mini (Intel, 32 GB) - VMware Fusion, NAT (vmnet8), nested VT-x on
 |- Windows 11 VM   Hyper-V    -> Ubuntu 24.04 cloud-image guest (SSH over the Default Switch)
 |                             -> Windows Server 2022 eval guest  (PowerShell Direct)
 '- Ubuntu 24.04 VM KVM/libvirt -> Ubuntu 24.04 cloud-image guest (QEMU guest agent)
```

Both host VMs stay on Fusion's NAT network and are reached by jumping through the Mini, `ssh -J macmini -i ~/.ssh/rowan_lab_ed25519 <user>@<vm-ip>`. Neither is bridged and neither runs Tailscale. Both are built unattended by `homelab lab build` (the homelab repo's `lab/`: Packer on the Mini), with these scripts as its provisioning profiles; building them by hand in Fusion is the fallback. Nothing here has been run yet.

| File | Runs on | Does |
|---|---|---|
| `fusion-nested.sh` | Mac Mini | sets `vhv.enable = "TRUE"`, CPUs and memory in a powered-off VM's `.vmx` |
| `prepare-kvm-host.sh` | Ubuntu VM | checks nesting, installs KVM, libvirt and virt-install, sets up the default network and pool |
| `run-kvm.sh` | Ubuntu VM | the lifecycle test on libvirt, `ubuntu-kvm` template |
| `prepare-hyperv-host.ps1` | Windows VM (elevated) | checks nesting, enables Hyper-V, installs Python, Git and qemu-img, turns on sshd |
| `prepare-windows-guest.ps1` | Windows VM (elevated) | turns the Windows Server 2022 eval VHD into a base disk with an answer file |
| `run-hyperv.ps1` | Windows VM (elevated) | the lifecycle test on Hyper-V, Linux or Windows guest |
| `lifecycle.py` | both | the test itself: one PASS/FAIL line per step |

## Building the two host VMs

From the MacBook, one at a time: the Mini has room for one nested host beside OrbStack and whatever else is running, and `homelab lab check` says so (`build` refuses when it doesn't fit):

```bash
homelab lab check --want windows --memory 12
homelab lab build windows --guest-iso Windows2022-Eval.iso --provision shikari-hyperv
homelab lab stop shikari-hyperv              # before the next one, unless check says both fit
homelab lab build ubuntu --provision shikari-kvm
```

Each runs on the Mini as a background job (an hour or more for Windows; `homelab lab job <id>` shows it, Ctrl-C only stops watching) and ends with the VM started and its `ssh -J macmini ...` command printed. `--provision` copies this folder into the VM (`C:\lab-provision`, `~/lab-provision`) from the Mini's `~/srv/shikari`, so commit the kit and pull it there first.

- **`shikari-hyperv`**: the Windows 11 Enterprise evaluation ISO from the VM folder, 4 vCPUs, 12 GB, 100 GB, nested VT-x, UEFI, NAT. Setup's TPM and Secure Boot checks are skipped (so no vTPM, no encrypted VM, no Fusion password to lose), local admin `lab`, OpenSSH with the `rowanholt-lab` key, then `prepare-hyperv-host.ps1`, a restart, and the `Get-VMHost` and Default Switch checks. With `--guest-iso` (the Server 2022 ISO, attached as a second DVD) `prepare-windows-guest.ps1` then builds the Windows guests' base disk from it, `C:\lab\images\ws2022-base.vhdx`, with the lab password as the guests' Administrator password.
- **`shikari-kvm`**: the newest Ubuntu 24.04 live server ISO (downloaded into the VM folder and checked against its SHA256SUMS if absent), 4 vCPUs, 8 GB, 60 GB, autoinstall, user `lab` with the key, `prepare-kvm-host.sh`, then key-only SSH.

The lab password goes in the Mini's login keychain (`security find-generic-password -s homelab-lab -a <name> -w`, on the Mini), or, when the build was started over SSH and the keychain is locked, an owner-only file under `~/Library/Application Support/homelab-lab/passwords/` on the Mini. Packer and its VMware plugin must be on the Mini; `build` prints the commands if they aren't. Then carry on from copying the working tree in, in section 1 or 2 below: nesting is on, the prepare script has run, and the restart has applied the libvirt group and Hyper-V.

## What you do by hand

Building the VMs by hand instead (the fallback, if the Packer build fails), these can't be scripted from here, or shouldn't be:

1. **Create both VMs in Fusion** (the GUI): the existing "Windows 11" VM has an encrypted disk and an unknown password, so both are new.
2. **Windows licensing.** Use the [Windows 11 Enterprise evaluation ISO](https://www.microsoft.com/en-us/evalcenter/download-windows-11-enterprise) (90 days, Hyper-V included, needs the Evaluation Center's registration form), or a Windows 11 Pro ISO and key. Home has no Hyper-V.
3. **The vTPM.** Windows 11 setup wants TPM 2.0, and Fusion only adds a vTPM to an encrypted VM. Choose Fusion's *only the files needed to support a TPM are encrypted* option and **save that password in your password manager before you click OK**, which is what went missing with the old VM. The alternative is to skip the TPM check during setup (Shift+F10, `regedit`, `HKLM\SYSTEM\Setup\LabConfig`, DWORDs `BypassTPMCheck` and `BypassSecureBootCheck` = 1).
4. **Accounts and passwords**: the Windows VM's local admin account, the Ubuntu VM's user, and the Administrator password for the Windows Server guests (asked by `prepare-windows-guest.ps1`). Keep them in your password manager.
5. **Download the Windows Server 2022 evaluation VHD** from the [Evaluation Center](https://www.microsoft.com/en-us/evalcenter/download-windows-server-2022) ("VHD download", English, 64-bit; roughly 10 GB; registration form again, so no script can fetch it). Only needed for the Windows-guest test. Microsoft's Windows 11 developer VMs would need no answer file, but their downloads have been unavailable since late 2024.
6. **Copy the working tree in.** The engines are uncommitted, so `git clone` won't bring them: use the `rsync`/`tar` commands below.
7. **BIOS-level settings**: none on the Mini beyond what macOS already allows; nested VT-x is Fusion's setting, set by `fusion-nested.sh`.

The Ubuntu cloud image (about 600 MB, `https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img`) is downloaded by Shikari itself, from the template, into `data/lab/images/`.

## 1. The Ubuntu VM (KVM host)

Built with `homelab lab build ubuntu --provision shikari-kvm` (above): `homelab lab ip shikari-kvm` gives its address, the user is `lab`, and the next step is copying the working tree in. By hand instead, in Fusion: New > Install from disc or image, Ubuntu Server 24.04 LTS amd64 ISO, 4 vCPUs, 8 GB, 60 GB disk, network *Share with my Mac* (NAT). Install with OpenSSH server ticked and your `rowanholt-lab` public key imported. Shut it down, then on the Mini (absolute path; `vmrun list` shows it if unsure):

```bash
ssh macmini 'bash -s' -- "$HOME/Virtual Machines.localized/shikari-kvm.vmwarevm/shikari-kvm.vmx" 4 8192 \
  < scripts/lab/host-engine-tests/fusion-nested.sh
```

Expect it to print `vhv.enable = "TRUE"`, `numvcpus = "4"`, `memsize = "8192"`. Start the VM (`vmrun -T fusion start <vmx> nogui`), find its address (`vmrun -T fusion getGuestIPAddress <vmx> -wait` on the Mini) and copy the working tree in from the MacBook:

```bash
cd ~/Library/CloudStorage/OneDrive-Personal/Projects/GitHub/shikari
rsync -az --exclude .venv --exclude data --exclude node_modules --exclude logs \
  -e "ssh -J macmini -i ~/.ssh/rowan_lab_ed25519" ./ ben@<vm-ip>:~/shikari/
```

In the VM:

```bash
cd ~/shikari
bash scripts/lab/host-engine-tests/prepare-kvm-host.sh
```

Expected: `vCPUs with vmx/svm: 4` (any number above 0), then `INFO: /dev/kvm exists` and `KVM acceleration can be used` from `kvm-ok`. If the count is 0 or `kvm-ok` says KVM can't be used, nesting didn't take: stop here and recheck the `.vmx`. Then sign out and in, and:

```bash
virsh -c qemu:///system list --all          # an empty table, no "permission denied"
python3 -m venv .venv && .venv/bin/pip install -e .
bash scripts/lab/host-engine-tests/run-kvm.sh
```

## 2. The Windows 11 VM (Hyper-V host)

Built with `homelab lab build windows --guest-iso Windows2022-Eval.iso --provision shikari-hyperv` (above): Hyper-V is on, the user is `lab`, the base disk is `C:\lab\images\ws2022-base.vhdx`, and the next step is copying the working tree in (after the post-reboot checks, if you want to see them yourself). By hand instead, in Fusion: New > Install from disc or image, the Windows 11 x64 ISO, 4 vCPUs, 12 GB, 100 GB disk, NAT, a vTPM as above. Install Windows with a local account. Shut it down and run `fusion-nested.sh` for its `.vmx` with `4 12288`. Expect the same three lines. Start it, then in an elevated PowerShell inside it, first check what nesting gives Windows:

```powershell
systeminfo | Select-String 'Hyper-V|VM Monitor|Virtuali|Second Level|Data Execution'
```

Expected, before Hyper-V is on: `VM Monitor Mode Extensions: Yes`, `Virtualization Enabled In Firmware: Yes`, `Second Level Address Translation: Yes`, `Data Execution Prevention Available: Yes`. Any `No` means nesting didn't take. Then (paste your `rowanholt-lab` public key):

```powershell
Set-ExecutionPolicy -Scope Process Bypass
# copy the kit in first, or the whole tree (below) and run it from there
.\scripts\lab\host-engine-tests\prepare-hyperv-host.ps1 -PublicKey "ssh-ed25519 AAAA... rowanholt-lab"
Restart-Computer
```

After the reboot, `systeminfo` instead says `A hypervisor has been detected. Features required for Hyper-V will not be displayed.`, which is the success case. Check:

```powershell
Get-VMHost | Select-Object Name, LogicalProcessorCount   # no error
Get-VMSwitch -Name 'Default Switch'                     # exists
qemu-img --version                                       # found (new shell after the PATH change)
```

Copy the working tree in from the MacBook (Windows has `tar` but no `rsync`), into `C:\shikari`:

```bash
cd ~/Library/CloudStorage/OneDrive-Personal/Projects/GitHub/shikari
tar czf - --exclude .venv --exclude data --exclude node_modules --exclude logs . |
  ssh -J macmini -i ~/.ssh/rowan_lab_ed25519 <user>@<vm-ip> "mkdir C:\shikari 2>nul & tar xzf - -C C:\shikari"
```

Then, elevated, in `C:\shikari`:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\pip install -e .
.\scripts\lab\host-engine-tests\run-hyperv.ps1 -Guest linux
```

For the Windows guest, prepare the base disk once, then run the test with the path it prints:

```powershell
.\scripts\lab\host-engine-tests\prepare-windows-guest.ps1 -Vhd "$env:USERPROFILE\Downloads\<eval>.vhd"
.\scripts\lab\host-engine-tests\run-hyperv.ps1 -Guest windows -Image C:\lab\images\ws2022-base.vhd
```

Run it elevated: Hyper-V Administrators membership is enough for Shikari's own commands, but `prepare-windows-guest.ps1` needs `Mount-VHD`, and running everything elevated keeps the two the same.

## The test sequence and what to expect

`lifecycle.py` prints one line per step, `PASS`, `FAIL` (with the reason) or `SKIP` (a step it depends on failed), and exits with the number of failures. A machine it created is always deleted at the end, whatever failed, unless you pass `--keep`.

| Step | libvirt, Ubuntu | Hyper-V, Ubuntu | Hyper-V, Windows Server |
|---|---|---|---|
| detect engine | `KVM (libvirt) 10.0.0 ready` | `Hyper-V 10.0.x ready` | same |
| create | first run downloads the image, uploads it to the pool as `shikari-base-…`, then overlay + seed + `virt-install`: about 2 min, seconds after | first run downloads and converts to VHDX (`data\lab\images`), then a differencing disk and the seed ISO | a differencing disk over the base, Generation 1 for a `.vhd` |
| start | `running` | `running` | `running` |
| guest ready | cloud-init installs `qemu-guest-agent`, 2 to 5 min; ends `status: done` | SSH as `shikari` answers, 1 to 3 min; `status: done` | PowerShell Direct answers after specialize and one reboot, 3 to 8 min |
| exec a command | `Linux 6.8.0-… x86_64 \| Ubuntu 24.04… LTS` | same | `Microsoft Windows [Version 10.0.20348…]` |
| push a file, pull a folder | intact | intact | intact |
| snapshot (clean) | `snapshot kit-clean` (internal, memory included) | Standard checkpoint | Standard checkpoint |
| change something | marker written | marker written | marker written |
| revert | back to running in seconds | Saved, then resumed | Saved, then resumed |
| change is gone | `marker gone` | `marker gone` | `marker gone` |
| logs | `Address: 192.168.122.x` | `… Its address is 172.x.x.x.` | same |
| stop | `shut off` | `off` | `off` |
| delete | `deleted, and no longer listed`; `virsh vol-list default` keeps only the `shikari-base-…` volume | gone, and `data\lab\hyperv\<name>` removed | same |

A run ends `13 passed, 0 failed, 0 skipped`.

## If a step fails

- **detect engine, libvirt not answering**: the group change hasn't applied (`id -nG` must list `libvirt`).
- **detect engine, Hyper-V not answering**: not elevated, or not signed out and in since joining Hyper-V Administrators.
- **create on Hyper-V, Linux, `qemu-img isn't installed`**: open a new shell so the PATH change applies.
- **guest ready times out, libvirt**: the guest had no route out to install the agent. `virsh console shi-kit-kvm-lin` (Ctrl+] leaves) shows cloud-init's progress; the console logs straight in.
- **guest ready times out, Hyper-V Ubuntu**: the riskiest step in the kit. Either the guest never booted (open it in Hyper-V Manager: a Generation 2 VM stuck at the firmware screen means Secure Boot refused it, a hang at the initramfs means the image lacks the Hyper-V storage driver) or it booted but Shikari can't find its address: `Get-VMNetworkAdapter -VMName shi-kit-hv-lin | Select IPAddresses` and `Get-NetNeighbor` should show it. If only the address is the problem, `--keep`, find the address in Hyper-V Manager, set it with Set OS in the Lab (Address field), and rerun the later steps by hand.
- **guest ready times out, Windows**: the answer file wasn't read (the VM sits at OOBE in Hyper-V Manager's Connect window) or the password differs. Rerun `prepare-windows-guest.ps1`.
- **snapshot fails on libvirt with "internal snapshots of a VM with pflash"**: the VM is UEFI. Shikari's own are BIOS, so this only happens to a hand-built VM.
- **revert passes, change is gone fails**: the snapshot isn't being applied; report the engine's own output (`virsh snapshot-list`, `Get-VMCheckpoint`).

To clean up after `--keep` or a crash: `virsh -c qemu:///system undefine <name> --remove-all-storage --snapshots-metadata` on Ubuntu; `Remove-VM <name> -Force` and delete `C:\shikari\data\lab\hyperv\<name>` on Windows. The host VMs themselves are disposable: delete them in Fusion when done.
