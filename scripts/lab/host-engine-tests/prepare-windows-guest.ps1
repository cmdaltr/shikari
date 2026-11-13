# Make a base disk Shikari can create Hyper-V Windows guests from, either from the Windows Server
# 2022 evaluation VHD or straight from an install ISO (a Server 2022 ISO, or the DVD drive the Mac
# VM's second DVD that homelab lab build attaches it as): copy or build the disk, write an answer file into it offline (so first boot skips OOBE and sets the local
# Administrator password, the account PowerShell Direct uses), and mark the copy read-only, since
# every guest is a differencing disk over it. Run elevated on the Hyper-V host (Mount-VHD needs it).
#
#   powershell -ExecutionPolicy Bypass -File scripts\lab\host-engine-tests\prepare-windows-guest.ps1 `
#       -Vhd "$env:USERPROFILE\Downloads\<the downloaded eval>.vhd"
#   ... prepare-windows-guest.ps1 -Iso D:\                 (an ISO's drive, or a path to the .iso)
#
# From an ISO it applies the Desktop Experience Datacenter (else Standard) image to a new GPT VHDX
# with DISM, so there's nothing to download. It asks for the password unless -Password gives it. The answer file keeps it in plain text inside the base disk, so use one
# for this lab only. Prints the base disk's path, for run-hyperv.ps1 -Guest windows -Image.
# ASCII only: Windows PowerShell 5.1 misreads anything else.
#Requires -RunAsAdministrator
param(
    [string]$Vhd = '',
    [string]$Iso = '',
    [string]$Password = '',
    [string]$OutDir = 'C:\lab\images'
)
$ErrorActionPreference = 'Stop'

if (-not $Vhd -and -not $Iso) { throw "Give -Vhd <evaluation .vhd> or -Iso <install ISO, or its drive>" }
if ($Password) {
    $plain = $Password
} else {
    $pw = Read-Host -AsSecureString "Administrator password for the guests"
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw))
}
if ($plain.Length -lt 8) { throw "Use at least 8 characters, with upper case, lower case and a digit (Windows' default policy)" }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
if ($Vhd) {
    if (-not (Test-Path $Vhd)) { throw "No such file: $Vhd" }
    $work = Join-Path $OutDir 'ws2022-work.vhd'
    Write-Host "Copying the evaluation VHD (it stays untouched)..."
    Copy-Item -Path $Vhd -Destination $work -Force
    Set-ItemProperty -Path $work -Name IsReadOnly -Value $false
} else {
    # The ISO's install image: a mounted .iso, or a drive or folder that holds sources\install.wim
    $mounted = $null
    if ($Iso -like '*.iso') {
        $mounted = Mount-DiskImage -ImagePath (Resolve-Path $Iso).Path -PassThru
        $root = '{0}:\' -f ($mounted | Get-Volume).DriveLetter
    } else {
        $root = $Iso
    }
    $wim = Join-Path $root 'sources\install.wim'
    if (-not (Test-Path $wim)) { throw "No sources\install.wim under $root" }
    # Server Core images have no desktop to troubleshoot a guest from: Desktop Experience first
    $images = Get-WindowsImage -ImagePath $wim
    $full = @($images | Where-Object { $_.ImageName -notmatch 'Core' })
    $pick = $null
    foreach ($term in 'Datacenter', 'Standard', 'Pro', 'Enterprise') {
        $pick = $full | Where-Object { $_.ImageName -match $term } | Select-Object -First 1
        if ($pick) { break }
    }
    if (-not $pick) { $pick = $images | Select-Object -First 1 }
    Write-Host ("Applying image {0}: {1}" -f $pick.ImageIndex, $pick.ImageName)

    # A GPT disk with the EFI system, MSR and Windows partitions, so Generation 2 can boot it
    $work = Join-Path $OutDir 'ws2022-work.vhdx'
    if (Test-Path $work) { Remove-Item $work -Force }
    New-VHD -Path $work -SizeBytes 60GB -Dynamic | Out-Null
    $disk = Mount-VHD -Path $work -Passthru | Get-Disk
    try {
        Initialize-Disk -Number $disk.Number -PartitionStyle GPT
        $efi = New-Partition -DiskNumber $disk.Number -Size 260MB -GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' -AssignDriveLetter
        Format-Volume -Partition $efi -FileSystem FAT32 -NewFileSystemLabel 'System' -Confirm:$false | Out-Null
        New-Partition -DiskNumber $disk.Number -Size 16MB -GptType '{e3c9e316-0b5c-4db8-817d-f92df00215ae}' | Out-Null
        $os = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter
        Format-Volume -Partition $os -FileSystem NTFS -NewFileSystemLabel 'Windows' -Confirm:$false | Out-Null
        $efiRoot = '{0}:\' -f (Get-Partition -DiskNumber $disk.Number -PartitionNumber $efi.PartitionNumber).DriveLetter
        $osRoot = '{0}:\' -f (Get-Partition -DiskNumber $disk.Number -PartitionNumber $os.PartitionNumber).DriveLetter
        Write-Host "Applying the image (several minutes)..."
        Expand-WindowsImage -ImagePath $wim -Index $pick.ImageIndex -ApplyPath $osRoot | Out-Null
        & bcdboot (Join-Path $osRoot 'Windows') /s $efiRoot.TrimEnd('\') /f UEFI
        if ($LASTEXITCODE -ne 0) { throw "bcdboot failed ($LASTEXITCODE)" }
        # Leave the EFI partition without a letter, or it shows up in Explorer as a drive
        Remove-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $efi.PartitionNumber -AccessPath $efiRoot
    } finally {
        Dismount-VHD -Path $work
        if ($mounted) { Dismount-DiskImage -ImagePath $mounted.ImagePath | Out-Null }
    }
}

$esc = [Security.SecurityElement]::Escape($plain)
$unattend = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>*</ComputerName>
      <TimeZone>GMT Standard Time</TimeZone>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <InputLocale>en-GB</InputLocale>
      <SystemLocale>en-GB</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UserLocale>en-GB</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <SkipMachineOOBE>true</SkipMachineOOBE>
        <SkipUserOOBE>true</SkipUserOOBE>
        <ProtectYourPC>3</ProtectYourPC>
      </OOBE>
      <UserAccounts>
        <AdministratorPassword><Value>$esc</Value><PlainText>true</PlainText></AdministratorPassword>
      </UserAccounts>
    </component>
  </settings>
</unattend>
"@

Write-Host "Writing the answer file into the disk..."
$disk = Mount-VHD -Path $work -Passthru | Get-Disk
try {
    $style = $disk.PartitionStyle
    $win = Get-Partition -DiskNumber $disk.Number | Get-Volume |
        Where-Object { $_.DriveLetter -and (Test-Path ("{0}:\Windows\System32" -f $_.DriveLetter)) } |
        Select-Object -First 1
    if (-not $win) {
        # The Windows partition may have no letter on a mounted disk; give it one
        $part = Get-Partition -DiskNumber $disk.Number | Sort-Object Size -Descending | Select-Object -First 1
        $part | Add-PartitionAccessPath -AssignDriveLetter
        $win = $part | Get-Volume
    }
    $panther = "{0}:\Windows\Panther" -f $win.DriveLetter
    New-Item -ItemType Directory -Force -Path $panther | Out-Null
    Set-Content -Path (Join-Path $panther 'unattend.xml') -Value $unattend -Encoding UTF8
} finally {
    Dismount-VHD -Path $work
}

# A Generation 2 VM boots only VHDX from a GPT disk; Shikari makes a .vhd parent a Generation 1 VM.
# So an MBR disk stays .vhd, and a GPT one is converted to .vhdx.
if ($work -like '*.vhdx') {
    $base = Join-Path $OutDir 'ws2022-base.vhdx'
    Move-Item -Path $work -Destination $base -Force
} elseif ($style -eq 'GPT') {
    $base = Join-Path $OutDir 'ws2022-base.vhdx'
    Convert-VHD -Path $work -DestinationPath $base -VHDType Dynamic
    Remove-Item $work
} else {
    $base = Join-Path $OutDir 'ws2022-base.vhd'
    Move-Item -Path $work -Destination $base -Force
}
Set-ItemProperty -Path $base -Name IsReadOnly -Value $true
Write-Host ""
Write-Host "Base disk ($style): $base"
Write-Host "Next: scripts\lab\host-engine-tests\run-hyperv.ps1 -Guest windows -Image '$base'"
