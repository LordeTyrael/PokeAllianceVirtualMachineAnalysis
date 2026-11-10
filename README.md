# PokeAlliance — VM Detection Documentation

PokeAlliance is a PokeTibia (OTClient fork, DirectX build). Its client is `PokeAlliance_dx.exe` (x86-64, base `0x140000000`), 30,921,776 bytes, SHA-256 `48c41bd4422842e7a73890c4e65fc0714beb80c191ca274612a86ebe27b0ac2b`, packed with Themida / WinLicense 3.x. The client refuses to run inside a virtual machine: it reads the raw SMBIOS firmware table, finds the hypervisor's identity strings in it, and terminates before the login screen. The decision is local, made before any account or server contact, and produces no dialog and no network traffic.

The binary also carries an al-khaser-derived anti-VM / anti-debug library with a complete hypervisor-vendor table. Only the SMBIOS check is enforced; the rest is present and passes.

## 1. The Gate

| Property | Value |
|---|---|
| API | `kernel32!GetSystemFirmwareTable` |
| Provider signature | `0x52534D42` — `RSMB`, raw SMBIOS |
| Table size | 10,248 bytes |
| Buffer contents | SMBIOS structures as supplied by the hypervisor at boot |
| Decision | string search for hypervisor identity |
| Result on match | clean `ExitProcess`, no dialog, no dump |
| Time to exit | 1–2 s from launch |

Two-call sequence, standard size-probe idiom:

```
GetSystemFirmwareTable(sig=0x52534d42, id=0, buf=NULL, size=0)   -> 10248
GetSystemFirmwareTable(sig=0x52534d42, id=0, buf,      size)     -> 10248
```

The returned block is a plain RSMB header followed by the firmware structures:

```
+0x00   4    "RSMB"            provider signature
+0x04   4    table length      = 10,248
+0x08   1    major version
+0x09   1    minor version
+0x0A   ...  structures, each { u8 type, u8 length, u16 handle, fields… }
             followed by its string set: NUL-terminated strings, double NUL terminator
```

The hypervisor identity lives in the type 1 (System Information) and type 2 (Baseboard) string sets. There is no registry read and no file read anywhere on this path — the whole check is one API call and a buffer scan.

Note that `RSMB` returns the firmware's own structures, not the registry mirror. The commonly checked key `HKLM\HARDWARE\DESCRIPTION\System\BIOS` is never opened by this client.

## 2. What the Table Contains

On a default VMware guest, the 10,248-byte buffer carries:

| Field | Value | SMBIOS type |
|---|---|---|
| System Manufacturer | `VMware, Inc.` | Type 1 |
| System Product Name | `VMware Virtual Platform` | Type 1 |
| System Serial | `VMware-<uuid>` | Type 1 |
| Baseboard Manufacturer | `Intel Corporation` | Type 2 |
| Baseboard Product | `440BX Desktop Reference Platform` | Type 2 |

Any single one of the five is sufficient. The check needs no structural parsing and no heuristic: the default guest identity is self-evidently synthetic.

`440BX` is a 1998 Intel chipset. It is the hypervisor's hardcoded default baseboard, and it appears in pafish, in al-khaser and in most published detection code, because a default VMware guest has always reported it.

## 3. Position in Startup

The check does not run at entry. The client completes graphics and audio initialisation first, then queries the firmware table:

```
GPU ANGLE (… Direct3D11 vs_5_0 …)
[Atlas] Text atlas: 4096x4096
OpenAL Soft
== application started
```

| Phase | State |
|---|---|
| Window creation, D3D11 / ANGLE init | completed |
| Text atlas (4096×4096), OpenAL device | completed |
| SMBIOS query | here |
| Login screen | never reached |
| Network activity | none before exit |

A visible window therefore does not mean the gate has been passed. The window is up for the entire detection sequence, and the exit follows it by roughly a second.

The exit is clean: no exception, no message box, and no `exception2.dmp` written, even though the client ships a crash handler capable of producing one. That distinguishes a deliberate exit from a failure.

## 4. Why I/O Monitors Do Not See It

The SMBIOS table is written into guest physical memory by the hypervisor during virtual firmware POST, before Windows boots. By the time the client runs, it is an ordinary buffer in the process's own address space. Reading it touches no monitored object.

| Procmon sees | Procmon cannot see |
|---|---|
| File system I/O | `cpuid` (hypervisor bit, vendor leaf) |
| Registry I/O | `GetSystemFirmwareTable` / `EnumSystemFirmwareTables` |
| Network I/O | firmware tables already resident in memory |
| Process / thread activity | MAC addresses read through the NIC driver |

An empty trace is not evidence that nothing happened. It is evidence that the check sits below the layer Procmon instruments. Every filesystem and registry theory about this client fails for that reason alone.

## 5. The Anti-VM Library

The SMBIOS scan is one function inside a much larger suite. The unpacked image holds a hypervisor-vendor table at `0x0203f116`:

```
cloud hypervisor · nutanix · proxmox · prl hyperv · " lrpepyh vr" ·
VMwareVMware · VBoxVBoxVBox · wine_get_version · Microsoft Hv ·
KVMKVMKVM · XenVMMXenVMM · bochs · bhyve · qemu · innotek · xen ·
parallels · hvm domu · (pid
```

This is al-khaser compiled in. Two details settle the attribution: `" lrpepyh vr"` is al-khaser's deliberately scrambled Parallels signature, reproduced byte for byte, and `nutanix` / `proxmox` / `cloud hypervisor` are the newer additions to that same list.

Beside it sit `SeDebugPrivilege`, `NtQueryInformationProcess`, `SHA256` and `HashDigestLength`. A second cluster at `0x02040310` contains:

```
HARDWARE\DESCRIPTION\System\CentralProcessor\0
ProcessorNameString
GetProductInfo
PokeAlliance - Application Crashed
exception2.dmp
RIP: 0x%016llX
```

Component inventory:

| Component | Reads | Status |
|---|---|---|
| SMBIOS string scan | `RSMB` table | **enforced — the gate** |
| CPUID leaf `0x40000000` | hypervisor vendor leaf | present, passes |
| `ProcessorNameString` | CPU model from registry | present, not a VM tell |
| `NtQueryInformationProcess` 7/30/31 | debug port, debug object, debug flags | present |
| `SeDebugPrivilege` | token privileges | present |
| `VEN_15AD` enumeration | VMware PCI device keys | present, red herring (§6) |
| MAC OUI | NIC address | present, never triggers |
| crash handler | minidump on abnormal exit | always active |

### Why only SMBIOS fires

The CPUID half never trips because the guest's `.vmx` already sets:

```
hypervisor.cpuid.v0 = "FALSE"
```

That suppresses the CPUID hypervisor-present bit, so leaf `0x40000000` never returns `VMwareVMware`. The client runs the check and receives a clean answer.

The remainder pass on their own merits: the MAC uses a real Intel OUI rather than a VMware prefix, the disk reports as a retail `WDS120G2G0A`, and `ProcessorNameString` returns the genuine host CPU — hardware identification, not hypervisor identification.

One enforced check, one code path, one decision.

## 6. False Positives

### `VEN_15AD` registry reads

Procmon shows the client opening these keys three times each:

```
HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_15AD&DEV_0405&SUBSYS_040515AD&REV_00
HKLM\SYSTEM\CurrentControlSet\Enum\HDAUDIO\FUNC_01&VEN_15AD&DEV_1975&SUBSYS_…
```

`VEN_15AD` is VMware's PCI vendor ID, `DEV_0405` the SVGA II adapter, `DEV_1975` the HD Audio controller. The pattern reads as device enumeration, and a deny-read ACE was applied to all nine matching keys on that basis.

The deny was verified effective — a plain `OpenSubKey` as the same interactive user returned `ACCESS DENIED` — and it changed nothing. The client still obtained `SUCCESS` on the same keys and still exited on schedule. These reads belong to the renderer enumerating hardware, not to a decision.

### `HARDWARE\DESCRIPTION\System\BIOS`

The classic DMI check and the usual first suspect. The client never opens it. The only `HARDWARE\DESCRIPTION` key it touches is `CentralProcessor\0\ProcessorNameString`, which returns a CPU model string.

## 7. What the Check Does Not Do

| Not | Evidence |
|---|---|
| server-side | zero packets before exit |
| packer behaviour | Themida unpacks and runs the client normally; the exit is client code |
| a crash | no exception, no dialog, no dump written |
| time-based | timing follows the firmware query, not a clock or licence |
| guest-tools dependent | VMware Tools never installed; check fired regardless |

## 8. Observing the Check

Logging only — attach suspended, record signature and returned size:

```js
const fwt = Module.getExportByName('kernel32.dll', 'GetSystemFirmwareTable');
Interceptor.attach(fwt, {
  onEnter(args) { this.sig = args[0].toInt32(); this.size = args[3].toInt32(); },
  onLeave(ret) {
    if (this.sig === 0x52534D42)
      console.log(`RSMB probe size=${this.size} -> ${ret.toInt32()}`);
  }
});
```

Expected output on a running guest: one size probe returning `10248`, followed by one full read of `10248` bytes. The process exits immediately after the second call returns.

Two constraints on the observation itself. The hook must be installed before the first instruction, because the client reaches the check within a second or two of launch and a late attach races the exit. And `CreateFileW`-based tracing is irrelevant here — the check performs no file I/O to trace.

---
