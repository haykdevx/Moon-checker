/*
 * MoonMon — kernel-level inspection driver for the Moon anti-cheat checker.
 * ---------------------------------------------------------------------------
 * Creates \Device\MoonMon (symlink \??\MoonMon, SYSTEM + Administrators only)
 * and answers IOCTL_MOON_GET_REPORT with one line per kernel module, taken
 * from the kernel's own module table (ZwQuerySystemInformation /
 * SystemModuleInformation), which the user-mode KernelBridge reads and
 * KernelCheck matches against the vulnerable-driver / cheat signatures.
 *
 * Contract (ru.moon.checker.kernel.KernelReport parses it):
 *   IOCTL_MOON_GET_REPORT = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800,
 *                                    METHOD_BUFFERED, FILE_READ_ACCESS) = 0x226000
 *   Output: ASCII text, '\n'-separated lines:
 *     MOONMON 2 <n>                  n = modules in the kernel's table at query time
 *     DRIVER <full image path>       one per module; bytes outside 0x20..0x7e become '?'
 *     END <n>                        written ONLY when all n records fit
 *   A missing or mismatched END means the report is incomplete; the checker
 *   records that as a collection error (incomplete scan), never as "clean".
 *
 * WHAT THIS CAN AND CANNOT SEE
 *   It lists PsLoadedModuleList through SystemModuleInformation — the same table
 *   an elevated user-mode caller can query. Its value is a second, kernel-side
 *   read for cross-checking; it does NOT reveal manually mapped drivers, which
 *   are never registered in that table, nor hypervisor, firmware or DMA cheats.
 *   All classification (paths, signatures) happens in user mode.
 *
 * BUILD (Windows; EWDK = Enterprise WDK ISO, no Visual Studio install needed)
 *   1. Mount the EWDK ISO as a local drive (it cannot run from a network share),
 *      e.g. E:, and open a build shell:           E:\LaunchBuildEnv.cmd
 *   2. cd <repo>\kernel\windows
 *      msbuild MoonMon.vcxproj /p:Configuration=Release /p:Platform=x64
 *      -> build\Release\MoonMon.sys
 *   CI uses the WDK NuGet packages instead: nuget restore packages.config
 *   -PackagesDirectory packages, then the same msbuild line (.github/workflows/ci.yml).
 *
 * TEST-SIGN AND LOAD (lab machines only; elevated PowerShell on the test PC)
 *   1. One-off test certificate (kept in the machine store, never committed):
 *        $c = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=Moon Test Driver" `
 *               -CertStoreLocation Cert:\LocalMachine\My -HashAlgorithm SHA256
 *   2. Sign (signtool is on the EWDK PATH):
 *        signtool sign /fd SHA256 /sm /s My /sha1 $c.Thumbprint build\Release\MoonMon.sys
 *   3. Allow test-signed drivers, then reboot. Requires Secure Boot OFF in firmware,
 *      otherwise bcdedit reports the value is protected by Secure Boot policy.
 *      Until the reboot, sc start fails with error 577 (ERROR_INVALID_IMAGE_HASH):
 *        bcdedit /set testsigning on
 *   4. Install, start, verify, remove:
 *        sc.exe create MoonMon type= kernel start= demand binPath= C:\path\MoonMon.sys
 *        sc.exe start MoonMon
 *        java -jar moon-checker.jar --diagnose     (probe kernel.bridge must PASS)
 *        sc.exe stop MoonMon  &&  sc.exe delete MoonMon
 *        bcdedit /set testsigning off              (reboot)
 *   Production needs an EV certificate + Microsoft attestation signing instead
 *   (Partner Center); test-signed builds must never be shipped to players.
 *
 * VERIFIED 2026-09-14 (protocol 1, before the framing below was added): Windows 11
 * Pro 25H2 (build 26200) with EWDK 28000.2526: warning-free at /W4 /WX, MoonMon.inf
 * passes infverif, the driver loads, and a standard user opening \\.\MoonMon gets
 * ACCESS_DENIED. Protocol 2 is compiled by CI (driver-windows) but has not yet
 * been loaded on hardware — re-run the lab steps before relying on it.
 *
 * Without the driver, KernelCheck falls back to user-mode kernel-state inspection.
 */

#include <ntddk.h>
#include <wdmsec.h>
#include <ntstrsafe.h>

#define MOON_DEVICE_NAME  L"\\Device\\MoonMon"
#define MOON_SYMLINK_NAME L"\\??\\MoonMon"
#define MOON_POOL_TAG     'nooM'
#define IOCTL_MOON_GET_REPORT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)

#define SystemModuleInformation 11

/* {5B3E8A5C-7E4B-4C8F-9D51-3A6B2C1D0E9F}: class GUID for IoCreateDeviceSecure */
static const GUID MOON_DEVICE_CLASS =
    { 0x5b3e8a5c, 0x7e4b, 0x4c8f, { 0x9d, 0x51, 0x3a, 0x6b, 0x2c, 0x1d, 0x0e, 0x9f } };

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE  Section;
    PVOID   MappedBase;
    PVOID   ImageBase;
    ULONG   ImageSize;
    ULONG   Flags;
    USHORT  LoadOrderIndex;
    USHORT  InitOrderIndex;
    USHORT  LoadCount;
    USHORT  OffsetToFileName;
    UCHAR   FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

DRIVER_INITIALIZE DriverEntry;
static DRIVER_UNLOAD MoonUnload;
_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
static DRIVER_DISPATCH MoonDispatch;

static UNICODE_STRING gSymlink;

/* Appends one line; FALSE once the caller's buffer is full. */
static BOOLEAN Emit(_Inout_updates_bytes_(cap) PCHAR out, _In_ ULONG cap, _Inout_ PULONG pos, _In_ PCSTR line)
{
    size_t len;
    if (!NT_SUCCESS(RtlStringCbLengthA(line, 512, &len)) || *pos + len > cap) {
        return FALSE;
    }
    RtlCopyMemory(out + *pos, line, len);
    *pos += (ULONG)len;
    return TRUE;
}

/* Copies a module path into dst as printable ASCII so no byte can forge a line. */
static VOID SanitizePath(_Out_writes_(cap) PCHAR dst, _In_ ULONG cap, _In_reads_(256) const UCHAR *src)
{
    ULONG i = 0;
    for (; i + 1 < cap && i < 256 && src[i] != 0; i++) {
        dst[i] = (src[i] >= 0x20 && src[i] <= 0x7e) ? (CHAR)src[i] : '?';
    }
    dst[i] = 0;
}

/* Snapshot of the kernel module table; caller frees with ExFreePoolWithTag. */
static PRTL_PROCESS_MODULES QueryModules(void)
{
    ULONG need = 0;
    for (int attempt = 0; attempt < 4; attempt++) {
        ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &need);
        if (need == 0) {
            return NULL;
        }
        need += 8192; /* drivers may load between the two calls */
        PRTL_PROCESS_MODULES mods = (PRTL_PROCESS_MODULES)
            ExAllocatePoolZero(NonPagedPoolNx, need, MOON_POOL_TAG);
        if (mods == NULL) {
            return NULL;
        }
        NTSTATUS st = ZwQuerySystemInformation(SystemModuleInformation, mods, need, &need);
        if (NT_SUCCESS(st)) {
            return mods;
        }
        ExFreePoolWithTag(mods, MOON_POOL_TAG);
        if (st != STATUS_INFO_LENGTH_MISMATCH) {
            return NULL;
        }
    }
    return NULL;
}

static NTSTATUS BuildReport(_Out_writes_bytes_(outCap) PCHAR out, _In_ ULONG outCap, _Out_ PULONG written)
{
    ULONG pos = 0;
    ULONG emitted = 0;
    CHAR line[300];
    CHAR path[257];
    *written = 0;

    if (out == NULL || outCap < 64) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    PRTL_PROCESS_MODULES mods = QueryModules();
    if (mods == NULL) {
        return STATUS_UNSUCCESSFUL;
    }
    const ULONG total = mods->NumberOfModules;
    if (NT_SUCCESS(RtlStringCbPrintfA(line, sizeof(line), "MOONMON 2 %lu\n", total))) {
        (void)Emit(out, outCap, &pos, line);
    }
    for (ULONG i = 0; i < total; i++) {
        SanitizePath(path, sizeof(path), mods->Modules[i].FullPathName);
        if (!NT_SUCCESS(RtlStringCbPrintfA(line, sizeof(line), "DRIVER %s\n", path))
                || !Emit(out, outCap, &pos, line)) {
            break; /* buffer full: stop without END so the client knows */
        }
        emitted++;
    }
    if (emitted == total && NT_SUCCESS(RtlStringCbPrintfA(line, sizeof(line), "END %lu\n", total))) {
        (void)Emit(out, outCap, &pos, line);
    }
    ExFreePoolWithTag(mods, MOON_POOL_TAG);
    *written = pos;
    return STATUS_SUCCESS;
}

static NTSTATUS MoonDispatch(PDEVICE_OBJECT dev, PIRP irp)
{
    UNREFERENCED_PARAMETER(dev);
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG info = 0;

    switch (sp->MajorFunction) {
    case IRP_MJ_CREATE:
    case IRP_MJ_CLOSE:
        break;
    case IRP_MJ_DEVICE_CONTROL:
        if (sp->Parameters.DeviceIoControl.IoControlCode == IOCTL_MOON_GET_REPORT) {
            status = BuildReport((PCHAR)irp->AssociatedIrp.SystemBuffer,
                                 sp->Parameters.DeviceIoControl.OutputBufferLength, &info);
        } else {
            status = STATUS_INVALID_DEVICE_REQUEST;
        }
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = info;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

static VOID MoonUnload(PDRIVER_OBJECT drv)
{
    IoDeleteSymbolicLink(&gSymlink);
    if (drv->DeviceObject != NULL) {
        IoDeleteDevice(drv->DeviceObject);
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg)
{
    UNREFERENCED_PARAMETER(reg);
    UNICODE_STRING devName;
    PDEVICE_OBJECT devObj = NULL;

    RtlInitUnicodeString(&devName, MOON_DEVICE_NAME);
    RtlInitUnicodeString(&gSymlink, MOON_SYMLINK_NAME);

    /* the report reveals kernel layout: only SYSTEM and Administrators may open it */
    NTSTATUS st = IoCreateDeviceSecure(drv, 0, &devName, FILE_DEVICE_UNKNOWN,
                                       FILE_DEVICE_SECURE_OPEN, FALSE,
                                       &SDDL_DEVOBJ_SYS_ALL_ADM_ALL, &MOON_DEVICE_CLASS, &devObj);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    st = IoCreateSymbolicLink(&gSymlink, &devName);
    if (!NT_SUCCESS(st)) {
        IoDeleteDevice(devObj);
        return st;
    }
    drv->MajorFunction[IRP_MJ_CREATE] = MoonDispatch;
    drv->MajorFunction[IRP_MJ_CLOSE] = MoonDispatch;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MoonDispatch;
    drv->DriverUnload = MoonUnload;
    return STATUS_SUCCESS;
}
