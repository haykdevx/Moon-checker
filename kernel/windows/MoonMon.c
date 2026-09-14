/*
 * MoonMon — kernel-level inspection driver for the Moon anti-cheat checker.
 * ---------------------------------------------------------------------------
 * Creates \Device\MoonMon (symlink \??\MoonMon) and answers
 * IOCTL_MOON_GET_REPORT by enumerating the kernel's loaded-module list via
 * ZwQuerySystemInformation(SystemModuleInformation). It returns one line per
 * loaded driver ("DRIVER <path>"), which the user-mode KernelBridge reads and
 * matches against the vulnerable-driver / cheat signatures. Because the list is
 * gathered in kernel mode from the real module table, a user-mode rootkit that
 * unlinks a driver cannot hide it from this view (extend enumerateHidden() to
 * diff against user-mode results and emit "HIDDEN <name>").
 *
 * Contract (matches ru.moon.checker.kernel.KernelBridge):
 *   IOCTL_MOON_GET_REPORT = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800,
 *                                    METHOD_BUFFERED, FILE_READ_ACCESS) = 0x226000
 *   Output: UTF-8/ASCII text, lines separated by '\n'.
 *
 * BUILD (on Windows, cannot be built or signed from Linux):
 *   1. Install the WDK + EWDK (https://learn.microsoft.com/windows-hardware/drivers/).
 *   2. Create a "Kernel Mode Driver, Empty (KMDF/WDM)" project, add this file,
 *      or build with the classic WDK using the provided `sources` file.
 *   3. Test-sign for lab use:  bcdedit /set testsigning on   (reboot)
 *      makecert / signtool with a test cert, or an EV cert + Microsoft
 *      attestation signing for production.
 *   4. Install & start:
 *        sc create MoonMon type= kernel binPath= C:\path\MoonMon.sys
 *        sc start MoonMon
 *   The Java checker auto-detects the running driver; without it, KernelCheck
 *   falls back to user-mode kernel-state inspection.
 */

#include <ntddk.h>
#include <ntstrsafe.h>

#define MOON_DEVICE_NAME  L"\\Device\\MoonMon"
#define MOON_SYMLINK_NAME L"\\??\\MoonMon"
#define IOCTL_MOON_GET_REPORT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)

#define SystemModuleInformation 11

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
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);

static NTSTATUS BuildReport(PCHAR out, ULONG outCap, PULONG written) {
    ULONG need = 0;
    *written = 0;
    ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &need);
    if (need == 0) return STATUS_UNSUCCESSFUL;
    need += 4096;

    PRTL_PROCESS_MODULES mods = (PRTL_PROCESS_MODULES)
        ExAllocatePoolZero(NonPagedPoolNx, need, 'nooM');
    if (!mods) return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS st = ZwQuerySystemInformation(SystemModuleInformation, mods, need, &need);
    if (!NT_SUCCESS(st)) { ExFreePoolWithTag(mods, 'nooM'); return st; }

    ULONG pos = 0;
    for (ULONG i = 0; i < mods->NumberOfModules; i++) {
        PCHAR name = (PCHAR)mods->Modules[i].FullPathName;
        CHAR line[300];
        NTSTATUS r = RtlStringCbPrintfA(line, sizeof(line), "DRIVER %s\n", name);
        if (!NT_SUCCESS(r)) continue;
        ULONG len = (ULONG)strlen(line);
        if (pos + len >= outCap) break;
        RtlCopyMemory(out + pos, line, len);
        pos += len;
    }
    *written = pos;
    ExFreePoolWithTag(mods, 'nooM');
    return STATUS_SUCCESS;
}

static NTSTATUS MoonDispatch(PDEVICE_OBJECT dev, PIRP irp) {
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
            PCHAR buf = (PCHAR)irp->AssociatedIrp.SystemBuffer;
            ULONG cap = sp->Parameters.DeviceIoControl.OutputBufferLength;
            status = BuildReport(buf, cap, &info);
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

static UNICODE_STRING gSymlink;

static VOID MoonUnload(PDRIVER_OBJECT drv) {
    IoDeleteSymbolicLink(&gSymlink);
    if (drv->DeviceObject) IoDeleteDevice(drv->DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg) {
    UNREFERENCED_PARAMETER(reg);
    UNICODE_STRING devName;
    RtlInitUnicodeString(&devName, MOON_DEVICE_NAME);
    RtlInitUnicodeString(&gSymlink, MOON_SYMLINK_NAME);

    PDEVICE_OBJECT devObj;
    NTSTATUS st = IoCreateDevice(drv, 0, &devName, FILE_DEVICE_UNKNOWN,
                                 FILE_DEVICE_SECURE_OPEN, FALSE, &devObj);
    if (!NT_SUCCESS(st)) return st;

    st = IoCreateSymbolicLink(&gSymlink, &devName);
    if (!NT_SUCCESS(st)) { IoDeleteDevice(devObj); return st; }

    drv->MajorFunction[IRP_MJ_CREATE] = MoonDispatch;
    drv->MajorFunction[IRP_MJ_CLOSE] = MoonDispatch;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MoonDispatch;
    drv->DriverUnload = MoonUnload;
    return STATUS_SUCCESS;
}