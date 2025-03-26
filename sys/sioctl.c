/*++

Copyright (c) 1990-98  Microsoft Corporation All Rights Reserved

Module Name:

    sioctl.c

Abstract:

    Purpose of this driver is to demonstrate how the four different types
    of IOCTLs can be used, and how the I/O manager handles the user I/O
    buffers in each case. This sample also helps to understand the usage of
    some of the memory manager functions.

Environment:

    Kernel mode only.

--*/


//
// Include files.
//

#include <ntddk.h>          // various NT definitions
#include <string.h>

#include "sioctl.h"

typedef unsigned int DWORD;


#define NT_DEVICE_NAME      L"\\Device\\SIOCTL"
#define DOS_DEVICE_NAME     L"\\DosDevices\\IoctlTest"


#if DBG
#define SIOCTL_KDPRINT(_x_) \
                DbgPrint("SIOCTL.SYS: ");\
                DbgPrint _x_;

#else
#define SIOCTL_KDPRINT(_x_)
#endif



// Windows 10 19041 x64
#define PID_OFFSET 0x440
#define PS_ACTIVE_OFFSET 0x448
QWORD FindProcessEPROC(
    _In_ int nPID
)
{
    QWORD eproc = 0x00000000;
    int currentPID = 0;
    int startPID = 0;
    int iCount = 0;
    PLIST_ENTRY plistActiveProcs;

    eproc = (QWORD)PsGetCurrentProcess();
    startPID = (INT) * ((QWORD*)(eproc + (QWORD)PID_OFFSET));
    currentPID = startPID;
    for (;;)
    {
        if (nPID == currentPID)
        {
            return eproc;// found
        }
        else if ((iCount >= 1) && (startPID == currentPID))
        {
            break;
        }
        else {
            plistActiveProcs = (LIST_ENTRY*)(eproc + PS_ACTIVE_OFFSET);
            eproc = (QWORD)plistActiveProcs->Flink - PS_ACTIVE_OFFSET;
            currentPID = (INT) * ((QWORD*)(eproc + (QWORD)PID_OFFSET));
            iCount++;
        }
    }

    return 0;
}

#define DTB_OFFSET 0x028
QWORD GetProcessDirBase(QWORD eproc)
{
    QWORD   directoryTableBase;

    if (eproc == 0x0) {
        return 0x0;
    }

    directoryTableBase = *(QWORD*)(eproc + DTB_OFFSET);
    directoryTableBase = directoryTableBase & 0xfffffffff000;

    return directoryTableBase;
}




#define PFN_MASK(pe)        ((QWORD)((pe) & 0x0000FFFFFFFFF000UL))
#define PFN_SETZERO(pe)    ((QWORD)((pe) & 0xFFFF000000000FFFUL))



NTSTATUS MmReadPhysical(PVOID targetAddress, ULONG64 sourceAddress, size_t size, size_t* bytesRead)
{
    PHYSICAL_ADDRESS address = { 0 };
    MM_COPY_ADDRESS copyInfo = { 0 };
    address.QuadPart = (LONGLONG)sourceAddress;
    copyInfo.PhysicalAddress = address;
    return MmCopyMemory(targetAddress, copyInfo, size, MM_COPY_MEMORY_PHYSICAL, bytesRead);
}



QWORD GetPfn(ULONG64 cr3, QWORD virtual_addr)
{
    size_t dummy;
    QWORD* ppml4 = NULL;
    QWORD   pdpt = 0;
    QWORD* ppdpt = NULL;
    QWORD   pd = 0;
    QWORD* ppd = NULL;
    QWORD   pt = 0;
    QWORD* ppt = NULL;
    QWORD   pfn = 0;

    virt_addr_t a;

    a.value = virtual_addr;

    size_t copySize = PAGE_SIZE;
    //    Int3();
    PVOID buffer = ExAllocatePool(NonPagedPool, copySize);

    //copy pml4
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "cr3 : %p\n", cr3);
    MmReadPhysical(buffer, cr3, copySize, &dummy);
    ppml4 = (PQWORD)buffer;
    pdpt = ppml4[a.a.pml4_index]; 
    pdpt = PFN_MASK(pdpt);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppml4[%d]:%p\r\n", a.a.pml4_index, pdpt);
    MmReadPhysical(buffer, pdpt, copySize, &dummy);
    ppdpt = (PQWORD)buffer;
    pd = ppdpt[a.a.pdpt_index];
    pd = PFN_MASK(pd);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppdpt[%d]:%p\r\n", a.a.pdpt_index, pd);
    MmReadPhysical(buffer, pd, copySize, &dummy);
    ppd = (PQWORD)buffer;
    pt = ppd[a.a.pd_index];
    pt = PFN_MASK(pt);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppd[%d]:%p\r\n", a.a.pd_index, pt);
    MmReadPhysical(buffer, pt, copySize, &dummy);
    ppt = (PQWORD)buffer;
    pfn = ppt[a.a.pt_index];
    pfn = PFN_MASK(pfn);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppt[%d].pfn:%p\r\n", a.a.pt_index, pfn);
    ExFreePool(buffer);

    return pfn;
}

static HANDLE hPhysicalhandle = NULL;

NTSTATUS GetPhysicalHandle()
{
    NTSTATUS status;
    UNICODE_STRING PhysicalMemoryString;
    OBJECT_ATTRIBUTES attributes;

    WCHAR PhysicalMemoryName[] = L"\\Device\\PhysicalMemory";
    RtlInitUnicodeString(&PhysicalMemoryString, PhysicalMemoryName);
    InitializeObjectAttributes(&attributes, &PhysicalMemoryString, 0, NULL, NULL);
    status = ZwOpenSection(&hPhysicalhandle, SECTION_MAP_READ | SECTION_MAP_WRITE, &attributes);

    return status;
}
NTSTATUS WritePhysicalMemory2(DWORD64 PhysicalAddress, DWORD32 WriteData)
{
    NTSTATUS status;
    PVOID BaseAddress = NULL;
    DWORD32 offset;
    LARGE_INTEGER SectionOffset;
    SIZE_T size = 0x2000;

    status = GetPhysicalHandle();
    if (status < 0)
    {
        status = FALSE;
        goto Leave;
    }

    offset = PhysicalAddress & 0xFFF;

    SectionOffset.QuadPart = (ULONGLONG)(PhysicalAddress);

    status = ZwMapViewOfSection(
        hPhysicalhandle,
        NtCurrentProcess(),
        (PVOID*)&BaseAddress,
        0,
        size,
        &SectionOffset,
        &size,
        ViewShare,
        MEM_TOP_DOWN,
        PAGE_READWRITE);

    if (status < 0)
    {
        status = FALSE;
        goto Leave;
    }

    memmove_s((PVOID)((DWORD64)BaseAddress + offset), sizeof(DWORD32), &WriteData, sizeof(DWORD32));

    status = ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);

    if (status < 0)
    {
        status = FALSE;
    }

Leave:
    if (hPhysicalhandle != NULL)
    {
        ZwClose(hPhysicalhandle);
    }

    return status;
}

QWORD SetPfn(QWORD cr3, QWORD virtual_addr, QWORD new_pfn)
{
    size_t dummy;
    QWORD* ppml4 = NULL;
    QWORD   pdpt = 0;
    QWORD* ppdpt = NULL;
    QWORD   pd = 0;
    QWORD* ppd = NULL;
    QWORD   pt = 0;
    QWORD* ppt = NULL;
    QWORD  old_pfn = 0;
    QWORD  tmp_pfn = 0;
    QWORD  pt_entry = 0;

    virt_addr_t a;
    //MM_COPY_ADDRESS copyInfo = { 0 };

    a.value = virtual_addr;

    size_t copySize = PAGE_SIZE;
    //Int3();
    PVOID buffer = ExAllocatePool(NonPagedPool, copySize);

    //copy pml4
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "cr3 : %p\n", cr3);
    MmReadPhysical(buffer, cr3, copySize, &dummy);
    ppml4 = (PQWORD)buffer;
    pdpt = ppml4[a.a.pml4_index];
    pdpt = PFN_MASK(pdpt);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppml4[%d]:%p\r\n", a.a.pml4_index, pdpt);
    MmReadPhysical(buffer, pdpt, copySize, &dummy);
    ppdpt = (PQWORD)buffer;
    pd = ppdpt[a.a.pdpt_index];
    pd = PFN_MASK(pd);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppdpt[%d]:%p\r\n", a.a.pdpt_index, pd);
    MmReadPhysical(buffer, pd, copySize, &dummy);
    ppd = (PQWORD)buffer;
    pt = ppd[a.a.pd_index];
    pt = PFN_MASK(pt);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppd[%d]:%p\r\n", a.a.pd_index, pt);

    MmReadPhysical(buffer, pt, copySize, &dummy);
    // buffer라는 가상 주소와 pt 즉 page tabe 시작주소 = 물리 주소를 인자로 넘기고
    // buffer라는 가상 주소에 물리 주소로 부터 읽은 데이터를 저장한다.
    ppt = (PQWORD)buffer;
    // buffer 가리키는 값을 8바이트 단위로 읽을 수 있는 PQWORD 포인터로 형변환
    // // buffer는 64비트(8바이트) 크기의 QWORD 자료형들이 저장된 공간의 시작 주소가 됨
    // buffer 가리키는 값이 어떠한 QWORD (8바이트) 단위의 데이터 즉 PTE 하나를 사용하기위해 형변환 한것이다.
    //ppt는 이제 어떠한 8바이트 크기의 데이터를 이루는 자료형이 있는 배열의 시작 주소가 됨
    tmp_pfn = ppt[a.a.pt_index]; 
    //ppt의 참조는 ppt 배열에서 데이터를 가져오는 것 즉 8바이트 배열 ppt에서
    // pt_index즉 pt 테이블에서 사용할 N번째 인덱스값을 통해 8바이트 배열에서 값을 하나 가져옴
    //그 데이터가 pfn을 저장하고 있는 N번째 PTE임
    old_pfn = PFN_MASK(tmp_pfn);
    //비트 마스킹을 통해 pfn을 정확히 추출하고 옵션비트는 제외해서 old_pfn에 넣어줌
    tmp_pfn = PFN_SETZERO(tmp_pfn);
    //비트 셋제로를 통해 tmp_pfn의 pfn부분만 정확히 지움 나머지 옵션 비트는 유지
    new_pfn = new_pfn << 12;
    //유저 모드에서 pfn이 12비트 밀려서 커널에 전달되었으므로 다시 12비트를 왼쪽 쉬프트해서 pfn 위치를 유지
    //또한 이 pfn은 옵션 바이트는 0으로 되어있는 순정 pfn임
    tmp_pfn = tmp_pfn | new_pfn;
    //옵션 비트를 유지한 tmp_pfn에 new_pfn을 이식함 
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppt[%d].old_pfn:%p tmp_pfn\r\n", a.a.pt_index, old_pfn, tmp_pfn);

    pt_entry = pt + 8 * a.a.pt_index;
    //pt는 물리 주소이고 이 pt의 8바이트*인덱스를 더한 값이 pt_entry의 물리 주소이다. 
    PHYSICAL_ADDRESS val2 = { 0, };
    val2.QuadPart = tmp_pfn;

    WritePhysicalMemory2(pt_entry, val2.LowPart); // 인자: 물리 주소(pt_entry)와 그 물리 주소에 쓸 데이터(val2.LowPart)
    WritePhysicalMemory2(pt_entry + 4, val2.HighPart); // 인자: 물리 주소(pt_entry)와 그 물리 주소에 쓸 데이터(val2.LowPart)

    MmReadPhysical(buffer, pt, copySize, &dummy);
    ppt = (PQWORD)buffer;
    tmp_pfn = ppt[a.a.pt_index];
    tmp_pfn = PFN_MASK(tmp_pfn);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppt[%d].new_pfn:%p\r\n", a.a.pt_index, tmp_pfn);

    ExFreePool(buffer);

    return old_pfn;
}



DWORD g_dwPid = 0;
QWORD g_qwVa = 0;
QWORD g_dwPfn = 0;


//
// Device driver routine declarations.
//

DRIVER_INITIALIZE DriverEntry;

_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH SioctlCreateClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH SioctlDeviceControl;

DRIVER_UNLOAD SioctlUnloadDriver;

VOID
PrintIrpInfo(
    PIRP Irp
);
VOID
PrintChars(
    _In_reads_(CountChars) PCHAR BufferAddress,
    _In_ size_t CountChars
);

#ifdef ALLOC_PRAGMA
#pragma alloc_text( INIT, DriverEntry )
#pragma alloc_text( PAGE, SioctlCreateClose)
#pragma alloc_text( PAGE, SioctlDeviceControl)
#pragma alloc_text( PAGE, SioctlUnloadDriver)
#pragma alloc_text( PAGE, PrintIrpInfo)
#pragma alloc_text( PAGE, PrintChars)
#endif // ALLOC_PRAGMA


NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT   DriverObject,
    _In_ PUNICODE_STRING      RegistryPath
)
/*++

Routine Description:
    This routine is called by the Operating System to initialize the driver.

    It creates the device object, fills in the dispatch entry points and
    completes the initialization.

Arguments:
    DriverObject - a pointer to the object that represents this device
    driver.

    RegistryPath - a pointer to our Services key in the registry.

Return Value:
    STATUS_SUCCESS if initialized; an error otherwise.

--*/

{
    NTSTATUS        ntStatus;
    UNICODE_STRING  ntUnicodeString;    // NT Device Name "\Device\SIOCTL"
    UNICODE_STRING  ntWin32NameString;    // Win32 Name "\DosDevices\IoctlTest"
    PDEVICE_OBJECT  deviceObject = NULL;    // ptr to device object

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&ntUnicodeString, NT_DEVICE_NAME);

    ntStatus = IoCreateDevice(
        DriverObject,                   // Our Driver Object
        0,                              // We don't use a device extension
        &ntUnicodeString,               // Device name "\Device\SIOCTL"
        FILE_DEVICE_UNKNOWN,            // Device type
        FILE_DEVICE_SECURE_OPEN,     // Device characteristics
        FALSE,                          // Not an exclusive device
        &deviceObject);                // Returned ptr to Device Object

    if (!NT_SUCCESS(ntStatus))
    {
        SIOCTL_KDPRINT(("Couldn't create the device object\n"));
        return ntStatus;
    }

    //
    // Initialize the driver object with this driver's entry points.
    //

    DriverObject->MajorFunction[IRP_MJ_CREATE] = SioctlCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = SioctlCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SioctlDeviceControl;
    DriverObject->DriverUnload = SioctlUnloadDriver;

    //
    // Initialize a Unicode String containing the Win32 name
    // for our device.
    //

    RtlInitUnicodeString(&ntWin32NameString, DOS_DEVICE_NAME);

    //
    // Create a symbolic link between our device name  and the Win32 name
    //

    ntStatus = IoCreateSymbolicLink(
        &ntWin32NameString, &ntUnicodeString);

    if (!NT_SUCCESS(ntStatus))
    {
        //
        // Delete everything that this routine has allocated.
        //
        SIOCTL_KDPRINT(("Couldn't create symbolic link\n"));
        IoDeleteDevice(deviceObject);
    }


    return ntStatus;
}


NTSTATUS
SioctlCreateClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
/*++

Routine Description:

    This routine is called by the I/O system when the SIOCTL is opened or
    closed.

    No action is performed other than completing the request successfully.

Arguments:

    DeviceObject - a pointer to the object that represents the device
    that I/O is to be done on.

    Irp - a pointer to the I/O Request Packet for this request.

Return Value:

    NT status code

--*/

{
    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

VOID
SioctlUnloadDriver(
    _In_ PDRIVER_OBJECT DriverObject
)
/*++

Routine Description:

    This routine is called by the I/O system to unload the driver.

    Any resources previously allocated must be freed.

Arguments:

    DriverObject - a pointer to the object that represents our driver.

Return Value:

    None
--*/

{
    PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;
    UNICODE_STRING uniWin32NameString;

    PAGED_CODE();

    //
    // Create counted string version of our Win32 device name.
    //

    RtlInitUnicodeString(&uniWin32NameString, DOS_DEVICE_NAME);


    //
    // Delete the link from our device name to a name in the Win32 namespace.
    //

    IoDeleteSymbolicLink(&uniWin32NameString);

    if (deviceObject != NULL)
    {
        IoDeleteDevice(deviceObject);
    }



}

QWORD test = 0x77;

NTSTATUS
SioctlDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)

/*++

Routine Description:

    This routine is called by the I/O system to perform a device I/O
    control function.

Arguments:

    DeviceObject - a pointer to the object that represents the device
        that I/O is to be done on.

    Irp - a pointer to the I/O Request Packet for this request.

Return Value:

    NT status code

--*/

{
    PIO_STACK_LOCATION  irpSp;// Pointer to current stack location
    NTSTATUS            ntStatus = STATUS_SUCCESS;// Assume success
    ULONG               inBufLength; // Input buffer length
    ULONG               outBufLength; // Output buffer length
    PCHAR               inBuf, outBuf; // pointer to Input and output buffer

    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    if (!inBufLength || !outBufLength)
    {
        ntStatus = STATUS_INVALID_PARAMETER;
        goto End;
    }

    //
    // Determine which I/O control code was specified.
    //

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
    {

    case IOCTL_SIOCTL_SET_PID:
        inBuf = Irp->AssociatedIrp.SystemBuffer;
        outBuf = Irp->AssociatedIrp.SystemBuffer;

        unsigned int unPid = 0;
        unPid = *(unsigned int*)inBuf;
        g_dwPid = unPid;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Pid :  %u\n", unPid);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Pid_address :  %p\n", &unPid);
        Irp->IoStatus.Information = 0;
        break;

    case IOCTL_SIOCTL_SET_VA:
        inBuf = Irp->AssociatedIrp.SystemBuffer;
        g_qwVa = *(QWORD*)inBuf;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "pid : %lld\n", g_qwVa);

        QWORD eproc = 0;
        eproc = FindProcessEPROC(g_dwPid);
        QWORD qwCr3 = 0;
        qwCr3 = GetProcessDirBase(eproc);

        QWORD qwPfn = 0;
        qwPfn = GetPfn(qwCr3, g_qwVa);

        outBuf = Irp->AssociatedIrp.SystemBuffer;
        RtlCopyBytes(outBuf, &qwPfn, sizeof(qwPfn));
        Irp->IoStatus.Information = sizeof(qwPfn);
        break;

    case IOCTL_SIOCTL_SET_PFN:
        inBuf = Irp->AssociatedIrp.SystemBuffer;
        g_dwPfn = *(DWORD*)inBuf;
        //QWORD eproc = 0;
        eproc = FindProcessEPROC(g_dwPid);
        //QWORD qwCr3 = 0;
        qwCr3 = GetProcessDirBase(eproc);
        SetPfn(qwCr3, g_qwVa, g_dwPfn);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "g_dwPfn : %d\n", g_dwPfn);
        Irp->IoStatus.Information = 0;
        break;

    default:

        //
        // The specified I/O control code is unrecognized by this driver.
        //

        ntStatus = STATUS_INVALID_DEVICE_REQUEST;
        SIOCTL_KDPRINT(("ERROR: unrecognized IOCTL %x\n",
            irpSp->Parameters.DeviceIoControl.IoControlCode));
        break;
    }

End:
    //
    // Finish the I/O operation by simply completing the packet and returning
    // the same status as in the packet itself.
    //

    Irp->IoStatus.Status = ntStatus;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return ntStatus;
}

VOID
PrintIrpInfo(
    PIRP Irp)
{
    PIO_STACK_LOCATION  irpSp;
    irpSp = IoGetCurrentIrpStackLocation(Irp);

    PAGED_CODE();

    SIOCTL_KDPRINT(("\tIrp->AssociatedIrp.SystemBuffer = 0x%p\n",
        Irp->AssociatedIrp.SystemBuffer));
    SIOCTL_KDPRINT(("\tIrp->UserBuffer = 0x%p\n", Irp->UserBuffer));
    SIOCTL_KDPRINT(("\tirpSp->Parameters.DeviceIoControl.Type3InputBuffer = 0x%p\n",
        irpSp->Parameters.DeviceIoControl.Type3InputBuffer));
    SIOCTL_KDPRINT(("\tirpSp->Parameters.DeviceIoControl.InputBufferLength = %d\n",
        irpSp->Parameters.DeviceIoControl.InputBufferLength));
    SIOCTL_KDPRINT(("\tirpSp->Parameters.DeviceIoControl.OutputBufferLength = %d\n",
        irpSp->Parameters.DeviceIoControl.OutputBufferLength));
    return;
}

VOID
PrintChars(
    _In_reads_(CountChars) PCHAR BufferAddress,
    _In_ size_t CountChars
)
{
    PAGED_CODE();

    if (CountChars) {

        while (CountChars--) {

            if (*BufferAddress > 31
                && *BufferAddress != 127) {

                KdPrint(("%c", *BufferAddress));

            }
            else {

                KdPrint(("."));

            }
            BufferAddress++;
        }
        KdPrint(("\n"));
    }
    return;
}


