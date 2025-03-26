/*++

Copyright (c) 1990-98  Microsoft Corporation All Rights Reserved

Module Name:

    testapp.c

Abstract:

Environment:

    Win32 console multi-threaded application

--*/
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strsafe.h>
#include <sys\sioctl.h>



void dump(const void* mem, size_t length) {
    const unsigned char* data = (const unsigned char*)mem;
    size_t i, j;

    for (i = 0; i < length; i += 16) {
        // Print offset
        printf("%016p  ", (((char*)mem + i)));

        // Print hex bytes
        for (j = 0; j < 16; ++j) {
            if (i + j < length) {
                printf("%02x ", data[i + j]);
            }
            else {
                printf("   ");
            }
        }

        // Print ASCII characters
        printf(" ");
        for (j = 0; j < 16; ++j) {
            if (i + j < length) {
                unsigned char ch = data[i + j];
                printf("%c", isprint(ch) ? ch : '.');
            }
            else {
                printf(" ");
            }
        }

        printf("\n");
    }
}


BOOLEAN
ManageDriver(
    _In_ LPCTSTR  DriverName,
    _In_ LPCTSTR  ServiceName,
    _In_ USHORT   Function
);

BOOLEAN
SetupDriverName(
    _Inout_updates_bytes_all_(BufferLength) PCHAR DriverLocation,
    _In_ ULONG BufferLength
);

char OutputBuffer[100];
char InputBuffer[100];



VOID __cdecl
main(
    _In_ ULONG argc,
    _In_reads_(argc) PCHAR argv[]
)
{
    HANDLE hDevice;
    BOOL bRc;
    ULONG bytesReturned;
    DWORD errNum = 0;
    TCHAR driverLocation[MAX_PATH];

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    // open the device

    if ((hDevice = CreateFile("\\\\.\\IoctlTest",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL)) == INVALID_HANDLE_VALUE) {

        errNum = GetLastError();

        if (errNum != ERROR_FILE_NOT_FOUND) {

            printf("CreateFile failed : %d\n", errNum);

            return;
        }

        // The driver is not started yet so let us the install the driver.
        // First setup full path to driver name.

        if (!SetupDriverName(driverLocation, sizeof(driverLocation))) {

            return;
        }

        if (!ManageDriver(DRIVER_NAME,
            driverLocation,
            DRIVER_FUNC_INSTALL
        )) {

            printf("Unable to install driver.\n");

            // Error - remove driver.

            ManageDriver(DRIVER_NAME,
                driverLocation,
                DRIVER_FUNC_REMOVE
            );

            return;
        }

        hDevice = CreateFile("\\\\.\\IoctlTest",
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        if (hDevice == INVALID_HANDLE_VALUE) {
            printf("Error: CreatFile Failed : %d\n", GetLastError());
            return;
        }

    }

    // Printing Input & Output buffer pointers and size

    printf("InputBuffer Pointer = %p, BufLength = %Iu\n", InputBuffer,
        sizeof(InputBuffer));
    printf("OutputBuffer Pointer = %p BufLength = %Iu\n", OutputBuffer,
        sizeof(OutputBuffer));

    // Performing METHOD_BUFFERED

    StringCbCopy(InputBuffer, sizeof(InputBuffer),
        "This String is from User Application; using METHOD_BUFFERED");

    printf("\nCalling DeviceIoControl METHOD_BUFFERED:\n");

    char cInput;
    char* pMem = NULL;
    DWORD pid = 0;
    unsigned __int64 un64Pfn = 0;
    unsigned __int64 un64NotepadPfn = 0;
    unsigned __int64 oldPfn= 0;
    unsigned int unPid;
    unsigned __int64 un64Va;
    virt_addr_t a = { 0 };
    unsigned __int64 check = 0;
    virt_addr_t b= { 0 };
    int doWhileCount = 0;

    while (1) {
        cInput = (char)getchar();
        switch (cInput)
        {
            case '1':
                printf("notepad.exe의 VA를 입력하세요 : ");
                scanf_s("%llx", &check);
                b.value = (QWORD)check;
                printf("notepad.exe의 VA : %llx \nPML4 index : %lld \nPDPT index : %lld \nPD index : %lld \nPT index : %lld \nOffset : %lld\n",
                    check, b.a.pml4_index, b.a.pdpt_index, b.a.pd_index, b.a.pt_index, b.a.offset_4kb);
                do {
                    if (doWhileCount != 0) {
                        printf("ioctlapp.exe의 offset 값이 notepad의 offset 값보다 큰이슈로 다시 동적 할당\n");
                    }
                    doWhileCount++;
                    pMem = (char*)malloc(4096 * 2);
                    memcpy(pMem, "mallocTest", 11);
                    a.value = (QWORD)pMem;
                    printf("ioctlapp.exe의 VA : %p \nPML4 index : %lld \nPDPT index : %lld \nPD index : %lld \nPT index : %lld \nOffset : %lld\n",
                        pMem, a.a.pml4_index, a.a.pdpt_index, a.a.pd_index, a.a.pt_index, a.a.offset_4kb);
                }
                while (b.a.offset_4kb < a.a.offset_4kb);  // 조건이 참이면 반복
                break;
            case '2':
                dump(pMem, 4096 * 2);
                printf("%p\n", pMem);
                break;
            case '3':
                printf("notepad.exe의 PID를 입력하세요 : ");           
                scanf_s("%d", &unPid);
                printf("notepad.exe의 VA를 입력하세요 : ");
                scanf_s("%llx", &un64Va);
                memset(OutputBuffer, 0, sizeof(OutputBuffer));
                unsigned int nPid = unPid;
                printf("Current notepad.exe Pid : %d\n", nPid);
                bRc = DeviceIoControl(hDevice,
                    (DWORD)IOCTL_SIOCTL_SET_PID,
                    &nPid,
                    (DWORD)sizeof(nPid),
                    &OutputBuffer,
                    sizeof(OutputBuffer),
                    &bytesReturned,
                    NULL
                );
                if (!bRc)
                {
                    printf("Error in DeviceIoControl : %d", GetLastError());
                    return;
            
                }
                bRc = DeviceIoControl(hDevice,
                    (DWORD)IOCTL_SIOCTL_SET_VA,
                    &un64Va,
                    (DWORD)sizeof(un64Va),
                    &un64NotepadPfn,
                    sizeof(un64NotepadPfn),
                    &bytesReturned,
                    NULL
                );
                if (!bRc)
                {
                    printf("Error in DeviceIoControl : %d", GetLastError());
                    return;
            
                }
                printf("Notepad Pfn : %llx\n", un64NotepadPfn);
            
                break;
            
            case '4':
                pid = GetCurrentProcessId();
                printf("Current ioctlapp.exe pid: %d\n", pid);
                //unsigned __int64 un64Va;
                // 이 프로그램에서 할당받은 pMem의 PFN을 notepad의 PFN으로 교체해야함
                // PID 전송
                /*if (!DeviceIoControl(hDriver, IOCTL_SIOCTL_SET_PID, &pid, sizeof(pid), (LPVOID)buf, sizeof(buf), &retLen, 0))
                {
                    printf("DeviceIoControl() failed\n");
                    CloseHandle(hDriver);
                    return 0;
                }*/
                bRc = DeviceIoControl(hDevice,
                    (DWORD)IOCTL_SIOCTL_SET_PID,
                    &pid,
                    (DWORD)sizeof(pid),
                    &OutputBuffer,
                    sizeof(OutputBuffer),
                    &bytesReturned,
                    NULL
                );
                if (!bRc)
                {
                    printf("Error in DeviceIoControl : %d", GetLastError());
                    return;
            
                }
                // pMem의 주소를 SET_VA로 전송
                /*printf("Receive message: %s (%d bytes)\n", buf, retLen);
                if (!DeviceIoControl(hDriver, IOCTL_SIOCTL_SET_VA, &un64Va, sizeof(un64Va), &un64Pfn, sizeof(un64Pfn), &retLen, 0))
                {
                    printf("DeviceIoControl() failed\n");
                    CloseHandle(hDriver);
                    return 0;
                }*/
                un64Va = (unsigned __int64)pMem;
                printf("Current ioctl.exe VA %llx\n", un64Va);
                bRc = DeviceIoControl(hDevice,
                    (DWORD)IOCTL_SIOCTL_SET_VA,
                    &un64Va,
                    (DWORD)sizeof(un64Va),
                    &un64Pfn,
                    sizeof(un64Pfn),
                    &bytesReturned,
                    NULL
                );
                if (!bRc)
                {
                    printf("Error in DeviceIoControl : %d", GetLastError());
                    return;
            
                }
                printf("Current ioctl.exe Pfn : %llx\n", un64Pfn);
                // 위에서 구한 notepad의 PFN을 입력해 
                //scanf_s("%llx", &un64Pfn);
                //printf("Pfn: %llx\n", un64Pfn);
                            // WritePhysicalMemory2 오류인지 주소가 12비트 SHIFT LEFT 당겨지는 문제가 있음.
                // 12비트 SHIFT RIGHT로 주소 오류 보정
                oldPfn = un64Pfn;
                un64NotepadPfn = un64NotepadPfn >> 12;
                /*if (!DeviceIoControl(hDriver, IOCTL_SIOCTL_SET_PFN, &un64Pfn, sizeof(un64Pfn), (LPVOID)buf, sizeof(buf), &retLen, 0))
                {
                    printf("DeviceIoControl() failed\n");
                    CloseHandle(hDriver);
                    return 0;
                }*/
                printf("ioctl.exe의 Pfn을 notepad.exe의 pfn으로 변경 시작!\n");
                bRc = DeviceIoControl(hDevice,
                    (DWORD)IOCTL_SIOCTL_SET_PFN,
                    &un64NotepadPfn,
                    (DWORD)sizeof(un64NotepadPfn),
                    &un64Pfn,
                    sizeof(un64Pfn),
                    &bytesReturned,
                    NULL
                );
                if (!bRc)
                {
                    printf("Error in DeviceIoControl : %d", GetLastError());
                    return;
            
                }
                printf("ioctl.exe의 Pfn을 notepad.exe의 pfn으로 변경 완료!\n");
                //printf("Pfn : %llx\n", un64Pfn);           
                //printf("Receive message: %s (%d bytes)\n", buf, retLen);
                //printf("Receive message: %s (%d bytes)\n", un64Pfn, bytesReturned);           
                break;            
            case '5':            
                printf("바꾸기 위한 ioctlapp.exe의 VA를 입력하세요 : ");
                scanf_s("%llx", &un64Va);            
                for (int i = 0; i < 10; i++) {
                    (*(char*)un64Va)++;
                    printf("%c\n", *((char*)un64Va));
                    Sleep(2000);
                }          
                break;         
            case '6':
                nPid = GetCurrentProcessId();
                printf("current ioctlapp.exe pid : %d\n", nPid);
                bRc = DeviceIoControl(hDevice,
                    (DWORD)IOCTL_SIOCTL_SET_PID,
                    &nPid,
                    sizeof(nPid),
                    &OutputBuffer,
                    sizeof(OutputBuffer),
                    &bytesReturned,
                    NULL
                );
                un64Va = (unsigned __int64)pMem;
                printf("current ioctlapp.exe VA %llx\n", un64Va);
                bRc = DeviceIoControl(hDevice,
                    (DWORD)IOCTL_SIOCTL_SET_VA,
                    &un64Va,
                    sizeof(un64Va),
                    &un64Pfn,
                    sizeof(un64Pfn),
                    &bytesReturned,
                    NULL
                );
                printf("수정된 ioctlapp.exe Pfn : %llx\n", un64Pfn);
                printf("원본 ioctlapp.exe Pfn : %llx\n", oldPfn);

                printf("ioctlapp.exe의 Pfn을 다시 원래대로 되돌리기 시작\n");
                oldPfn = oldPfn >> 12;
                bRc = DeviceIoControl(hDevice,
                    (DWORD)IOCTL_SIOCTL_SET_PFN,
                    &oldPfn,
                    sizeof(oldPfn),
                    &un64Pfn,
                    sizeof(un64Pfn),
                    &bytesReturned,
                    NULL
                );
                printf("ioctlapp.exe의 Pfn을 다시 원래대로 되돌리기 완료\n");
                break;
            case 'x':
                break;
        }
    }
    CloseHandle(hDevice);
    // Unload the driver.  Ignore any errors.
    ManageDriver(DRIVER_NAME,
        driverLocation,
        DRIVER_FUNC_REMOVE
    );
    // close the handle to the device.
}

