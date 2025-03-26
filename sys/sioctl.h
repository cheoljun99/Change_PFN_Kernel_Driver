/*++

Copyright (c) 1997  Microsoft Corporation

Module Name:

    SIOCTL.H

Abstract:


    Defines the IOCTL codes that will be used by this driver.  The IOCTL code
    contains a command identifier, plus other information about the device,
    the type of access with which the file must have been opened,
    and the type of buffering.

Environment:

    Kernel mode only.

--*/

//
// Device type           -- in the "User Defined" range."
//
#define SIOCTL_TYPE 40000
//
// The IOCTL function codes from 0x800 to 0xFFF are for customer use.
//


#define IOCTL_SIOCTL_METHOD_BUFFERED\
    CTL_CODE( SIOCTL_TYPE, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS  )

#define IOCTL_SIOCTL_SET_PID\
    CTL_CODE( SIOCTL_TYPE, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS  )


#define IOCTL_SIOCTL_SET_VA\
    CTL_CODE( SIOCTL_TYPE, 0x904, METHOD_BUFFERED, FILE_ANY_ACCESS  )

#define IOCTL_SIOCTL_SET_PFN\
    CTL_CODE( SIOCTL_TYPE, 0x905, METHOD_BUFFERED, FILE_ANY_ACCESS  )

typedef unsigned __int64 QWORD, * PQWORD;

#define PFN_MASK(pe)        ((QWORD)((pe) & 0x0000FFFFFFFFF000UL))
#define PFN_SETZERO(pe)    ((QWORD)((pe) & 0xFFFF000000000FFFUL))

typedef union _virt_addr_t
{
    QWORD value;
    struct
    {
        QWORD offset_4kb : 12;
        QWORD pt_index : 9;
        QWORD pd_index : 9;
        QWORD pdpt_index : 9;
        QWORD pml4_index : 9;
        QWORD reserved : 16;
    }a;

    struct
    {
        QWORD offset_2mb : 21;
        QWORD pd_index : 9;
        QWORD pdpt_index : 9;
        QWORD pml4_index : 9;
        QWORD reserved : 16;
    }b;

    struct
    {
        QWORD offset_1gb : 30;
        QWORD pdpt_index : 9;
        QWORD pml4_index : 9;
        QWORD reserved : 16;
    }c;

} virt_addr_t, * pvirt_addr_t;


#define DRIVER_FUNC_INSTALL     0x01
#define DRIVER_FUNC_REMOVE      0x02

#define DRIVER_NAME       "SIoctl"


