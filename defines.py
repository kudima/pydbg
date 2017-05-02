#
# PyDBG
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: defines.py 224 2007-10-12 19:51:45Z aportnoy $
#
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program; if not, write to the Free
# Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
#
# windows_h.py was generated with:
#
#    c:\Python\Lib\site-packages\ctypes\wrap
#    c:\python\python h2xml.py windows.h -o windows.xml -q -c
#    c:\python\python xml2py.py windows.xml -s DEBUG_EVENT -s CONTEXT -s MEMORY_BASIC_INFORMATION -s LDT_ENTRY \
#        -s PROCESS_INFORMATION -s STARTUPINFO -s SYSTEM_INFO -o windows_h.py
#
# Then the import of ctypes was changed at the top of the file to utilize my_ctypes, which adds the necessary changes
# to support the pickle-ing of our defined data structures and ctype primitives.
#

'''
@author:       Pedram Amini
@license:      GNU General Public License 2.0 or later
@contact:      pedram.amini@gmail.com
@organization: www.openrce.org
'''

from my_ctypes import *
from windows_h import *
import struct


###
### manually declare entities from Tlhelp32.h since i was unable to import using h2xml.py.
###

TH32CS_SNAPHEAPLIST = 0x00000001
TH32CS_SNAPPROCESS  = 0x00000002
TH32CS_SNAPTHREAD   = 0x00000004
TH32CS_SNAPMODULE   = 0x00000008
TH32CS_INHERIT      = 0x80000000
TH32CS_SNAPALL      = (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE)

class THREADENTRY32(Structure):
    _fields_ = [
        ('dwSize',             DWORD),
        ('cntUsage',           DWORD),
        ('th32ThreadID',       DWORD),
        ('th32OwnerProcessID', DWORD),
        ('tpBasePri',          DWORD),
        ('tpDeltaPri',         DWORD),
        ('dwFlags',            DWORD),
    ]

class PROCESSENTRY32(Structure):
    _fields_ = [
        ('dwSize',              DWORD),
        ('cntUsage',            DWORD),
        ('th32ProcessID',       DWORD),
        ('th32DefaultHeapID',   DWORD),
        ('th32ModuleID',        DWORD),
        ('cntThreads',          DWORD),
        ('th32ParentProcessID', DWORD),
        ('pcPriClassBase',      DWORD),
        ('dwFlags',             DWORD),
        ('szExeFile',           CHAR * 260),
    ]

class MODULEENTRY32(Structure):
    _fields_ = [
        ("dwSize",        DWORD),
        ("th32ModuleID",  DWORD),
        ("th32ProcessID", DWORD),
        ("GlblcntUsage",  DWORD),
        ("ProccntUsage",  DWORD),
        ("modBaseAddr",   DWORD),
        ("modBaseSize",   DWORD),
        ("hModule",       DWORD),
        ("szModule",      CHAR * 256),
        ("szExePath",     CHAR * 260),
    ]

class _MIB_TCPROW_OWNER_PID(Structure):
    _fields_ = [
        ("dwState",      DWORD),
        ("dwLocalAddr",  DWORD),
        ("dwLocalPort",  DWORD),
        ("dwRemoteAddr", DWORD),
        ("dwRemotePort", DWORD),
        ("dwOwningPid",  DWORD),
    ]

class MIB_TCPTABLE_OWNER_PID(Structure):
    _fields_ = [
        ("dwNumEntries", DWORD),
        ("table",        _MIB_TCPROW_OWNER_PID * 512)
    ]


class _MIB_UDPROW_OWNER_PID(Structure):
    _fields_ = [
        ("dwLocalAddr", DWORD),
        ("dwLocalPort", DWORD),
        ("dwOwningPid", DWORD)
    ]

class MIB_UDPTABLE_OWNER_PID(Structure):
    _fields_ = [
        ("dwNumEntries", DWORD),
        ("table",        _MIB_UDPROW_OWNER_PID * 512)
    ]


###
### manually declare various structures as needed.
###

class SYSDBG_MSR(Structure):
    _fields_ = [
        ("Address", c_ulong),
        ("Data",    c_ulonglong),
    ]

class PEB:
    def __init__(self, dbg):
        """ 
        Process Environment Block
        
        @type  imm: Debugger OBJECT
        @param imm: Debugger        
        """
        # PEB struct is 488 bytes (win2k) located at 0x7ffdf000
        # can also use NTQueryProcessInformation to locate PEB base
        self.base = dbg.peb

        try:
            self.PEB = dbg.read(self.base, 488)
        except:
            error = "can't read PEB struct"
            raise Exception, error

        """
        0:000> !kdex2x86.strct PEB
        Loaded kdex2x86 extension DLL
        struct   _PEB (sizeof=488)
        +000 byte     InheritedAddressSpace
        +001 byte     ReadImageFileExecOptions
        +002 byte     BeingDebugged
        +003 byte     SpareBool
        +004 void     *Mutant
        +008 void     *ImageBaseAddress
        +00c struct   _PEB_LDR_DATA *Ldr
        +010 struct   _RTL_USER_PROCESS_PARAMETERS *ProcessParameters
        +014 void     *SubSystemData
        +018 void     *ProcessHeap
        +01c void     *FastPebLock
        +020 void     *FastPebLockRoutine
        +024 void     *FastPebUnlockRoutine
        +028 uint32   EnvironmentUpdateCount
        +02c void     *KernelCallbackTable
        +030 uint32   SystemReserved[2]
        +038 struct   _PEB_FREE_BLOCK *FreeList
        +03c uint32   TlsExpansionCounter
        +040 void     *TlsBitmap
        +044 uint32   TlsBitmapBits[2]
        +04c void     *ReadOnlySharedMemoryBase
        +050 void     *ReadOnlySharedMemoryHeap
        +054 void     **ReadOnlyStaticServerData
        +058 void     *AnsiCodePageData
        +05c void     *OemCodePageData
        +060 void     *UnicodeCaseTableData
        +064 uint32   NumberOfProcessors
        +068 uint32   NtGlobalFlag
        +070 union    _LARGE_INTEGER CriticalSectionTimeout
        +070 uint32   LowPart
        +074 int32    HighPart
        +070 struct   __unnamed3 u
        +070 uint32   LowPart
        +074 int32    HighPart
        +070 int64    QuadPart
        +078 uint32   HeapSegmentReserve
        +07c uint32   HeapSegmentCommit
        +080 uint32   HeapDeCommitTotalFreeThreshold
        +084 uint32   HeapDeCommitFreeBlockThreshold
        +088 uint32   NumberOfHeaps
        +08c uint32   MaximumNumberOfHeaps
        +090 void     **ProcessHeaps
        +094 void     *GdiSharedHandleTable
        +098 void     *ProcessStarterHelper
        +09c uint32   GdiDCAttributeList
        +0a0 void     *LoaderLock
        +0a4 uint32   OSMajorVersion
        +0a8 uint32   OSMinorVersion
        +0ac uint16   OSBuildNumber
        +0ae uint16   OSCSDVersion
        +0b0 uint32   OSPlatformId
        +0b4 uint32   ImageSubsystem
        +0b8 uint32   ImageSubsystemMajorVersion
        +0bc uint32   ImageSubsystemMinorVersion
        +0c0 uint32   ImageProcessAffinityMask
        +0c4 uint32   GdiHandleBuffer[34]
        +14c function *PostProcessInitRoutine
        +150 void     *TlsExpansionBitmap
        +154 uint32   TlsExpansionBitmapBits[32]
        +1d4 uint32   SessionId
        +1d8 void     *AppCompatInfo
        +1dc struct   _UNICODE_STRING CSDVersion
        +1dc uint16   Length
        +1de uint16   MaximumLength
        +1e0 uint16   *Buffer
        """
        # init PEB struct
        index = 0x000
        self.InheritedAddressSpace = struct.unpack("B",self.PEB[index])[0]
        index = 0x001
        self.ReadImageFileExecOptions = struct.unpack("B",self.PEB[index])[0]
        index = 0x002
        self.BeingDebugged = struct.unpack("B",self.PEB[index])[0]
        index = 0x003
        self.SpareBool = struct.unpack("B",self.PEB[index])[0]
        index = 0x004
        self.Mutant = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x008
        self.ImageBaseAddress = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x00c
        self.Ldr = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x010
        self.ProcessParameters = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x014
        self.SubSystemData = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x018
        self.ProcessHeap = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x01c
        self.FastPebLock = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x020
        self.FastPebLockRoutine = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x024
        self.FastPebUnlockRoutine = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x028
        self.EnviromentUpdateCount = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x02c
        self.KernelCallbackTable = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x030
        self.SystemReserved = []
        for i in range(0,2):
            self.SystemReserved.append(struct.unpack("<L",self.PEB[index:index+4])[0])
            index += 4
        index = 0x038
        self.FreeList = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x03c
        self.TlsExpansionCounter = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x040
        self.TlsBitmap = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x044
        self.TlsBitmapBits = []
        for i in range(0,2):
            self.TlsBitmapBits.append(struct.unpack("<L",self.PEB[index:index+4])[0])
            index += 4
        index = 0x04c
        self.ReadOnlySharedMemoryBase = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x050
        self.ReadOnlySharedMemoryheap = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x054
        self.ReadOnlyStaticServerData = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x058
        self.AnsiCodePageData = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x05c
        self.OemCodePageData = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x060
        self.UnicodeCaseTableData = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x064
        self.NumberOfProcessors = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x068
        self.NtGlobalFlag = struct.unpack("<L",self.PEB[index:index+4])[0]

        # ??? WHAT HAPPENS TO THE 4 bytes here ?

        index = 0x070
        self.CriticalSectionTimeout_LowPart = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x074
        self.CriticalSectionTimeout_HighPart = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x078
        self.HeapSegmentReserve = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x07c
        self.HeapSegmentCommit = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x080
        self.HeapDeCommitTotalFreeThreshold = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x084
        self.HeapDeCommitFreeBlockThreshold = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x088
        self.NumberOfHeaps = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x08c
        self.MaximumNumberOfHeaps = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x090
        self.ProcessHeaps = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x094
        self.GdiSharedHandleTable = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x098
        self.ProcessStarterHelper = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x09c
        self.GdiDCAttributeList = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x0a0
        self.LoaderLock = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x0a4
        self.OSMajorVersion = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x0a8
        self.OSMinorVersion = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x0ac
        self.OSBuildNumber = struct.unpack("<H",self.PEB[index:index+2])[0]
        index = 0x0ae
        self.OSCSDVersion = struct.unpack("<H",self.PEB[index:index+2])[0]
        index = 0x0b0
        self.OSPlatformId = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x0b4
        self.ImageSubsystem = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x0b8
        self.ImageSubsystemMajorVersion = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x0bc
        self.ImageSubsystemMinorVersion = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x0c0
        self.ImageProcessAffinityMask = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x0c4
        # uint32 GdiHandleBuffer[34]
        self.GdiHandleBuffer = []
        for i in range(0,34):
            self.GdiHandleBuffer.append(struct.unpack("<L",self.PEB[index:index+4])[0])
            index += 4
        index = 0x14c
        self.PostProcessInitRoutine = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x150
        self.TlsExpansionBitmap = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x154
        # uint32 TlsExpansionBitmapBits[32]
        self.TlsExpansionBitmapBits = []
        for i in range(0,32):
            self.TlsExpansionBitmapBits.append(struct.unpack("<L",self.PEB[index:index+4])[0])
            index += 4
        index = 0x1d4
        self.SessionId = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x1d8
        self.AppCompatInfo = struct.unpack("<L",self.PEB[index:index+4])[0]
        index = 0x1dc
        # struct _UNICODE_STRING CSDVersion
        self.CSDVersion_Length = struct.unpack("<H",self.PEB[index:index+2])[0]
        index += 2
        self.CSDVersion_MaximumLength = struct.unpack("<H",self.PEB[index:index+2])[0]
        index += 2
        self.CSDVersion_Buffer = struct.unpack("<H",self.PEB[index:index+2])[0]
        index += 2



###
### manually declare various #define's as needed.
###

# debug event codes.
EXCEPTION_DEBUG_EVENT          = 0x00000001
CREATE_THREAD_DEBUG_EVENT      = 0x00000002
CREATE_PROCESS_DEBUG_EVENT     = 0x00000003
EXIT_THREAD_DEBUG_EVENT        = 0x00000004
EXIT_PROCESS_DEBUG_EVENT       = 0x00000005
LOAD_DLL_DEBUG_EVENT           = 0x00000006
UNLOAD_DLL_DEBUG_EVENT         = 0x00000007
OUTPUT_DEBUG_STRING_EVENT      = 0x00000008
RIP_EVENT                      = 0x00000009
USER_CALLBACK_DEBUG_EVENT      = 0xDEADBEEF     # added for callback support in debug event loop.

# debug exception codes.
EXCEPTION_ACCESS_VIOLATION     = 0xC0000005
EXCEPTION_BREAKPOINT           = 0x80000003
EXCEPTION_GUARD_PAGE           = 0x80000001
EXCEPTION_SINGLE_STEP          = 0x80000004

# hw breakpoint conditions
HW_ACCESS                      = 0x00000003
HW_EXECUTE                     = 0x00000000
HW_WRITE                       = 0x00000001

CONTEXT_CONTROL                = 0x00010001
CONTEXT_FULL                   = 0x00010007
CONTEXT_DEBUG_REGISTERS        = 0x00010010
CREATE_NEW_CONSOLE             = 0x00000010
DBG_CONTINUE                   = 0x00010002
DBG_EXCEPTION_NOT_HANDLED      = 0x80010001
DBG_EXCEPTION_HANDLED          = 0x00010001
DEBUG_PROCESS                  = 0x00000001
DEBUG_ONLY_THIS_PROCESS        = 0x00000002
EFLAGS_RF                      = 0x00010000
EFLAGS_TRAP                    = 0x00000100
ERROR_NO_MORE_FILES            = 0x00000012
FILE_MAP_READ                  = 0x00000004
FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100
FORMAT_MESSAGE_FROM_SYSTEM     = 0x00001000
INVALID_HANDLE_VALUE           = 0xFFFFFFFF
MEM_COMMIT                     = 0x00001000
MEM_DECOMMIT                   = 0x00004000
MEM_IMAGE                      = 0x01000000
MEM_RELEASE                    = 0x00008000
PAGE_NOACCESS                  = 0x00000001
PAGE_READONLY                  = 0x00000002
PAGE_READWRITE                 = 0x00000004
PAGE_WRITECOPY                 = 0x00000008
PAGE_EXECUTE                   = 0x00000010
PAGE_EXECUTE_READ              = 0x00000020
PAGE_EXECUTE_READWRITE         = 0x00000040
PAGE_EXECUTE_WRITECOPY         = 0x00000080
PAGE_GUARD                     = 0x00000100
PAGE_NOCACHE                   = 0x00000200
PAGE_WRITECOMBINE              = 0x00000400
PROCESS_ALL_ACCESS             = 0x001F0FFF
SE_PRIVILEGE_ENABLED           = 0x00000002
SW_SHOW                        = 0x00000005
THREAD_ALL_ACCESS              = 0x001F03FF
TOKEN_ADJUST_PRIVILEGES        = 0x00000020
UDP_TABLE_OWNER_PID            = 0x00000001
VIRTUAL_MEM                    = 0x00003000

# for NtSystemDebugControl()
SysDbgReadMsr                  = 16
SysDbgWriteMsr                 = 17

# for mapping TCP ports and PIDs
AF_INET                        = 0x00000002
AF_INET6                       = 0x00000017
MIB_TCP_STATE_LISTEN           = 0x00000002
TCP_TABLE_OWNER_PID_ALL        = 0x00000005

# process access right

PROCESS_QUERY_INFORMATION      = 0x0400
PROCESS_VM_READ                = 0x0010

