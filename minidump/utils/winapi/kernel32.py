from minidump.utils.winapi.defines import *
import enum


# DWORD WINAPI GetLastError(void);
def GetLastError():
    _GetLastError = windll.kernel32.GetLastError
    _GetLastError.argtypes = []
    _GetLastError.restype  = DWORD
    return _GetLastError()

class WindowsMinBuild(enum.Enum):
	WIN_XP = 2500
	WIN_2K3 = 3000
	WIN_VISTA = 5000
	WIN_7 = 7000
	WIN_8 = 8000
	WIN_BLUE = 9400
	WIN_10 = 9800

#utter microsoft bullshit commencing..
def getWindowsBuild():   
    class OSVersionInfo(ctypes.Structure):
        _fields_ = [
            ("dwOSVersionInfoSize" , ctypes.c_int),
            ("dwMajorVersion"      , ctypes.c_int),
            ("dwMinorVersion"      , ctypes.c_int),
            ("dwBuildNumber"       , ctypes.c_int),
            ("dwPlatformId"        , ctypes.c_int),
            ("szCSDVersion"        , ctypes.c_char*128)];
    GetVersionEx = getattr( ctypes.windll.kernel32 , "GetVersionExA")
    version  = OSVersionInfo()
    version.dwOSVersionInfoSize = ctypes.sizeof(OSVersionInfo)
    GetVersionEx( ctypes.byref(version) )    
    return version.dwBuildNumber

def get_all_access_flags():
    DELETE = 0x00010000
    READ_CONTROL = 0x00020000
    WRITE_DAC = 0x00040000
    WRITE_OWNER = 0x00080000

    SYNCHRONIZE = 0x00100000

    STANDARD_RIGHTS_REQUIRED = DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER
    STANDARD_RIGHTS_ALL = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE

    if getWindowsBuild() >= WindowsMinBuild.WIN_VISTA.value:
        return STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF
    else:
        return STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF

PROCESS_ALL_ACCESS = get_all_access_flags()

# Process access rights for OpenProcess
PROCESS_TERMINATE                 = 0x0001
PROCESS_CREATE_THREAD             = 0x0002
PROCESS_SET_SESSIONID             = 0x0004
PROCESS_VM_OPERATION              = 0x0008
PROCESS_VM_READ                   = 0x0010
PROCESS_VM_WRITE                  = 0x0020
PROCESS_DUP_HANDLE                = 0x0040
PROCESS_CREATE_PROCESS            = 0x0080
PROCESS_SET_QUOTA                 = 0x0100
PROCESS_SET_INFORMATION           = 0x0200
PROCESS_QUERY_INFORMATION         = 0x0400
PROCESS_SUSPEND_RESUME            = 0x0800
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

# Thread access rights for OpenThread
THREAD_TERMINATE                 = 0x0001
THREAD_SUSPEND_RESUME            = 0x0002
THREAD_ALERT                     = 0x0004
THREAD_GET_CONTEXT               = 0x0008
THREAD_SET_CONTEXT               = 0x0010
THREAD_SET_INFORMATION           = 0x0020
THREAD_QUERY_INFORMATION         = 0x0040
THREAD_SET_THREAD_TOKEN          = 0x0080
THREAD_IMPERSONATE               = 0x0100
THREAD_DIRECT_IMPERSONATION      = 0x0200
THREAD_SET_LIMITED_INFORMATION   = 0x0400
THREAD_QUERY_LIMITED_INFORMATION = 0x0800

# typedef struct DECLSPEC_ALIGN(16) _MEMORY_BASIC_INFORMATION64 {
#     ULONGLONG BaseAddress;
#     ULONGLONG AllocationBase;
#     DWORD     AllocationProtect;
#     DWORD     __alignment1;
#     ULONGLONG RegionSize;
#     DWORD     State;
#     DWORD     Protect;
#     DWORD     Type;
#     DWORD     __alignment2;
# } MEMORY_BASIC_INFORMATION64, *PMEMORY_BASIC_INFORMATION64;
class MEMORY_BASIC_INFORMATION64(Structure):
    _fields_ = [
        ('BaseAddress',         ULONGLONG),     # remote pointer
        ('AllocationBase',      ULONGLONG),     # remote pointer
        ('AllocationProtect',   DWORD),
        ('__alignment1',        DWORD),
        ('RegionSize',          ULONGLONG),
        ('State',               DWORD),
        ('Protect',             DWORD),
        ('Type',                DWORD),
        ('__alignment2',        DWORD),
    ]

# typedef struct _MEMORY_BASIC_INFORMATION {
#     PVOID BaseAddress;
#     PVOID AllocationBase;
#     DWORD AllocationProtect;
#     SIZE_T RegionSize;
#     DWORD State;
#     DWORD Protect;
#     DWORD Type;
# } MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;
class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ('BaseAddress',         SIZE_T),    # remote pointer
        ('AllocationBase',      SIZE_T),    # remote pointer
        ('AllocationProtect',   DWORD),
        ('RegionSize',          SIZE_T),
        ('State',               DWORD),
        ('Protect',             DWORD),
        ('Type',                DWORD),
    ]
PMEMORY_BASIC_INFORMATION = POINTER(MEMORY_BASIC_INFORMATION)


# HANDLE WINAPI OpenProcess(
#   __in  DWORD dwDesiredAccess,
#   __in  BOOL bInheritHandle,
#   __in  DWORD dwProcessId
# );
def OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId):
    _OpenProcess = windll.kernel32.OpenProcess
    _OpenProcess.argtypes = [DWORD, BOOL, DWORD]
    _OpenProcess.restype  = HANDLE

    hProcess = _OpenProcess(dwDesiredAccess, bool(bInheritHandle), dwProcessId)
    if hProcess == NULL:
        raise ctypes.WinError()
    return hProcess

# SIZE_T WINAPI VirtualQueryEx(
#   __in      HANDLE hProcess,
#   __in_opt  LPCVOID lpAddress,
#   __out     PMEMORY_BASIC_INFORMATION lpBuffer,
#   __in      SIZE_T dwLength
# );
def VirtualQueryEx(hProcess, lpAddress):
    _VirtualQueryEx = windll.kernel32.VirtualQueryEx
    _VirtualQueryEx.argtypes = [HANDLE, LPVOID, PMEMORY_BASIC_INFORMATION, SIZE_T]
    _VirtualQueryEx.restype  = SIZE_T

    lpBuffer  = MEMORY_BASIC_INFORMATION()
    dwLength  = sizeof(MEMORY_BASIC_INFORMATION)
    success   = _VirtualQueryEx(hProcess, lpAddress, byref(lpBuffer), dwLength)
    if success == 0:
        raise ctypes.WinError()
    return lpBuffer


# BOOL WINAPI ReadProcessMemory(
#   __in   HANDLE hProcess,
#   __in   LPCVOID lpBaseAddress,
#   __out  LPVOID lpBuffer,
#   __in   SIZE_T nSize,
#   __out  SIZE_T* lpNumberOfBytesRead
# );
def ReadProcessMemory(hProcess, lpBaseAddress, nSize):
    _ReadProcessMemory = windll.kernel32.ReadProcessMemory
    _ReadProcessMemory.argtypes = [HANDLE, LPVOID, LPVOID, SIZE_T, POINTER(SIZE_T)]
    _ReadProcessMemory.restype  = bool

    lpBuffer            = ctypes.create_string_buffer(b'', nSize)
    lpNumberOfBytesRead = SIZE_T(0)
    success = _ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, byref(lpNumberOfBytesRead))
    if not success and GetLastError() != ERROR_PARTIAL_COPY:
        raise ctypes.WinError()
    #return str(lpBuffer.raw)[:lpNumberOfBytesRead.value]
    return lpBuffer.raw[:lpNumberOfBytesRead.value]


#--- Toolhelp library defines and structures ----------------------------------

TH32CS_SNAPHEAPLIST = 0x00000001
TH32CS_SNAPPROCESS  = 0x00000002
TH32CS_SNAPTHREAD   = 0x00000004
TH32CS_SNAPMODULE   = 0x00000008
TH32CS_INHERIT      = 0x80000000
TH32CS_SNAPALL      = (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE)

# typedef struct tagTHREADENTRY32 {
#   DWORD dwSize;
#   DWORD cntUsage;
#   DWORD th32ThreadID;
#   DWORD th32OwnerProcessID;
#   LONG tpBasePri;
#   LONG tpDeltaPri;
#   DWORD dwFlags;
# } THREADENTRY32,  *PTHREADENTRY32;
class THREADENTRY32(Structure):
    _fields_ = [
        ('dwSize',             DWORD),
        ('cntUsage',           DWORD),
        ('th32ThreadID',       DWORD),
        ('th32OwnerProcessID', DWORD),
        ('tpBasePri',          LONG),
        ('tpDeltaPri',         LONG),
        ('dwFlags',            DWORD),
    ]
LPTHREADENTRY32 = POINTER(THREADENTRY32)

# typedef struct tagPROCESSENTRY32 {
#    DWORD dwSize;
#    DWORD cntUsage;
#    DWORD th32ProcessID;
#    ULONG_PTR th32DefaultHeapID;
#    DWORD th32ModuleID;
#    DWORD cntThreads;
#    DWORD th32ParentProcessID;
#    LONG pcPriClassBase;
#    DWORD dwFlags;
#    TCHAR szExeFile[MAX_PATH];
# } PROCESSENTRY32,  *PPROCESSENTRY32;
class PROCESSENTRY32(Structure):
    _fields_ = [
        ('dwSize',              DWORD),
        ('cntUsage',            DWORD),
        ('th32ProcessID',       DWORD),
        ('th32DefaultHeapID',   ULONG_PTR),
        ('th32ModuleID',        DWORD),
        ('cntThreads',          DWORD),
        ('th32ParentProcessID', DWORD),
        ('pcPriClassBase',      LONG),
        ('dwFlags',             DWORD),
        ('szExeFile',           TCHAR * 260),
    ]
LPPROCESSENTRY32 = POINTER(PROCESSENTRY32)

# typedef struct tagPROCESSENTRY32W {
#    DWORD dwSize;
#    DWORD cntUsage;
#    DWORD th32ProcessID;
#    ULONG_PTR th32DefaultHeapID;
#    DWORD th32ModuleID;
#    DWORD cntThreads;
#    DWORD th32ParentProcessID;
#    LONG pcPriClassBase;
#    DWORD dwFlags;
#    WCHAR szExeFile[MAX_PATH];
# } PROCESSENTRY32W,  *PPROCESSENTRY32W;
class PROCESSENTRY32W(Structure):
    _fields_ = [
        ('dwSize',              DWORD),
        ('cntUsage',            DWORD),
        ('th32ProcessID',       DWORD),
        ('th32DefaultHeapID',   ULONG_PTR),
        ('th32ModuleID',        DWORD),
        ('cntThreads',          DWORD),
        ('th32ParentProcessID', DWORD),
        ('pcPriClassBase',      LONG),
        ('dwFlags',             DWORD),
        ('szExeFile',           WCHAR * 260),
    ]
LPPROCESSENTRY32W = POINTER(PROCESSENTRY32W)



# typedef struct tagMODULEENTRY32 {
#   DWORD dwSize;
#   DWORD th32ModuleID;
#   DWORD th32ProcessID;
#   DWORD GlblcntUsage;
#   DWORD ProccntUsage;
#   BYTE* modBaseAddr;
#   DWORD modBaseSize;
#   HMODULE hModule;
#   TCHAR szModule[MAX_MODULE_NAME32 + 1];
#   TCHAR szExePath[MAX_PATH];
# } MODULEENTRY32,  *PMODULEENTRY32;
class MODULEENTRY32(Structure):
    _fields_ = [
        ("dwSize",        DWORD),
        ("th32ModuleID",  DWORD),
        ("th32ProcessID", DWORD),
        ("GlblcntUsage",  DWORD),
        ("ProccntUsage",  DWORD),
        ("modBaseAddr",   LPVOID),  # BYTE*
        ("modBaseSize",   DWORD),
        ("hModule",       HMODULE),
        ("szModule",      TCHAR * (MAX_MODULE_NAME32 + 1)),
        ("szExePath",     TCHAR * MAX_PATH),
    ]
LPMODULEENTRY32 = POINTER(MODULEENTRY32)

# typedef struct tagHEAPENTRY32 {
#   SIZE_T    dwSize;
#   HANDLE    hHandle;
#   ULONG_PTR dwAddress;
#   SIZE_T    dwBlockSize;
#   DWORD     dwFlags;
#   DWORD     dwLockCount;
#   DWORD     dwResvd;
#   DWORD     th32ProcessID;
#   ULONG_PTR th32HeapID;
# } HEAPENTRY32,
# *PHEAPENTRY32;
class HEAPENTRY32(Structure):
    _fields_ = [
        ("dwSize",          SIZE_T),
        ("hHandle",         HANDLE),
        ("dwAddress",       ULONG_PTR),
        ("dwBlockSize",     SIZE_T),
        ("dwFlags",         DWORD),
        ("dwLockCount",     DWORD),
        ("dwResvd",         DWORD),
        ("th32ProcessID",   DWORD),
        ("th32HeapID",      ULONG_PTR),
]
LPHEAPENTRY32 = POINTER(HEAPENTRY32)

# typedef struct tagHEAPLIST32 {
#   SIZE_T    dwSize;
#   DWORD     th32ProcessID;
#   ULONG_PTR th32HeapID;
#   DWORD     dwFlags;
# } HEAPLIST32,
#  *PHEAPLIST32;
class HEAPLIST32(Structure):
    _fields_ = [
        ("dwSize",          SIZE_T),
        ("th32ProcessID",   DWORD),
        ("th32HeapID",      ULONG_PTR),
        ("dwFlags",         DWORD),
]
LPHEAPLIST32 = POINTER(HEAPLIST32)

#   __in  DWORD dwFlags,
#   __in  DWORD th32ProcessID
# );
def CreateToolhelp32Snapshot(dwFlags = TH32CS_SNAPALL, th32ProcessID = 0):
    _CreateToolhelp32Snapshot = windll.kernel32.CreateToolhelp32Snapshot
    _CreateToolhelp32Snapshot.argtypes = [DWORD, DWORD]
    _CreateToolhelp32Snapshot.restype  = HANDLE

    hSnapshot = _CreateToolhelp32Snapshot(dwFlags, th32ProcessID)
    if hSnapshot == INVALID_HANDLE_VALUE:
        raise ctypes.WinError()
    return hSnapshot

# BOOL WINAPI Heap32ListFirst(
#   __in     HANDLE hSnapshot,
#   __inout  LPHEAPLIST32 lphl
# );
def Heap32ListFirst(hSnapshot):
    _Heap32ListFirst = windll.kernel32.Heap32ListFirst
    _Heap32ListFirst.argtypes = [HANDLE, LPHEAPLIST32]
    _Heap32ListFirst.restype  = bool

    hl = HEAPLIST32()
    hl.dwSize = sizeof(HEAPLIST32)
    success = _Heap32ListFirst(hSnapshot, byref(hl))
    if not success:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return hl

# BOOL WINAPI Heap32ListNext(
#   __in     HANDLE hSnapshot,
#   __out  LPHEAPLIST32 lphl
# );
def Heap32ListNext(hSnapshot, hl = None):
    _Heap32ListNext = windll.kernel32.Heap32ListNext
    _Heap32ListNext.argtypes = [HANDLE, LPHEAPLIST32]
    _Heap32ListNext.restype  = bool

    if hl is None:
        hl = HEAPLIST32()
    hl.dwSize = sizeof(HEAPLIST32)
    success = _Heap32ListNext(hSnapshot, byref(hl))
    if not success:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return hl


# BOOL WINAPI Thread32First(
#   __in     HANDLE hSnapshot,
#   __inout  LPTHREADENTRY32 lpte
# );
def Thread32First(hSnapshot):
    _Thread32First = windll.kernel32.Thread32First
    _Thread32First.argtypes = [HANDLE, LPTHREADENTRY32]
    _Thread32First.restype  = bool

    te = THREADENTRY32()
    te.dwSize = sizeof(THREADENTRY32)
    success = _Thread32First(hSnapshot, byref(te))
    if not success:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return te

# BOOL WINAPI Thread32Next(
#   __in     HANDLE hSnapshot,
#   __out  LPTHREADENTRY32 lpte
# );
def Thread32Next(hSnapshot, te = None):
    _Thread32Next = windll.kernel32.Thread32Next
    _Thread32Next.argtypes = [HANDLE, LPTHREADENTRY32]
    _Thread32Next.restype  = bool

    if te is None:
        te = THREADENTRY32()
    te.dwSize = sizeof(THREADENTRY32)
    success = _Thread32Next(hSnapshot, byref(te))
    if not success:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return te