from minidump.constants import MINIDUMP_STREAM_TYPE, MINIDUMP_TYPE
from minidump.header import MinidumpHeader
from minidump.common_structs import MINIDUMP_LOCATION_DESCRIPTOR
from minidump.utils.privileges import enable_debug_privilege

from minidump.utils.winapi.version import GetSystemInfo, GetVersionExW
from minidump.utils.winapi.kernel32 import OpenProcess, PROCESS_ALL_ACCESS, VirtualQueryEx, ReadProcessMemory, CreateToolhelp32Snapshot, Thread32First, Thread32Next
from minidump.utils.winapi.psapi import EnumProcessModules, GetModuleInformation, GetModuleFileNameExW
from minidump.utils.winapi.version import GetFileVersionInfoW
from minidump.streams import MINIDUMP_SYSTEM_INFO, PROCESSOR_ARCHITECTURE, MINIDUMP_MODULE_LIST, \
	MINIDUMP_MODULE, VS_FIXEDFILEINFO, MINIDUMP_MEMORY_INFO_LIST, MINIDUMP_MEMORY_INFO, \
	AllocationProtect, MemoryType, MemoryState, \
	MINIDUMP_MEMORY64_LIST, MINIDUMP_MEMORY_DESCRIPTOR64, MINIDUMP_MEMORY_DESCRIPTOR

from minidump.streams.SystemInfoStream import PROCESSOR_ARCHITECTURE, PRODUCT_TYPE
from minidump.streams.UnloadedModuleListStream import MINIDUMP_UNLOADED_MODULE_LIST
from minidump.streams.HandleDataStream import MINIDUMP_HANDLE_DATA_STREAM
from minidump.streams.ThreadInfoListStream import MINIDUMP_THREAD_INFO_LIST
from minidump.streams.ThreadListStream import MINIDUMP_THREAD_LIST, MINIDUMP_THREAD

from minidump.directory import MINIDUMP_DIRECTORY

import io
		

class MinidumpSystemReader:
	def __init__(self):
		pass

	def setup(self):
		pass

	def get_sysinfo(self, databuffer):
		pass

	def get_modules(self, databuffer):
		pass

	def get_sections(self, databuffer):
		pass

	def get_memory(self, buffer):
		pass

	def get_threads(self, databuffer):
		pass

	def get_exceptions(self, databuffer):
		pass

class LiveSystemReader(MinidumpSystemReader):
	def __init__(self, pid):
		MinidumpSystemReader.__init__(self)
		self.pid = pid
		self.process_handle = None
		self.process_toolhelp_handle = None
		self.sysinfo = None
		self.meminfolist = None

		# TODO: implement more streams. The currently implemented streams are the 'bare minimum' for windbg
		self.streamtypes = [
			MINIDUMP_STREAM_TYPE.SystemInfoStream, 
			MINIDUMP_STREAM_TYPE.ModuleListStream, 
			MINIDUMP_STREAM_TYPE.ThreadListStream,
			# MINIDUMP_STREAM_TYPE.ThreadInfoListStream,
			# MINIDUMP_STREAM_TYPE.UnloadedModuleListStream,
			# MINIDUMP_STREAM_TYPE.HandleDataStream,
			MINIDUMP_STREAM_TYPE.MemoryInfoListStream, 
			MINIDUMP_STREAM_TYPE.Memory64ListStream,
		]

		self.setup()

	def get_available_directories(self):
		sts = []
		for st in self.streamtypes:
			memdir = MINIDUMP_DIRECTORY()
			memdir.Location = None #location is not needed, only the type
			memdir.StreamType = st
			sts.append(memdir)
		return sts

	def open_process(self):
		self.process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)

	def open_toolhelp(self):
		self.process_toolhelp_handle = CreateToolhelp32Snapshot(th32ProcessID = self.pid)

	def setup(self):
		self.open_process()
		self.open_toolhelp()

	def get_sysinfo(self, databuffer):
		#https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsysteminfo
		sysinfo_raw = GetSystemInfo()
		version_raw = GetVersionExW()

		sysinfo = MINIDUMP_SYSTEM_INFO()
		sysinfo.ProcessorArchitecture = PROCESSOR_ARCHITECTURE(sysinfo_raw.id.w.wProcessorArchitecture)
		sysinfo.ProcessorLevel = sysinfo_raw.wProcessorLevel
		sysinfo.ProcessorRevision = sysinfo_raw.wProcessorRevision
		#sysinfo.Reserved0 = None
		sysinfo.NumberOfProcessors = sysinfo_raw.dwNumberOfProcessors
		sysinfo.ProductType = PRODUCT_TYPE(version_raw.wProductType)
		sysinfo.MajorVersion = version_raw.dwMajorVersion
		sysinfo.MinorVersion = version_raw.dwMinorVersion
		sysinfo.BuildNumber = version_raw.dwBuildNumber
		sysinfo.PlatformId = version_raw.dwPlatformId
		sysinfo.CSDVersionRva = 0
		#sysinfo.Reserved1 = None
		sysinfo.SuiteMask = version_raw.wSuiteMask
		#sysinfo.Reserved2 = None

		sysinfo.CSDVersion = None #version_raw.szCSDVersion

		#below todo, keeping all zeroes for now..
		if sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.INTEL:
			sysinfo.VendorId = [0,0,0]
			sysinfo.VersionInformation = 0
			sysinfo.FeatureInformation = 0
			sysinfo.AMDExtendedCpuFeatures = 0
		else:
			sysinfo.ProcessorFeatures = [0,0]
		
		self.sysinfo_raw = sysinfo_raw #other functions will be using data from sysinfo so we need to store it!
		#p1 = databuffer.tell()
		sysinfo.to_buffer(databuffer)
		#input('Sysinfo size: %s' % (databuffer.tell() - p1))
	
	def get_threadinfo(self, databuffer):
		ti = MINIDUMP_THREAD_INFO_LIST()
		ti.NumberOfEntries = 0
		ti.to_buffer(databuffer)

	def get_handle_data(self, databuffer):
		hds = MINIDUMP_HANDLE_DATA_STREAM()
		hds.NumberOfDescriptors = 0
		hds.to_buffer(databuffer)

	def get_unloaded_modules(self, databuffer):
		#TODO: implement this. problem: finding an api call that differentiates between loaded and unloaded modules
		# currently returning empty list
		umodlist = MINIDUMP_UNLOADED_MODULE_LIST()
		umodlist.NumberOfEntries = 0
		umodlist.to_buffer(databuffer)

	def get_modules(self, databuffer):
		#https://docs.microsoft.com/en-us/windows/win32/psapi/enumerating-all-modules-for-a-process
		#https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocessmodules
		#
		module_list = MINIDUMP_MODULE_LIST()
		for module in EnumProcessModules(self.process_handle):
			#print(module)
			modinfo = GetModuleInformation(self.process_handle,module)
			modname = GetModuleFileNameExW(self.process_handle,module)
			#print(modname)
			try:
				fileversion_raw = GetFileVersionInfoW(modname)
				fileversion = VS_FIXEDFILEINFO.from_bytes(fileversion_raw.raw[8+(16*2):])
				ts = fileversion.dwFileDateMS << 32 + fileversion.dwFileDateLS
			except Exception as e:
				print("Failed to get fileversion! Reason: %s " % e)
				fileversion = None
				ts = 0
			
			mmod = MINIDUMP_MODULE()
			mmod.BaseOfImage = modinfo.lpBaseOfDll
			mmod.SizeOfImage = modinfo.SizeOfImage
			mmod.TimeDateStamp = ts
			mmod.ModuleNameRva = None
			mmod.VersionInfo = fileversion
			mmod.CvRecord = None # TODO?
			mmod.MiscRecord = None # TODO?

			mmod.ModuleName = modname

			module_list.Modules.append(mmod)
		
		module_list.to_buffer(databuffer)

	def get_sections(self, databuffer):
		#https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex
		meminfolist = MINIDUMP_MEMORY_INFO_LIST()
		i = self.sysinfo_raw.lpMinimumApplicationAddress
		while i < self.sysinfo_raw.lpMaximumApplicationAddress:
			mi_raw = VirtualQueryEx(self.process_handle, i)
			mi = MINIDUMP_MEMORY_INFO()
			mi.BaseAddress = mi_raw.BaseAddress
			mi.AllocationBase = mi_raw.AllocationBase
			mi.AllocationProtect = mi_raw.AllocationProtect
			mi.RegionSize = mi_raw.RegionSize
			try:
				mi.State = MemoryState(mi_raw.State)
			except:
				mi.State = mi_raw.State
			try:
				mi.Protect = AllocationProtect(mi_raw.Protect)
			except:
				mi.Protect = mi_raw.Protect
			try:
				mi.Type = MemoryType(mi_raw.Type)
			except:
				mi.Type = mi_raw.Type

			meminfolist.entries.append(mi)
			print(str(mi))
			
			i += mi_raw.RegionSize
		self.meminfolist = meminfolist
		meminfolist.to_buffer(databuffer)
	
	def get_threads(self, databuffer):
		tl = MINIDUMP_THREAD_LIST()
		for thread_number in range(2):
			mt = MINIDUMP_THREAD()
			mt.ThreadId = 4 * (thread_number + 1)
			mt.SuspendCount = 0
			mt.PriorityClass = 0
			mt.Priority = 40
			# TODO: get thread teb
			# TODO: get thread context so windbg's stack trace works
			mt.Teb = 0
			tl.Threads.append(mt)

		tl.to_buffer(databuffer)

	def get_exceptions(self, databuffer):
		pass

	def get_memory(self, buffer):
		read_flags = [AllocationProtect.PAGE_EXECUTE_READ,
				AllocationProtect.PAGE_EXECUTE_READWRITE,
				AllocationProtect.PAGE_READONLY,
				AllocationProtect.PAGE_EXECUTE,
				AllocationProtect.PAGE_READWRITE,
				AllocationProtect.PAGE_WRITECOPY
		]
		memlist = MINIDUMP_MEMORY64_LIST()
		memlist.BaseRva = 0 # TODO: check if this is correct!
		for section in self.meminfolist.entries:
			if section.Protect in read_flags:
				memdesc = MINIDUMP_MEMORY_DESCRIPTOR64()
				memdesc.StartOfMemoryRange = section.BaseAddress
				memdesc.DataSize = section.RegionSize
				memlist.MemoryRanges.append(memdesc)

		memlist_rva_placeholder_loc = buffer.tell() + 8
		memlist.to_buffer(buffer)
		memlist_rva = buffer.tell()

		buffer.seek(memlist_rva_placeholder_loc, 0)
		buffer.write(memlist_rva.to_bytes(8, byteorder = 'little', signed = False))
		buffer.seek(memlist_rva, 0)


		for section in self.meminfolist.entries:
			if section.Protect in read_flags:
				data = ReadProcessMemory(self.process_handle, section.BaseAddress, section.RegionSize)
				if section.RegionSize > len(data):
					data += b'\x00' * (section.RegionSize + len(data))
				buffer.write(data)

		return (len(memlist.MemoryRanges) + 1) * 0x10


if __name__ == '__main__':
	import sys
	from minidump.minidumpfile import MinidumpFile
	pid = int(sys.argv[1])
	print(pid)
	enable_debug_privilege()
	sysreader = LiveSystemReader(pid)
	with open('test_new.dmp', 'wb') as f:
		mf = MinidumpFile()
		mf.writer = sysreader
		mf.to_buffer(f)

