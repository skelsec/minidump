from minidump.constants import MINIDUMP_STREAM_TYPE, MINIDUMP_TYPE
from minidump.header import MinidumpHeader
from minidump.common_structs import MINIDUMP_LOCATION_DESCRIPTOR

from minidump.utils.winapi.version import GetSystemInfo, GetVersionExW
from minidump.utils.winapi.kernel32 import OpenProcess, PROCESS_ALL_ACCESS
from minidump.streams import MINIDUMP_SYSTEM_INFO, PROCESSOR_ARCHITECTURE

import io

class MinidumpSystemReader:
	def __init__(self):
		pass

	def setup(self):
		pass

	def get_sysinfo(self):
		pass

	def get_modules(self):
		pass

	def get_sections(self):
		pass

	def get_memory(self):
		pass

	def get_threads(self):
		pass

	def get_exceptions(self):
		pass

class LiveSystemReader(MinidumpSystemReader):
	def __init__(self, pid):
		MinidumpSystemReader.__init__(self)
		self.pid = pid
		self.process_handle = None

		self.setup()

	def open_process(self):
		self.process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)

	def setup(self):
		self.open_process()

	def get_sysinfo(self):
		#https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsysteminfo
		sysinfo_raw = GetSystemInfo()
		version_raw = GetVersionExW()

		sysinfo = MINIDUMP_SYSTEM_INFO()
		sysinfo.ProcessorArchitecture = sysinfo_raw.id.w.wProcessorArchitecture
		sysinfo.ProcessorLevel = sysinfo_raw.wProcessorLevel
		sysinfo.ProcessorRevision = sysinfo_raw.wProcessorRevision
		#sysinfo.Reserved0 = None
		sysinfo.NumberOfProcessors = sysinfo_raw.dwNumberOfProcessors
		sysinfo.ProductType = version_raw.wProductType
		sysinfo.MajorVersion = version_raw.dwMajorVersion
		sysinfo.MinorVersion = version_raw.dwMinorVersion
		sysinfo.BuildNumber = version_raw.dwBuildNumber
		sysinfo.PlatformId = version_raw.dwPlatformId
		sysinfo.CSDVersionRva = 0
		#sysinfo.Reserved1 = None
		sysinfo.SuiteMask = version_raw.wSuiteMask
		#sysinfo.Reserved2 = None

		sysinfo.CSDVersion = version_raw.szCSDVersion

		#below todo, keeping all zeroes for now..
		if sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.INTEL:
			sysinfo.VendorId = [0,0,0]
			sysinfo.VersionInformation = 0
			sysinfo.FeatureInformation = 0
			sysinfo.AMDExtendedCpuFeatures = 0
		else:
			sysinfo.ProcessorFeatures = [0,0]

		return sysinfo


	def get_modules(self, hdr_buff, data_buff):
		#https://docs.microsoft.com/en-us/windows/win32/psapi/enumerating-all-modules-for-a-process
		#https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocessmodules
		#
		pass

	def get_sections(self, hdr_buff, data_buff):
		#https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex
		pass

	def get_memory(self, hdr_buff, data_buff):
		pass

	def get_threads(self, hdr_buff, data_buff):
		pass

	def get_exceptions(self, hdr_buff, data_buff):
		pass


class MinidumpWriter:
	def __init__(self,sysreader):
		self.sysreader = sysreader
		self.output_file = None

		self.streams = {} #stream type -> list of stream objects

		self.header = None
		self.directory = []

	def create_streams(self):
		sysinfo = self.sysreader.get_sysinfo(self)
		self.streams[MINIDUMP_STREAM_TYPE.SystemInfoStream] = sysinfo
		
		
	#def get_total_streams_cnt(self):
	#	total = 0
	#	for t in self.streams:
	#		total += len(t)
	#	return total

	def construct_header(self):
		self.header = MinidumpHeader()
		self.header.Version = 1
		self.header.ImplementationVersion = 1
		self.header.NumberOfStreams = self.stream_cnt
		self.header.StreamDirectoryRva = 28
		#self.header.CheckSum = None
		#self.header.Reserved = None
		#self.header.TimeDateStamp = None
		self.header.Flags = MINIDUMP_TYPE.MiniDumpWithFullMemory

		return self.header.to_bytes()

		

	#def construct_directory(self):
	#
	#	total_streams = self.get_total_streams_cnt()
	#
	#	for stype in self.streams:			
	#		for stream in self.streams[stype]:
	#			
	#			stream
	#
	#			loc = MINIDUMP_LOCATION_DESCRIPTOR()
	#			loc.DataSize = 0
	#			loc.Rva = 0
	#			directory = MINIDUMP_DIRECTORY()
	#			directory.StreamType = stream
	#			self.directory.append()


	def write_header(self):
		hdr_pos = self.hdr_buff.tell()
		self.hdr_buff.seek(0,0)
		self.hdr_buff.write(self.construct_header())
		self.hdr_buff.seek(hdr_pos, 0)
		return


	def construct_directory(self):
		self.sysreader.get_sysinfo(self.hdr_buff, self.data_buff)
		self.stream_cnt += 1
		#modules
		#self.sysreader.get_modules(self.hdr_buff, self.data_buff)
		#self.stream_cnt += 1
		
		#write header
		self.write_header()
		

		#append datastream for memory, with correct rva
		
		#dump memory

	def run(self):
		return


if __name__ == '__main__':
	sysreader = LiveSystemReader(1)
	writer = MinidumpWriter(sysreader)
	writer.run()
