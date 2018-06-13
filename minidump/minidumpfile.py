#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import sys
import enum
import struct
import logging

from .exceptions import *
from .minidumpreader import *
from .common_structs import *
from .streams import *


class MINIDUMP_STREAM_TYPE(enum.Enum):
	UnusedStream			   = 0
	ReservedStream0			= 1
	ReservedStream1			= 2
	ThreadListStream		   = 3
	ModuleListStream		   = 4
	MemoryListStream		   = 5
	ExceptionStream			= 6
	SystemInfoStream		   = 7
	ThreadExListStream		 = 8
	Memory64ListStream		 = 9
	CommentStreamA			 = 10
	CommentStreamW			 = 11
	HandleDataStream		   = 12
	FunctionTableStream		= 13
	UnloadedModuleListStream   = 14
	MiscInfoStream			 = 15
	MemoryInfoListStream	   = 16
	ThreadInfoListStream	   = 17
	HandleOperationListStream  = 18
	TokenStream = 19
	JavaScriptDataStream = 20
	SystemMemoryInfoStream = 21
	ProcessVmCountersStream = 22
	LastReservedStream		 = 0xffff
	
class MINIDUMP_TYPE(enum.IntFlag): 
	MiniDumpNormal						  = 0x00000000
	MiniDumpWithDataSegs					= 0x00000001
	MiniDumpWithFullMemory				  = 0x00000002
	MiniDumpWithHandleData				  = 0x00000004
	MiniDumpFilterMemory					= 0x00000008
	MiniDumpScanMemory					  = 0x00000010
	MiniDumpWithUnloadedModules			 = 0x00000020
	MiniDumpWithIndirectlyReferencedMemory  = 0x00000040
	MiniDumpFilterModulePaths			   = 0x00000080
	MiniDumpWithProcessThreadData		   = 0x00000100
	MiniDumpWithPrivateReadWriteMemory	  = 0x00000200
	MiniDumpWithoutOptionalData			 = 0x00000400
	MiniDumpWithFullMemoryInfo			  = 0x00000800
	MiniDumpWithThreadInfo				  = 0x00001000
	MiniDumpWithCodeSegs					= 0x00002000
	MiniDumpWithoutAuxiliaryState		   = 0x00004000
	MiniDumpWithFullAuxiliaryState		  = 0x00008000
	MiniDumpWithPrivateWriteCopyMemory	  = 0x00010000
	MiniDumpIgnoreInaccessibleMemory		= 0x00020000
	MiniDumpWithTokenInformation			= 0x00040000
	MiniDumpWithModuleHeaders			   = 0x00080000
	MiniDumpFilterTriage					= 0x00100000
	MiniDumpValidTypeFlags				  = 0x001fffff
		
class MINIDUMP_DIRECTORY:
	def __init__(self):
		self.StreamType = None
		self.Location = None
	
	@staticmethod
	def parse(buff):
		md = MINIDUMP_DIRECTORY()
		md.StreamType = MINIDUMP_STREAM_TYPE(int.from_bytes(buff.read(4), byteorder = 'little', signed = False))
		md.Location = MINIDUMP_LOCATION_DESCRIPTOR.parse(buff)
		return md
		
	def __str__(self):
		t = 'StreamType: %s %s' % (self.StreamType, self.Location)
		return t

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680378(v=vs.85).aspx
class MinidumpHeader:
	def __init__(self):
		self.Signature = None
		self.Version = None
		self.ImplementationVersion = None
		self.NumberOfStreams = None
		self.StreamDirectoryRva = None
		self.CheckSum = None
		self.Reserved = None
		self.TimeDateStamp = None
		self.Flags = None
		
	@staticmethod
	def parse(buff):
		mh = MinidumpHeader()
		mh.Signature = buff.read(4).decode()[::-1]
		if mh.Signature != 'PMDM':
			raise MinidumpHeaderSignatureMismatchException(mh.Signature)
		mh.Version = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
		mh.ImplementationVersion = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
		mh.NumberOfStreams = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mh.StreamDirectoryRva = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mh.CheckSum = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mh.Reserved = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mh.TimeDateStamp = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		try:
			mh.Flags = MINIDUMP_TYPE(int.from_bytes(buff.read(8), byteorder = 'little', signed = False))
		except Exception as e:
			raise MinidumpHeaderFlagsException('Could not parse header flags!')
			
		return mh
		
	def __str__(self):
		t = '== MinidumpHeader ==\n'
		t+= 'Signature: %s\n' % self.Signature
		t+= 'Version: %s\n' % self.Version
		t+= 'ImplementationVersion: %s\n' % self.ImplementationVersion
		t+= 'NumberOfStreams: %s\n' % self.NumberOfStreams
		t+= 'StreamDirectoryRva: %s\n' % self.StreamDirectoryRva
		t+= 'CheckSum: %s\n' % self.CheckSum
		t+= 'Reserved: %s\n' % self.Reserved
		t+= 'TimeDateStamp: %s\n' % self.TimeDateStamp
		t+= 'Flags: %s\n' % self.Flags
		return t		

class MinidumpFile:
	def __init__(self):
		self.filename = None
		self.file_handle = None
		self.header = None
		self.directories = []
		
		self.threads_ex = None
		self.threads = None
		self.modules = None
		self.memory_segments = None
		self.memory_segments_64 = None
		self.sysinfo = None
		self.comment_a = None
		self.comment_w = None
		self.handles = None
		self.unloaded_modules = None
		self.misc_info = None
		self.memory_info = None
		self.thread_info = None

		
	@staticmethod
	def parse(filename):
		mf = MinidumpFile()
		mf.filename = filename
		mf.file_handle = open(filename, 'rb')
		mf._parse()
		return mf
		
	def get_reader(self):
		return MinidumpFileReader(self)
		
	def _parse(self):
		self.__parse_header()
		self.__parse_directories()
			
	def __parse_header(self):
		self.header = MinidumpHeader.parse(self.file_handle)
		for i in range(0, self.header.NumberOfStreams):
			self.file_handle.seek(self.header.StreamDirectoryRva + i * 12, 0 )
			self.directories.append(MINIDUMP_DIRECTORY.parse(self.file_handle))
	
			
	def __parse_directories(self):
		for dir in self.directories:
			if dir.StreamType == MINIDUMP_STREAM_TYPE.UnusedStream:
				logging.debug('Found UnusedStream @%x Size: %d' % (dir.Location.Rva, dir.Location.DataSize))
				continue # Reserved. Do not use this enumeration value.
			elif dir.StreamType == MINIDUMP_STREAM_TYPE.ReservedStream0:
				logging.debug('Found ReservedStream0 @%x Size: %d' % (dir.Location.Rva, dir.Location.DataSize))
				continue # Reserved. Do not use this enumeration value.
			elif dir.StreamType == MINIDUMP_STREAM_TYPE.ReservedStream1:
				logging.debug('Found ReservedStream1 @%x Size: %d' % (dir.Location.Rva, dir.Location.DataSize))
				continue # Reserved. Do not use this enumeration value.
			elif dir.StreamType == MINIDUMP_STREAM_TYPE.ThreadListStream:
				logging.debug('Found ThreadListStream @%x Size: %d' % (dir.Location.Rva, dir.Location.DataSize))
				self.threads = MinidumpThreadList.parse(dir, self.file_handle)
				continue
			elif dir.StreamType == MINIDUMP_STREAM_TYPE.ModuleListStream:
				logging.debug('Found ModuleListStream @%x Size: %d' % (dir.Location.Rva, dir.Location.DataSize))
				self.modules = MinidumpModuleList.parse(dir, self.file_handle)
				#logging.debug(str(modules_list))
				continue
			elif dir.StreamType == MINIDUMP_STREAM_TYPE.MemoryListStream:
				logging.debug('Found MemoryListStream @%x Size: %d' % (dir.Location.Rva, dir.Location.DataSize))
				self.memory_segments = MinidumpMemoryList.parse(dir, self.file_handle)
				#logging.debug(str(self.memory_segments))
				continue
			elif dir.StreamType == MINIDUMP_STREAM_TYPE.SystemInfoStream:
				logging.debug('Found SystemInfoStream @%x Size: %d' % (dir.Location.Rva, dir.Location.DataSize))
				self.sysinfo = MinidumpSystemInfo.parse(dir, self.file_handle)
				#logging.debug(str(self.sysinfo))
				continue
			elif dir.StreamType == MINIDUMP_STREAM_TYPE.ThreadExListStream:
				logging.debug('Found ThreadExListStream @%x Size: %d' % (dir.Location.Rva, dir.Location.DataSize))
				self.threads_ex = MinidumpThreadExList.parse(dir, self.file_handle)
				#logging.debug(str(self.threads_ex))
				continue
			elif dir.StreamType == MINIDUMP_STREAM_TYPE.Memory64ListStream:
				logging.debug('Found Memory64ListStream @%x Size: %d' % (dir.Location.Rva, dir.Location.DataSize))
				self.memory_segments_64 = MinidumpMemory64List.parse(dir, self.file_handle)
				#logging.debug(str(self.memory_segments_64))
				continue
			elif dir.StreamType == MINIDUMP_STREAM_TYPE.CommentStreamA:
				logging.debug('Found CommentStreamA @%x Size: %d' % (dir.Location.Rva, dir.Location.DataSize))
				self.comment_a = CommentStreamA.parse(dir, self.file_handle)
				#logging.debug(str(self.comment_a))
				continue
			elif dir.StreamType == MINIDUMP_STREAM_TYPE.CommentStreamW:
				logging.debug('Found CommentStreamW @%x Size: %d' % (dir.Location.Rva, dir.Location.DataSize))
				self.comment_w = CommentStreamW.parse(dir, self.file_handle)
				#logging.debug(str(self.comment_w))
				continue
			elif dir.StreamType == MINIDUMP_STREAM_TYPE.HandleDataStream:
				logging.debug('Found HandleDataStream @%x Size: %d' % (dir.Location.Rva, dir.Location.DataSize))
				self.handles = MinidumpHandleDataStream.parse(dir, self.file_handle)
				#logging.debug(str(self.handles))
				continue
			
			elif dir.StreamType == MINIDUMP_STREAM_TYPE.FunctionTableStream:
				logging.debug('Found FunctionTableStream @%x Size: %d' % (dir.Location.Rva, dir.Location.DataSize))
				logging.debug('Parsing of this stream type is not yet implemented!')
				continue
			
			elif dir.StreamType == MINIDUMP_STREAM_TYPE.UnloadedModuleListStream:
				logging.debug('Found UnloadedModuleListStream @%x Size: %d' % (dir.Location.Rva, dir.Location.DataSize))
				self.unloaded_modules = MinidumpUnloadedModuleList.parse(dir, self.file_handle)
				#logging.debug(str(self.unloaded_modules))
				continue
			elif dir.StreamType == MINIDUMP_STREAM_TYPE.MiscInfoStream:
				logging.debug('Found MiscInfoStream @%x Size: %d' % (dir.Location.Rva, dir.Location.DataSize))
				self.misc_info = MinidumpMiscInfo.parse(dir, self.file_handle)
				#logging.debug(str(self.misc_info))
				continue
			elif dir.StreamType == MINIDUMP_STREAM_TYPE.MemoryInfoListStream:
				logging.debug('Found MemoryInfoListStream @%x Size: %d' % (dir.Location.Rva, dir.Location.DataSize))
				self.memory_info = MinidumpMemoryInfoList.parse(dir, self.file_handle)
				#logging.debug(str(self.memory_info))
				continue
			elif dir.StreamType == MINIDUMP_STREAM_TYPE.ThreadInfoListStream:
				logging.debug('Found ThreadInfoListStream @%x Size: %d' % (dir.Location.Rva, dir.Location.DataSize))
				self.thread_info = MinidumpThreadInfoList.parse(dir, self.file_handle)
				logging.debug(str(self.thread_info))
				continue
			elif dir.StreamType == MINIDUMP_STREAM_TYPE.SystemMemoryInfoStream:
				logging.debug('Found SystemMemoryInfoStream @%x Size: %d' % (dir.Location.Rva, dir.Location.DataSize))
				logging.debug('SystemMemoryInfoStream parsing is not implemented (Missing documentation)')
				continue
				
			elif dir.StreamType == MINIDUMP_STREAM_TYPE.JavaScriptDataStream:
				logging.debug('Found JavaScriptDataStream @%x Size: %d' % (dir.Location.Rva, dir.Location.DataSize))
				logging.debug('JavaScriptDataStream parsing is not implemented (Missing documentation)')
				
			elif dir.StreamType == MINIDUMP_STREAM_TYPE.ProcessVmCountersStream:
				logging.debug('Found ProcessVmCountersStream @%x Size: %d' % (dir.Location.Rva, dir.Location.DataSize))
				logging.debug('ProcessVmCountersStream parsing is not implemented (Missing documentation)')
				
			elif dir.StreamType == MINIDUMP_STREAM_TYPE.TokenStream:
				logging.debug('Found TokenStream @%x Size: %d' % (dir.Location.Rva, dir.Location.DataSize))
				logging.debug('TokenStream parsing is not implemented (Missing documentation)')
				
			else:
				logging.debug('Found Unknown Stream! Type: %s @%x Size: %d' % (dir.StreamType.name, dir.Location.Rva, dir.Location.DataSize))
				
			"""
			elif dir.StreamType == MINIDUMP_STREAM_TYPE.HandleOperationListStream:
			elif dir.StreamType == MINIDUMP_STREAM_TYPE.LastReservedStream:
			elif dir.StreamType == MINIDUMP_STREAM_TYPE.ExceptionStream:
			"""			
		
	def __str__(self):
		t = '== Minidump File ==\n'
		t += str(self.header)
		t += str(self.sysinfo)
		for dir in self.directories:
			t += str(dir) + '\n'
		for mod in self.modules:
			t += str(mod) + '\n'
		for segment in self.memorysegments:
			t+= str(segment) + '\n'
		
		return t
