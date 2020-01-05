#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import io
import sys
import enum
import struct
import logging

from minidump.header import MinidumpHeader
from minidump.minidumpreader import MinidumpFileReader
from minidump.streams import *
from minidump.common_structs import *
from minidump.constants import MINIDUMP_STREAM_TYPE
from minidump.directory import MINIDUMP_DIRECTORY
from minidump.constants import MINIDUMP_TYPE

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
		self.exception = None
		self.handles = None
		self.unloaded_modules = None
		self.misc_info = None
		self.memory_info = None
		self.thread_info = None

		self.writer = None

	def to_buffer(self, buffer):
		"""
		Serializes the contents of the minidumpfile to a buffer/file handle
		Writer must be already specified!
		"""
		databuffer = io.BytesIO() # data buffer is where the actual directory data will be stored, except the full memory dump!
		mem64_present = False
		mem_present = False

		self.header = MinidumpHeader()
		self.header.Version = 1
		self.header.ImplementationVersion = 1
		self.header.NumberOfStreams = len([self.writer.get_available_directories])
		self.header.Flags = MINIDUMP_TYPE.MiniDumpWithFullMemory
		
		hdr_bytes = self.header.to_bytes()
		buffer.write(hdr_bytes)
		databuffer.write(b'\x00' * len(hdr_bytes))
		for directory in self.writer.get_available_directories:
			databuffer.write(b'\x00' * 8)
		
		for directory in self.writer.get_available_directories:
			directory.Location = databuffer.tell()
			if directory.StreamType == MINIDUMP_STREAM_TYPE.SystemInfoStream:
				self.writer.get_sysinfo(databuffer)
			elif directory.StreamType == MINIDUMP_STREAM_TYPE.ModuleListStream:
				self.writer.get_modules(databuffer)
			elif directory.StreamType == MINIDUMP_STREAM_TYPE.MemoryInfoListStream:
				self.writer.get_sections(databuffer)
			elif directory.StreamType == MINIDUMP_STREAM_TYPE.Memory64ListStream:
				mem64_present = True
				continue #skipping this!
			elif directory.StreamType == MINIDUMP_STREAM_TYPE.MemoryListStream:
				mem_present = True
				continue #skipping this!

			directory.to_buffer(buffer)

		if mem64_present is True:
			# if memory is present, we add one more directory entry to the directory list, and finalize the header
			memdir = MINIDUMP_DIRECTORY()
			memdir.Location = databuffer.tell()
			memdir.StreamType = MINIDUMP_STREAM_TYPE.Memory64ListStream
			memdir.to_buffer(buffer)
			databuffer.seek(0,0)
			buffer.write(databuffer.read())
			self.writer.get_memory(buffer) # here we use the merged buffer (or the actual file) because memory to dump might be huge
			return

		elif mem_present is True:
			raise Exception('Not yet implemented!')

	@staticmethod
	def parse(filename):
		mf = MinidumpFile()
		mf.filename = filename
		mf.file_handle = open(filename, 'rb')
		mf._parse()
		return mf

	@staticmethod
	def parse_external(file_handle, filename = ''):
		"""
		External file handle must be an object that exposes basic file IO functionality
		that you'd get by python's file buffer (read, seek, tell etc.)
		"""
		mf = MinidumpFile()
		mf.filename = filename
		mf.file_handle = file_handle
		mf._parse()
		return mf

	@staticmethod
	def parse_bytes(data):
		return MinidumpFile.parse_buff(io.BytesIO(data))

	@staticmethod
	def parse_buff(buffer):
		mf = MinidumpFile()
		mf.file_handle = buffer
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
			minidump_dir = MINIDUMP_DIRECTORY.parse(self.file_handle)
			
			if minidump_dir:
				self.directories.append(minidump_dir)
			else:
				self.file_handle.seek(self.header.StreamDirectoryRva + i * 12, 0 )
				user_stream_type_value = MINIDUMP_DIRECTORY.get_stream_type_value(self.file_handle)
				logging.debug('Found Unknown UserStream directory Type: %x' % (user_stream_type_value))

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
			elif dir.StreamType == MINIDUMP_STREAM_TYPE.ExceptionStream:
				logging.debug('Found ExceptionStream @%x Size: %d' % (dir.Location.Rva, dir.Location.DataSize))
				self.exception = ExceptionList.parse(dir, self.file_handle)
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
			
			"""

	def __str__(self):
		t = '== Minidump File ==\n'
		t += str(self.header)
		t += str(self.sysinfo)
		for dir in self.directories:
			t += str(dir) + '\n'
		for mod in self.modules:
			t += str(mod) + '\n'
		if self.memory_segments is not None:
			for segment in self.memory_segments:
				t+= str(segment) + '\n'

		if self.memory_segments_64 is not None:
			for segment in self.memory_segments_64:
				t+= str(segment) + '\n'

		return t
