#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import struct
from .common_structs import * 
from .streams.SystemInfoStream import PROCESSOR_ARCHITECTURE

class MinidumpFileReader:
	def __init__(self, minidumpfile):
		self.modules = minidumpfile.modules.modules
		self.memory_segments = minidumpfile.memory_segments_64.memory_segments
		self.sysinfo = minidumpfile.sysinfo
		
		self.filename = minidumpfile.filename
		self.file_handle = minidumpfile.file_handle
		
		#reader params
		self.sizeof_long = 4
		self.unpack_long = '<L'
		if minidumpfile.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.AMD64:
			self.sizeof_ptr = 8
			self.unpack_ptr = '<Q'
		elif self.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.INTEL:
			self.sizeof_ptr = 4
			self.unpack_ptr = '<L'
		else:
			raise Exception('Unknown processor architecture %s! Please fix and submit PR!' % self.sysinfo.ProcessorArchitecture)
	
	def get_module_by_name(self, module_name):
		for mod in self.modules:
			if mod.name.find(module_name) != -1:
				return mod
		return None
	
	def search_module(self, module_name, pattern):
		mod = self.get_module_by_name(module_name)
		if mod is None:
			raise Exception('Could not find module! %s' % module_name)
		t = []
		for ms in self.memory_segments:
			if mod.baseaddress <= ms.start_virtual_address < mod.endaddress:
				t+= ms.search(pattern, self.file_handle)
			
		return t
		
	def search(self, pattern):
		t = []
		for ms in self.memory_segments:
			t+= ms.search(pattern, self.file_handle)
			
		return t
		
	def read(self, virt_addr, size):
		for segment in self.memory_segments:
			if segment.inrange(virt_addr):
				return segment.read(virt_addr, size, self.file_handle)
		raise Exception('Address not in memory range! %s' % hex(virt_addr))
		
		
	def get_ptr(self, pos):
		raw_data = self.read(pos, self.sizeof_ptr)
		return struct.unpack(self.unpack_ptr, raw_data)[0]
	
	def get_ptr_with_offset(self, pos):
		if self.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.AMD64:
			raw_data = self.read(pos, self.sizeof_long)
			ptr = struct.unpack(self.unpack_long, raw_data)[0]
			return pos + self.sizeof_long + ptr
		else:
			raw_data = self.read(pos, self.sizeof_long)
			return struct.unpack(self.unpack_long, raw_data)[0]
