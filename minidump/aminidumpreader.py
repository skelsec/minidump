#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import struct
import ntpath
from .common_structs import *
from .streams.SystemInfoStream import PROCESSOR_ARCHITECTURE

class AMinidumpBufferedMemorySegment:
	def __init__(self):
		self.start_address = None
		self.end_address = None
		self.data = None

	async def load(self, memory_segment, file_handle):
		self.start_address = memory_segment.start_virtual_address
		self.end_address = memory_segment.end_virtual_address
		await file_handle.seek(memory_segment.start_file_address)
		self.data = await file_handle.read(memory_segment.size)

	def inrange(self, position):
		return self.start_address <= position <= self.end_address

	def remaining_len(self, position):
		if not self.inrange(position):
			return None
		return self.end_address - position

class AMinidumpBufferedReader:
	def __init__(self, reader):
		self.reader = reader
		self.memory_segments = []

		self.current_segment = None
		self.current_position = None

	async def _select_segment(self, requested_position):
		"""

		"""
		# check if we have semgnet for requested address in cache
		for memory_segment in self.memory_segments:
			if memory_segment.inrange(requested_position):
				self.current_segment = memory_segment
				self.current_position = requested_position
				return

		# not in cache, check if it's present in memory space. if yes then create a new buffered memeory object, and copy data
		for memory_segment in self.reader.memory_segments:
			if memory_segment.inrange(requested_position):
				newsegment = AMinidumpBufferedMemorySegment()
				await newsegment.load(memory_segment, self.reader.file_handle)
				self.memory_segments.append(newsegment)
				self.current_segment = newsegment
				self.current_position = requested_position
				return

		raise Exception('Memory address 0x%08x is not in process memory space' % requested_position)

	async def seek(self, offset, whence = 0):
		"""
		Changes the current address to an offset of offset. The whence parameter controls from which position should we count the offsets.
		0: beginning of the current memory segment
		1: from current position
		2: from the end of the current memory segment
		If you wish to move out from the segment, use the 'move' function
		"""
		if whence == 0:
			t = self.current_segment.start_address + offset
		elif whence == 1:
			t = self.current_position + offset
		elif whence == 2:
			t = self.current_segment.end_address - offset
		else:
			raise Exception('Seek function whence value must be between 0-2')

		if not self.current_segment.inrange(t):
			raise Exception('Seek would cross memory segment boundaries (use move)')

		self.current_position = t
		return

	async def move(self, address):
		"""
		Moves the buffer to a virtual address specified by address
		"""
		await self._select_segment(address)
		return

	async def align(self, alignment = None):
		"""
		Repositions the current reader to match architecture alignment
		"""
		if alignment is None:
			if self.reader.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.AMD64:
				alignment = 8
			else:
				alignment = 4
		offset = self.current_position % alignment
		if offset == 0:
			return
		offset_to_aligned = (alignment - offset) % alignment
		await self.seek(offset_to_aligned, 1)
		return

	def tell(self):
		"""
		Returns the current virtual address
		"""
		return self.current_position

	async def peek(self, length):
		"""
		Returns up to length bytes from the current memory segment
		"""
		t = self.current_position + length
		if not self.current_segment.inrange(t):
			raise Exception('Would read over segment boundaries!')
		return self.current_segment.data[self.current_position - self.current_segment.start_address :t - self.current_segment.start_address]

	async def read(self, size = -1):
		"""
		Returns data bytes of size size from the current segment. If size is -1 it returns all the remaining data bytes from memory segment
		"""
		if size < -1:
			raise Exception('You shouldnt be doing this')
		if size == -1:
			t = self.current_segment.remaining_len(self.current_position)
			if not t:
				return None

			old_new_pos = self.current_position
			self.current_position = self.current_segment.end_address
			return self.current_segment.data[old_new_pos - self.current_segment.start_address:]

		t = self.current_position + size
		if not self.current_segment.inrange(t):
			raise Exception('Would read over segment boundaries!')

		old_new_pos = self.current_position
		self.current_position = t
		return self.current_segment.data[old_new_pos - self.current_segment.start_address :t - self.current_segment.start_address]

	async def read_int(self):
		"""
		Reads an integer. The size depends on the architecture.
		Reads a 4 byte small-endian singed int on 32 bit arch
		Reads an 8 byte small-endian singed int on 64 bit arch
		"""
		if self.reader.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.AMD64:
			t = await self.read(8)
			return int.from_bytes(t, byteorder = 'little', signed = True)
		else:
			t = t = await self.read(4)
			return int.from_bytes(t, byteorder = 'little', signed = True)

	async def read_uint(self):
		"""
		Reads an integer. The size depends on the architecture.
		Reads a 4 byte small-endian unsinged int on 32 bit arch
		Reads an 8 byte small-endian unsinged int on 64 bit arch
		"""
		if self.reader.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.AMD64:
			t = await self.read(8)
			return int.from_bytes(t, byteorder = 'little', signed = False)
		else:
			t = await self.read(4)
			return int.from_bytes(t, byteorder = 'little', signed = False)

	async def find(self, pattern):
		"""
		Searches for a pattern in the current memory segment
		"""
		pos = self.current_segment.data.find(pattern)
		if pos == -1:
			return -1
		return pos + self.current_position

	async def find_all(self, pattern):
		"""
		Searches for all occurrences of a pattern in the current memory segment, returns all occurrences as a list
		"""
		pos = []
		last_found = -1
		while True:
			last_found = self.current_segment.data.find(pattern, last_found + 1)
			if last_found == -1:
				break
			pos.append(last_found + self.current_segment.start_address)

		return pos

	async def find_global(self, pattern):
		"""
		Searches for the pattern in the whole process memory space and returns the first occurrence.
		This is exhaustive!
		"""
		pos_s = await self.reader.search(pattern)
		if len(pos_s) == 0:
			return -1

		return pos_s[0]

	async def find_all_global(self, pattern):
		"""
		Searches for the pattern in the whole process memory space and returns a list of addresses where the pattern begins.
		This is exhaustive!
		"""
		return await self.reader.search(pattern)

	async def get_ptr(self, pos):
		await self.move(pos)
		return await self.read_uint()
		#raw_data = self.read(pos, self.sizeof_ptr)
		#return struct.unpack(self.unpack_ptr, raw_data)[0]

	async def get_ptr_with_offset(self, pos):
		if self.reader.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.AMD64:
			await self.move(pos)
			t = await self.read(4)
			ptr = int.from_bytes(t, byteorder = 'little', signed = True)
			return pos + 4 + ptr
		else:
			await self.move(pos)
			return await self.read_uint()

	async def find_in_module(self, module_name, pattern):
		t = await self.reader.search_module(module_name, pattern)
		return t




class AMinidumpFileReader:
	def __init__(self, minidumpfile):
		self.modules = minidumpfile.modules.modules
		self.sysinfo = minidumpfile.sysinfo

		if minidumpfile.memory_segments_64:
			self.memory_segments = minidumpfile.memory_segments_64.memory_segments
			self.is_fulldump = True

		else:
			self.memory_segments = minidumpfile.memory_segments.memory_segments
			self.is_fulldump = False

		self.filename = minidumpfile.filename
		self.file_handle = minidumpfile.file_handle

		#reader params
		self.sizeof_long = 4
		self.unpack_long = '<L'
		if minidumpfile.sysinfo.ProcessorArchitecture in [PROCESSOR_ARCHITECTURE.AMD64, PROCESSOR_ARCHITECTURE.AARCH64]:
			self.sizeof_ptr = 8
			self.unpack_ptr = '<Q'
		elif self.sysinfo.ProcessorArchitecture in [PROCESSOR_ARCHITECTURE.INTEL,
				PROCESSOR_ARCHITECTURE.ARM]:
			self.sizeof_ptr = 4
			self.unpack_ptr = '<L'
		else:
			raise Exception('Unknown processor architecture %s! Please fix and submit PR!' % self.sysinfo.ProcessorArchitecture)

	def get_buffered_reader(self):
		return AMinidumpBufferedReader(self)

	def get_module_by_name(self, module_name):
		for mod in self.modules:
			if ntpath.basename(mod.name).find(module_name) != -1:
				return mod
		return None

	async def search_module(self, module_name, pattern):
		mod = self.get_module_by_name(module_name)
		if mod is None:
			raise Exception('Could not find module! %s' % module_name)
		t = []
		for ms in self.memory_segments:
			if mod.baseaddress <= ms.start_virtual_address < mod.endaddress:
				t += await ms.asearch(pattern, self.file_handle)

		return t

	async def search(self, pattern):
		t = []
		for ms in self.memory_segments:
			t += await ms.asearch(pattern, self.file_handle)

		return t

	async def read(self, virt_addr, size):
		for segment in self.memory_segments:
			if segment.inrange(virt_addr):
				return await segment.aread(virt_addr, size, self.file_handle)
		raise Exception('Address not in memory range! %s' % hex(virt_addr))

