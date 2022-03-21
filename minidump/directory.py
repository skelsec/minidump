
from minidump.constants import MINIDUMP_STREAM_TYPE
from minidump.common_structs import MINIDUMP_LOCATION_DESCRIPTOR

import io

class MINIDUMP_DIRECTORY:
	def __init__(self):
		self.StreamType = None
		self.Location = None

	def to_buffer(self, buffer):
		"""
		Locaton must be set for the correct location in the databuffer!
		"""
		buffer.write(self.to_bytes())

	def to_bytes(self):
		t = self.StreamType.value.to_bytes(4, byteorder = 'little', signed = False)
		t += self.Location.to_bytes()
		return t

	@staticmethod
	def get_stream_type_value(buff, peek=False):
		return int.from_bytes(buff.read(4), byteorder = 'little', signed = False)

	@staticmethod
	def parse(buff):

		raw_stream_type_value = MINIDUMP_DIRECTORY.get_stream_type_value(buff)

		# StreamType value that are over 0xffff are considered MINIDUMP_USER_STREAM streams
		# and their format depends on the client used to create the minidump.
		# As per the documentation, this stream should be ignored : https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/ne-minidumpapiset-minidumminidump_dirp_stream_type#remarks
		is_user_stream = raw_stream_type_value > MINIDUMP_STREAM_TYPE.LastReservedStream.value
		is_stream_supported = raw_stream_type_value in MINIDUMP_STREAM_TYPE._value2member_map_
		if is_user_stream and not is_stream_supported:
			return None

		md = MINIDUMP_DIRECTORY()
		md.StreamType = MINIDUMP_STREAM_TYPE(raw_stream_type_value)
		md.Location = MINIDUMP_LOCATION_DESCRIPTOR.parse(buff)
		return md

	@staticmethod
	async def aparse(buff):
		
		t = await buff.read(4)
		raw_stream_type_value = int.from_bytes(t, byteorder = 'little', signed = False)

		# StreamType value that are over 0xffff are considered MINIDUMP_USER_STREAM streams
		# and their format depends on the client used to create the minidump.
		# As per the documentation, this stream should be ignored : https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/ne-minidumpapiset-minidumminidump_dirp_stream_type#remarks
		is_user_stream = raw_stream_type_value > MINIDUMP_STREAM_TYPE.LastReservedStream.value
		is_stream_supported = raw_stream_type_value in MINIDUMP_STREAM_TYPE._value2member_map_
		if is_user_stream and not is_stream_supported:
			return None

		md = MINIDUMP_DIRECTORY()
		md.StreamType = MINIDUMP_STREAM_TYPE(raw_stream_type_value)
		md.Location = await MINIDUMP_LOCATION_DESCRIPTOR.aparse(buff)
		return md

	def __str__(self):
		t = 'StreamType: %s %s' % (self.StreamType, self.Location)
		return t


class DirectoryBuffer:
	def __init__(self, offset = 0):
		self.offset = offset
		self.buffer = io.BytesIO()
		self.databuffer = io.BytesIO()

		self.rvas = [] #ptr_position_in_buffer, data_pos_in_databuffer
		self.lds = [] # pos, size

	def write_rva(self, data):
		"""
		Stores the data in databuffer and returns an RVA position relative to buffer's start
		"""
		#pos = self.buffer.tell() + self.databuffer.tell() + self.offset
		#self.databuffer.write(data)
		#self.buffer.write(pos.to_bytes(4, byteorder = 'little', signed = False))
		
		data_pos = self.databuffer.tell()
		self.databuffer.write(data)
		ptr_pos = self.buffer.tell()
		self.buffer.write(b'\x00' * 4)
		self.rvas.append((ptr_pos, data_pos))
		return

	def write_ld(self, data):
		#"""
		#writes a location descriptor to the buffer and the actual data to the databuffer
		#"""

		#pos = self.buffer.tell() + self.databuffer.tell() + self.offset
		#ld = MINIDUMP_LOCATION_DESCRIPTOR(len(data), pos)
		#self.databuffer.write(data)
		#self.buffer.write(ld.to_bytes())
		
		data_pos = self.databuffer.tell()
		self.databuffer.write(data)
		ptr_pos = self.buffer.tell()
		self.buffer.write(MINIDUMP_LOCATION_DESCRIPTOR(0,0).to_bytes())
		self.lds.append((ptr_pos, data_pos, len(data)))
		
		return

	def write_data(self, data):
		return self.databuffer.write(data)

	def write(self, data):
		return self.buffer.write(data)
	
	def tell(self):
		return self.buffer.tell()

	def seek(self, pos, whence):
		print('Seek is not advised!')
		return self.buffer.seek(pos, whence)

	def read(self, count = 1):
		return self.buffer.read(count)

	def finalize(self):
		self.databuffer.seek(0,0)
		buffer_end = self.buffer.tell() + self.offset
		for ptr_pos, data_pos in self.rvas:
			final_pos = data_pos + buffer_end - 0x10 # TODO! figure out the offset?
			self.buffer.seek(ptr_pos)
			self.buffer.write(final_pos.to_bytes(4, byteorder ='little', signed= False))

		for ptr_pos, data_pos, data_size in self.lds:
			final_pos = data_pos + buffer_end - 0x10 # TODO! figure out the offset?
			self.buffer.seek(ptr_pos)
			self.buffer.write(MINIDUMP_LOCATION_DESCRIPTOR(data_size, final_pos).to_bytes())

		self.buffer.write(self.databuffer.read())
		self.databuffer = None
		self.buffer.seek(0,0)
		return self.buffer.read()



		
			