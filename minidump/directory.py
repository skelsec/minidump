
from minidump.constants import MINIDUMP_STREAM_TYPE
from minidump.common_structs import MINIDUMP_LOCATION_DESCRIPTOR

class MINIDUMP_DIRECTORY:
	def __init__(self):
		self.StreamType:MINIDUMP_STREAM_TYPE = None
		self.Location:MINIDUMP_LOCATION_DESCRIPTOR = None

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

		# StreamType values over 0xffff are MINIDUMP_USER_STREAM streams, whose format
		# depends on the client that created the minidump, and some writers also emit
		# non-standard types inside the reserved range (e.g. Wine/Proton crash dumps
		# contain stream type 0xFFF0). As per the documentation, unknown stream types
		# should be ignored : https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/ne-minidumpapiset-minidumminidump_dirp_stream_type#remarks
		is_stream_supported = raw_stream_type_value in MINIDUMP_STREAM_TYPE._value2member_map_
		if not is_stream_supported:
			return None

		md = MINIDUMP_DIRECTORY()
		md.StreamType = MINIDUMP_STREAM_TYPE(raw_stream_type_value)
		md.Location = MINIDUMP_LOCATION_DESCRIPTOR.parse(buff)
		return md

	@staticmethod
	async def aparse(buff):

		t = await buff.read(4)
		raw_stream_type_value = int.from_bytes(t, byteorder = 'little', signed = False)

		# StreamType values over 0xffff are MINIDUMP_USER_STREAM streams, whose format
		# depends on the client that created the minidump, and some writers also emit
		# non-standard types inside the reserved range (e.g. Wine/Proton crash dumps
		# contain stream type 0xFFF0). As per the documentation, unknown stream types
		# should be ignored : https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/ne-minidumpapiset-minidumminidump_dirp_stream_type#remarks
		is_stream_supported = raw_stream_type_value in MINIDUMP_STREAM_TYPE._value2member_map_
		if not is_stream_supported:
			return None

		md = MINIDUMP_DIRECTORY()
		md.StreamType = MINIDUMP_STREAM_TYPE(raw_stream_type_value)
		md.Location = await MINIDUMP_LOCATION_DESCRIPTOR.aparse(buff)
		return md

	def __str__(self):
		t = 'StreamType: %s %s' % (self.StreamType, self.Location)
		return t