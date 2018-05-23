
# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680383(v=vs.85).aspx	
class MINIDUMP_LOCATION_DESCRIPTOR:
	def __init__(self):
		self.DataSize = None
		self.Rva = None
	
	@staticmethod
	def parse(buff):
		mld = MINIDUMP_LOCATION_DESCRIPTOR()
		mld.DataSize = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mld.Rva = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		return mld
	
	def __str__(self):
		t = 'Size: %s File offset: %s' % (self.DataSize, self.Rva)
		return t
		
class MINIDUMP_LOCATION_DESCRIPTOR64:
	def __init__(self):
		self.DataSize = None
		self.Rva = None
	
	@staticmethod
	def parse(buff):
		mld = MINIDUMP_LOCATION_DESCRIPTOR64()
		mld.DataSize = int.from_bytes(buff.read(8), byteorder = 'little', signed = False)
		mld.Rva = int.from_bytes(buff.read(8), byteorder = 'little', signed = False)
		return mld
	
	def __str__(self):
		t = 'Size: %s File offset: %s' % (self.DataSize, self.Rva)
		return t
		
class MINIDUMP_STRING:
	def __init__(self):
		self.Length = None
		self.Buffer = None
	
	@staticmethod
	def parse(buff):
		ms = MINIDUMP_STRING()
		ms.Length = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		ms.Buffer = buff.read(ms.Length)
		return ms
		
	@staticmethod
	def get_from_rva(rva, buff):
		pos = buff.tell()
		buff.seek(rva, 0)
		ms = MINIDUMP_STRING.parse(buff)
		buff.seek(pos, 0)
		return ms.Buffer.decode('utf-16-le')
		
class MinidumpMemorySegment:
	def __init__(self):
		self.start_virtual_address = None
		self.size = None
		self.end_virtual_address = None
		self.start_file_address = None
		
	def parse_mini(memory_decriptor, buff):
		"""
		memory_descriptor: MINIDUMP_MEMORY_DESCRIPTOR
		buff: file_handle
		"""
		mms = MinidumpMemorySegment()
		mms.start_virtual_address = memory_decriptor.StartOfMemoryRange
		mms.size = memory_decriptor.Memory.DataSize
		mms.start_file_address = memory_decriptor.Memory.Rva
		mms.end_virtual_address = mms.start_virtual_address + mms.size
		return mms
		
	def parse_full(memory_decriptor, buff, rva):
		mms = MinidumpMemorySegment()
		mms.start_virtual_address = memory_decriptor.StartOfMemoryRange
		mms.size = memory_decriptor.DataSize
		mms.start_file_address = rva
		mms.end_virtual_address = mms.start_virtual_address + mms.size
		return mms
		
		
	def inrange(self, virt_addr):
		if virt_addr >= self.start_virtual_address and virt_addr < self.end_virtual_address:
			return True
		return False
	def read(self, virtual_address, size, file_handler):
		if virtual_address > self.end_virtual_address or virtual_address < self.start_virtual_address:
			raise Exception('Reading from wrong segment!')
		
		if virtual_address+size > self.end_virtual_address:
			raise Exception('Read would cross boundaries!')
		
		pos = file_handler.tell()
		offset = virtual_address - self.start_virtual_address
		file_handler.seek(self.start_file_address + offset, 0)
		data = file_handler.read(size)
		file_handler.seek(pos, 0)
		return data
		
	def search(self, pattern, file_handler):
		if len(pattern) > self.size:
			return []
		pos = file_handler.tell()
		file_handler.seek(self.start_file_address, 0)
		data = file_handler.read(self.size)
		file_handler.seek(pos, 0)
		fl = []
		offset = 0
		while len(data) > len(pattern):
			marker = data.find(pattern)
			if marker == -1:
				return fl
			fl.append(marker + offset + self.start_virtual_address)
			data = data[marker+1:]
			offset = marker + 1
				
		return fl
		
	def __str__(self):
		t = 'VA Start: %s, RVA: %s, Size: %s' % (hex(self.start_virtual_address), hex(self.start_file_address), hex(self.size))
		return t
		
		

def hexdump( src, length=16, sep='.', start = 0):
	'''
	@brief Return {src} in hex dump.
	@param[in] length	{Int} Nb Bytes by row.
	@param[in] sep		{Char} For the text part, {sep} will be used for non ASCII char.
	@return {Str} The hexdump

	@note Full support for python2 and python3 !
	'''
	result = [];

	# Python3 support
	try:
		xrange(0,1);
	except NameError:
		xrange = range;

	for i in xrange(0, len(src), length):
		subSrc = src[i:i+length];
		hexa = '';
		isMiddle = False;
		for h in xrange(0,len(subSrc)):
			if h == length/2:
				hexa += ' ';
			h = subSrc[h];
			if not isinstance(h, int):
				h = ord(h);
			h = hex(h).replace('0x','');
			if len(h) == 1:
				h = '0'+h;
			hexa += h+' ';
		hexa = hexa.strip(' ');
		text = '';
		for c in subSrc:
			if not isinstance(c, int):
				c = ord(c);
			if 0x20 <= c < 0x7F:
				text += chr(c);
			else:
				text += sep;
		if start == 0:
			result.append(('%08X:  %-'+str(length*(2+1)+1)+'s  |%s|') % (i, hexa, text));
		else:
			result.append(('%08X+%08X:  %-'+str(length*(2+1)+1)+'s  |%s|') % (start, i, hexa, text));
	return '\n'.join(result);