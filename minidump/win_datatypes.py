
# https://msdn.microsoft.com/en-us/library/windows/desktop/aa383751(v=vs.85).aspx

class POINTER:
	def __init__(self, finaltype):
		self.finaltype = finaltype
		
	def read(self, reader, override_finaltype = None):
		pos = reader.tell()
		reader.move(self.value)
		if override_finaltype:
			data = override_finaltype(reader)
		else:
			data = self.finaltype(reader)
		reader.move(pos)
		return data
		
class PVOID(POINTER):
	def __init__(self, reader):
		super().__init__(None) #with void we cannot determine the final type
		self.value = reader.read_uint()
		
class BOOL:
	def __init__(self, reader):
		self.value = bool(reader.read_uint())
		
class BOOLEAN:
	def __init__(self, reader):
		self.value = reader.read(1)
		
class BYTE:
	def __init__(self, reader):
		self.value = reader.read(1)

class CCHAR:
	def __init__(self, reader):
		self.value = reader.read(1).decode('ascii')
		
class CHAR:
	def __init__(self, reader):
		self.value = reader.read(1).decode('ascii')
		
class DWORD:
	def __init__(self, reader):
		self.value = int.from_bytes(reader.read(4), byteorder = 'little', signed = False)
		
class DWORDLONG:
	def __init__(self, reader):
		self.value = int.from_bytes(reader.read(8), byteorder = 'little', signed = False)
		
class DWORD_PTR(POINTER):
	def __init__(self, reader):
		super().__init__(DWORD)
		self.value = reader.read_uint()
		
class DWORD32:
	def __init__(self, reader):
		self.value = int.from_bytes(reader.read(4), byteorder = 'little', signed = False)

class DWORD64:
	def __init__(self, reader):
		self.value = int.from_bytes(reader.read(8), byteorder = 'little', signed = False)		

"""
class FLOAT:
	def __init__(self, reader):
		self.value = int.from_bytes(reader.read(8), byteorder = 'little', signed = False)			

class HALF_PTR(POINTER):
	def __init__(self, reader):
		self.value = reader.read_uint()		
"""

		
class HANDLE:
	def __init__(self, reader):
		self.value = reader.read_uint()
		
class HFILE:
	def __init__(self, reader):
		self.value = int.from_bytes(reader.read(4), byteorder = 'little', signed = False)
		
class HINSTANCE:
	def __init__(self, reader):
		self.value = reader.read_uint()		
		

class HKEY:
	def __init__(self, reader):
		self.value = reader.read_uint()


class HKL:
	def __init__(self, reader):
		self.value = reader.read_uint()
		
class HLOCAL:
	def __init__(self, reader):
		self.value = reader.read_uint()

class INT:
	def __init__(self, reader):
		self.value = reader.read_int()

class INT_PTR(POINTER):
	def __init__(self, reader):
		super().__init__(INT)
		self.value = reader.read_int()

class INT8:
	def __init__(self, reader):
		self.value = int.from_bytes(reader.read(1), byteorder = 'little', signed = True)

class INT16:
	def __init__(self, reader):
		self.value = int.from_bytes(reader.read(2), byteorder = 'little', signed = True)

class INT32:
	def __init__(self, reader):
		self.value = int.from_bytes(reader.read(4), byteorder = 'little', signed = True)

class INT64:
	def __init__(self, reader):
		self.value = int.from_bytes(reader.read(8), byteorder = 'little', signed = True)

class LONG:
	def __init__(self, reader):
		self.value = int.from_bytes(reader.read(4), byteorder = 'little', signed = True)

class LONGLONG:
	def __init__(self, reader):
		self.value = int.from_bytes(reader.read(8), byteorder = 'little', signed = True)

class LONG_PTR(POINTER):
	def __init__(self, reader):
		super().__init__(LONG)
		self.value = reader.read_uint()

class LONG32:
	def __init__(self, reader):
		self.value = int.from_bytes(reader.read(8), byteorder = 'little', signed = True)

class LONG64():
	def __init__(self, reader):
		self.value = int.from_bytes(reader.read(8), byteorder = 'little', signed = True)

class LPARAM(POINTER):
	def __init__(self, reader):
		super().__init__(LONG)
		self.value = reader.read_uint()

class LPBOOL(POINTER):
	def __init__(self, reader):
		super().__init__(BOOL)
		self.value = reader.read_uint()

class LPBYTE(POINTER):
	def __init__(self, reader):
		super().__init__(BYTE)
		self.value = reader.read_uint()	
"""
class LPCSTR(POINTER):
	def __init__(self, reader):
		super().__init__(STR)
		self.value = reader.read_uint()			
		
class LPCTSTR(POINTER):
	def __init__(self, reader):
		super().__init__(LPCTSTR)
		self.value = reader.read_uint()	
	
class STR:
	def __init__(self, reader):
		self.value = reader.read_uint()			
"""	
class ULONG:
	def __init__(self, reader):
		self.value = int.from_bytes(reader.read(4), byteorder = 'little', signed = False)
		
class ULONGLONG:
	def __init__(self, reader):
		self.value = int.from_bytes(reader.read(8), byteorder = 'little', signed = False)

class ULONG32:
	def __init__(self, reader):
		self.value = int.from_bytes(reader.read(4), byteorder = 'little', signed = False)
		
class ULONG64:
	def __init__(self, reader):
		self.value = int.from_bytes(reader.read(8), byteorder = 'little', signed = False)
		
class PWSTR(POINTER):
	def __init__(self, reader):
		super().__init__(None)
		self.value = reader.read_uint()
		
class PCHAR(POINTER):
	def __init__(self, reader):
		super().__init__(CHAR)
		self.value = reader.read_uint()
		
class USHORT:
	def __init__(self, reader):
		self.value = int.from_bytes(reader.read(2), byteorder = 'little', signed = False)