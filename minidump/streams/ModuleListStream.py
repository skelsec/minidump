#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import io
from minidump.common_structs import * 

class MinidumpModule:
	def __init__(self):
		self.name = None
		self.baseaddress = None
		self.size = None
		self.endaddress = None
		
		self.versioninfo = None
		self.checksum = None
		self.timestamp = None
		
		
	def parse(mod, buff):
		"""
		mod: MINIDUMP_MODULE
		buff: file handle
		"""
		mm = MinidumpModule()
		mm.baseaddress = mod.BaseOfImage
		mm.size = mod.SizeOfImage
		mm.checksum = mod.CheckSum
		mm.timestamp = mod.TimeDateStamp
		mm.name = MINIDUMP_STRING.get_from_rva(mod.ModuleNameRva, buff)
		mm.versioninfo = mod.VersionInfo
		mm.endaddress = mm.baseaddress + mm.size
		return mm
		
	def inrange(self, memory_loc):
		return self.baseaddress <= memory_loc < self.endaddress
		
	def get_header():
		return [
			'Module name',
			'BaseAddress',
			'Size',
			'Endaddress',
		]
	
	def to_row(self):
		return [
			str(self.name),
			'0x%08x' % self.baseaddress,
			hex(self.size),
			'0x%08x' % self.endaddress,
		]
		
		
	def __str__(self):
		return 'Module name: %s BaseAddress: 0x%08x Size: 0x%x Endaddress: 0x%08x' % (self.name, self.baseaddress, self.size, self.endaddress)
		
# https://msdn.microsoft.com/en-us/library/windows/desktop/ms646997(v=vs.85).aspx
class VS_FIXEDFILEINFO:
	def __init__(self):
		self.dwSignature = None
		self.dwStrucVersion = None
		self.dwFileVersionMS = None
		self.dwFileVersionLS = None
		self.dwProductVersionMS = None
		self.dwProductVersionLS = None
		self.dwFileFlagsMask = None
		self.dwFileFlags = None
		self.dwFileOS = None
		self.dwFileType = None
		self.dwFileSubtype = None
		self.dwFileDateMS = None
		self.dwFileDateLS = None
		
	@staticmethod
	def parse(buff):
		vf = VS_FIXEDFILEINFO()
		vf.dwSignature = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		vf.dwStrucVersion = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		vf.dwFileVersionMS = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		vf.dwFileVersionLS = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		vf.dwProductVersionMS = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		vf.dwProductVersionLS = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		vf.dwFileFlagsMask = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		vf.dwFileFlags = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		vf.dwFileOS = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		vf.dwFileType = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		vf.dwFileSubtype = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		vf.dwFileDateMS = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		vf.dwFileDateLS = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		return vf

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680392(v=vs.85).aspx
class MINIDUMP_MODULE:
	def __init__(self):
		self.BaseOfImage = None
		self.SizeOfImage = None
		self.CheckSum = None
		self.TimeDateStamp = None
		self.ModuleNameRva = None
		self.VersionInfo = None
		self.CvRecord = None
		self.MiscRecord = None
		self.Reserved0 = None
		self.Reserved1 = None
		
	@staticmethod
	def parse(buff):
		mm = MINIDUMP_MODULE()
		mm.BaseOfImage = int.from_bytes(buff.read(8), byteorder = 'little', signed = False)
		mm.SizeOfImage = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mm.CheckSum = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mm.TimeDateStamp = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mm.ModuleNameRva = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mm.VersionInfo = VS_FIXEDFILEINFO.parse(buff)
		mm.CvRecord = MINIDUMP_LOCATION_DESCRIPTOR.parse(buff)
		mm.MiscRecord = MINIDUMP_LOCATION_DESCRIPTOR.parse(buff)
		mm.Reserved0 = int.from_bytes(buff.read(8), byteorder = 'little', signed = False)
		mm.Reserved1 = int.from_bytes(buff.read(8), byteorder = 'little', signed = False)
		return mm
  
# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680391(v=vs.85).aspx
class MINIDUMP_MODULE_LIST:
	def __init__(self):
		self.NumberOfModules = None
		self.Modules = []
	
	@staticmethod
	def parse(buff):
		mml = MINIDUMP_MODULE_LIST()
		mml.NumberOfModules = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		for i in range(mml.NumberOfModules):
			mml.Modules.append(MINIDUMP_MODULE.parse(buff))
			
		return mml
		
class MinidumpModuleList:
	def __init__(self):
		self.modules = []
		
	def parse(dir, buff):
		t = MinidumpModuleList()
		buff.seek(dir.Location.Rva)
		chunk = io.BytesIO(buff.read(dir.Location.DataSize))
		mtl = MINIDUMP_MODULE_LIST.parse(chunk)
		for mod in mtl.Modules:
			t.modules.append(MinidumpModule.parse(mod, buff))
		return t
		
	def to_table(self):
		t = []
		t.append(MinidumpModule.get_header())
		for mod in self.modules:
			t.append(mod.to_row())
		return t
		
	def __str__(self):
		t  = '== ModuleList ==\n' + construct_table(self.to_table())
		return t
		