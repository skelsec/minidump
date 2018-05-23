#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import io
import enum
from minidump.common_structs import * 

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680372(v=vs.85).aspx
class MINIDUMP_HANDLE_DATA_STREAM:
	def __init__(self):
		self.SizeOfHeader = None
		self.SizeOfDescriptor = None
		self.NumberOfDescriptors = None
		self.Reserved = None
		
	def parse(buff):
		mhds = MINIDUMP_HANDLE_DATA_STREAM()
		mhds.SizeOfHeader = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mhds.SizeOfDescriptor = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mhds.NumberOfDescriptors = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mhds.Reserved = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
			
		return mhds
	
# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680374(v=vs.85).aspx
class MINIDUMP_HANDLE_DESCRIPTOR:
	size = 32
	def __init__(self):
		self.Handle = None
		self.TypeNameRva = None
		self.ObjectNameRva = None
		self.Attributes = None
		self.GrantedAccess = None
		self.HandleCount = None
		self.PointerCount = None
	
	def parse(buff):
		mhd = MINIDUMP_HANDLE_DESCRIPTOR()
		mhd.Handle = int.from_bytes(buff.read(8), byteorder = 'little', signed = False)
		mhd.TypeNameRva = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mhd.ObjectNameRva = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mhd.Attributes = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mhd.GrantedAccess = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mhd.HandleCount = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mhd.PointerCount = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		
		return mhd
		
# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680373(v=vs.85).aspx
class MINIDUMP_HANDLE_DESCRIPTOR_2:	
	def __init__(self):
		self.Handle = None
		self.TypeNameRva = None
		self.ObjectNameRva = None
		self.Attributes = None
		self.GrantedAccess = None
		self.HandleCount = None
		self.PointerCount = None
		self.ObjectInfoRva = None
		self.Reserved0 = None
	
	def parse(buff):
		mhd = MINIDUMP_HANDLE_DESCRIPTOR_2()
		mhd.Handle = int.from_bytes(buff.read(8), byteorder = 'little', signed = False)
		mhd.TypeNameRva = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mhd.ObjectNameRva = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mhd.Attributes = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mhd.GrantedAccess = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mhd.HandleCount = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mhd.PointerCount = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mhd.ObjectInfoRva = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mhd.Reserved0 = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		return mhd

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680376(v=vs.85).aspx
class MINIDUMP_HANDLE_OBJECT_INFORMATION_TYPE(enum.Enum): 
	MiniHandleObjectInformationNone = 0
	MiniThreadInformation1 = 1
	MiniMutantInformation1 = 2
	MiniMutantInformation2 = 3
	MiniProcessInformation1 = 4
	MiniProcessInformation2 = 5
	

class MINIDUMP_HANDLE_OBJECT_INFORMATION:
	def __init__(self):
		self.NextInfoRva = None
		self.InfoType = None
		self.SizeOfInfo = None
		
		#high-level, delete this when documentation becomes available!
		self.info_bytes = None
	
	def parse(buff):
		mhoi = MINIDUMP_HANDLE_OBJECT_INFORMATION()
		mhoi.NextInfoRva = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mhoi.InfoType = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mhoi.SizeOfInfo = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mhoi.info_bytes = buff.read(mhoi.SizeOfInfo)
		return mhoi
		
class MinidumpHandleObjectInformation:
	def __init__(self):
		self.NextInfo = None
		self.InfoType = None
		self.SizeOfInfo = None
		self.info_bytes = None
		
	def parse(mhoi, buff):
		t = MinidumpHandleObjectInformation()
		t.InfoType = mhoi.InfoType
		t.SizeOfInfo = mhoi.SizeOfInfo
		t.info_bytes = mhoi.info_bytes
		return t
	
	def __str__(self):
		return self.info_bytes.hex()
	
	
		
class MinidumpHandleDescriptor:
	def __init__(self):
		self.Handle = None
		self.TypeName = None
		self.ObjectName = None
		self.Attributes = None
		self.GrantedAccess = None
		self.HandleCount = None
		self.PointerCount = None
		self.ObjectInfos = []
	
	def parse(t, buff):
		mhd = MinidumpHandleDescriptor()
		mhd.Handle = t.Handle
		if t.TypeNameRva != 0:
			mhd.TypeName = MINIDUMP_STRING.get_from_rva(t.TypeNameRva, buff)
		if t.ObjectNameRva != 0:
			mhd.ObjectName = MINIDUMP_STRING.get_from_rva(t.ObjectNameRva, buff)
		mhd.Attributes = t.Attributes
		mhd.GrantedAccess = t.GrantedAccess
		mhd.HandleCount = t.HandleCount
		mhd.PointerCount = t.PointerCount
		if isinstance(t, MINIDUMP_HANDLE_DESCRIPTOR_2):
			if t.ObjectInfoRva is not None and t.ObjectInfoRva != 0:
				MinidumpHandleDescriptor.walk_objectinfo(mhd, t.ObjectInfoRva, buff)
		return mhd
		
	def walk_objectinfo(mhd, start, buff):
		while start is not None and start != 0:
			buff.seek(start)
			mhoi = MINIDUMP_HANDLE_OBJECT_INFORMATION.parse(buff)
			t = MinidumpHandleObjectInformation.parse(mhoi, buff)
			mhd.ObjectInfos.append(t)
			start = t.NextInfo
		
		
	def __str__(self):
		t = '== MinidumpHandleDescriptor == \n'
		t += 'Handle 0x%08x ' % self.Handle
		t += 'TypeName %s ' % self.TypeName
		t += 'ObjectName %s ' % self.ObjectName
		t += 'Attributes %s ' % self.Attributes
		t += 'GrantedAccess %s ' % self.GrantedAccess
		t += 'HandleCount %s ' % self.HandleCount
		t += 'PointerCount %s ' % self.PointerCount
		for oi in self.ObjectInfos:
			t += str(oi)
		return t
		
class MinidumpHandleDataStream:
	def __init__(self):
		self.header = None
		self.handles = []
		
	def parse(dir, buff):
		t = MinidumpHandleDataStream()
		buff.seek(dir.Location.Rva)
		chunk = io.BytesIO(buff.read(dir.Location.DataSize))
		t.header = MINIDUMP_HANDLE_DATA_STREAM.parse(chunk)
		for i in range(t.header.NumberOfDescriptors):
			if t.header.SizeOfDescriptor == MINIDUMP_HANDLE_DESCRIPTOR.size:
				mhd = MINIDUMP_HANDLE_DESCRIPTOR.parse(chunk)
				t.handles.append(MinidumpHandleDescriptor.parse(mhd, buff))
			else:
				mhd = MINIDUMP_HANDLE_DESCRIPTOR_2.parse(chunk)
				t.handles.append(MinidumpHandleDescriptor.parse(mhd, buff))
		return t
		
	def __str__(self):
		t  = '== MinidumpHandleDataStream ==\n'
		for handle in self.handles:
			t += str(handle)
		return t