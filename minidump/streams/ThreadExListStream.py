#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

from minidump.common_structs import * 

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680399(v=vs.85).aspx
class MINIDUMP_THREAD_EX_LIST:
	def __init__(self):
		self.NumberOfThreads = None
		self.Threads = []
	
	def parse(buff):
		mtel = MINIDUMP_THREAD_EX_LIST()
		mtel.NumberOfThreads = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		for i in range(mtle.NumberOfThreads):
			mtel.Threads.append(MINIDUMP_THREAD_EX.parse(buff))
		
		return mtel
		
# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680400(v=vs.85).aspx
class MINIDUMP_THREAD_EX:
	def __init__(self):
		self.ThreadId = None
		self.SuspendCount = None
		self.PriorityClass = None
		self.Priority = None
		self.Teb = None
		self.Stack = None
		self.ThreadContext = None
		self.BackingStore = None
		
	def parse(buff):
		mte = MINIDUMP_THREAD_EX()
		mte.ThreadId = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mte.SuspendCount = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mte.PriorityClass = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mte.Priority = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mte.Teb = int.from_bytes(buff.read(8), byteorder = 'little', signed = False)
		mte.Stack = MINIDUMP_MEMORY_DESCRIPTOR.parse(buff)
		mte.ThreadContext = MINIDUMP_LOCATION_DESCRIPTOR.parse(buff)
		mte.BackingStore = MINIDUMP_MEMORY_DESCRIPTOR.parse(buff)
		return mte
		
		
class MinidumpThreadExList:
	def __init__(self):
		self.threads = []
		
	def parse(dir, buff):
		t = MinidumpThreadExList()
		buff.seek(dir.Location.Rva)
		chunk = io.BytesIO(buff.read(dir.Location.DataSize))
		mtl = MINIDUMP_THREAD_EX.parse(chunk)
		t.threads = mtl.Threads
		return t