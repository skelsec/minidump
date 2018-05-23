#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
# TODO: implement this better, the ExceptionInformation definition is missing on msdn :(

import enum
from minidump.common_structs import * 

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680368(v=vs.85).aspx
class MINIDUMP_EXCEPTION_STREAM:
	def __init__(self):
		self.ThreadId = None
		self.alignment = None
		self.ExceptionRecord = None
		self.ThreadContext = None
	
	@staticmethod
	def parse(buff):
		mes = MINIDUMP_EXCEPTION_STREAM()
		mes.ThreadId = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mes.alignment = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mes.ExceptionRecord = MINIDUMP_EXCEPTION.parse(buff)
		mes.ThreadContext = MINIDUMP_LOCATION_DESCRIPTOR.parse(buff)
		return mes
		
class ExceptionCode(enum.Enum):
	EXCEPTION_ACCESS_VIOLATION =  0xC0000005 #The thread tried to read from or write to a virtual address for which it does not have the appropriate access.
	EXCEPTION_ARRAY_BOUNDS_EXCEEDED = 0xC000008C #The thread tried to access an array element that is out of bounds and the underlying hardware supports bounds checking.
	EXCEPTION_BREAKPOINT = 0x80000003 #A breakpoint was encountered.
	EXCEPTION_DATATYPE_MISALIGNMENT = 0x80000002 #The thread tried to read or write data that is misaligned on hardware that does not provide alignment. For example, 16-bit values must be aligned on 2-byte boundaries; 32-bit values on 4-byte boundaries, and so on.
	EXCEPTION_FLT_DENORMAL_OPERAND = 0xC000008D#One of the operands in a floating-point operation is denormal. A denormal value is one that is too small to represent as a standard floating-point value.
	EXCEPTION_FLT_DIVIDE_BY_ZERO = 0xC000008E#The thread tried to divide a floating-point value by a floating-point divisor of zero.
	EXCEPTION_FLT_INEXACT_RESULT = 0xC000008F#The result of a floating-point operation cannot be represented exactly as a decimal fraction.
	EXCEPTION_FLT_INVALID_OPERATION = 0xC0000090#This exception represents any floating-point exception not included in this list.
	EXCEPTION_FLT_OVERFLOW = 0xC0000091#The exponent of a floating-point operation is greater than the magnitude allowed by the corresponding type.
	EXCEPTION_FLT_STACK_CHECK = 0xC0000092#The stack overflowed or underflowed as the result of a floating-point operation.
	EXCEPTION_FLT_UNDERFLOW = 0xC0000093#The exponent of a floating-point operation is less than the magnitude allowed by the corresponding type.
	EXCEPTION_ILLEGAL_INSTRUCTION = 0xC000001D#The thread tried to execute an invalid instruction.
	EXCEPTION_IN_PAGE_ERROR = 0xC0000006#The thread tried to access a page that was not present, and the system was unable to load the page. For example, this exception might occur if a network connection is lost while running a program over the network.
	EXCEPTION_INT_DIVIDE_BY_ZERO = 0xC0000094#The thread tried to divide an integer value by an integer divisor of zero.
	EXCEPTION_INT_OVERFLOW = 0xC0000095#The result of an integer operation caused a carry out of the most significant bit of the result.
	EXCEPTION_INVALID_DISPOSITION = 0xC0000026#An exception handler returned an invalid disposition to the exception dispatcher. Programmers using a high-level language such as C should never encounter this exception.
	EXCEPTION_NONCONTINUABLE_EXCEPTION =0xC0000025 #The thread tried to continue execution after a noncontinuable exception occurred.
	EXCEPTION_PRIV_INSTRUCTION = 0xC0000096#The thread tried to execute an instruction whose operation is not allowed in the current machine mode.
	EXCEPTION_SINGLE_STEP = 0x80000004#A trace trap or other single-instruction mechanism signaled that one instruction has been executed.
	EXCEPTION_STACK_OVERFLOW = 0xC00000FD#The thread used up its stack.
		
#https://msdn.microsoft.com/en-us/library/windows/desktop/ms680367(v=vs.85).aspx
class MINIDUMP_EXCEPTION:
	def __init__(self):
		self.ExceptionCode = None
		self.ExceptionFlags = None
		self.ExceptionRecord = None
		self.ExceptionAddress = None
		self.NumberParameters = None
		self.__unusedAlignment = None
		#self.ExceptionInformation = []
		
	def parse(buff):
		me = MINIDUMP_EXCEPTION()
		me.ExceptionCode = ExceptionCode(int.from_bytes(buff.read(4), byteorder = 'little', signed = False))
		me.ExceptionFlags = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		me.ExceptionRecord = int.from_bytes(buff.read(8), byteorder = 'little', signed = False)
		me.ExceptionAddress = int.from_bytes(buff.read(8), byteorder = 'little', signed = False)
		me.NumberParameters = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		me.__unusedAlignment = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		#for i in range(me.NumberParameters):
		#	me.ExceptionInformation.append()
			
		return me
