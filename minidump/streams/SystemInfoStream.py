#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import io
import enum
import logging
from minidump.common_structs import * 

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680396(v=vs.85).aspx
class PROCESSOR_ARCHITECTURE(enum.Enum):
	AMD64 = 9 #x64 (AMD or Intel)
	ARM = 5 #ARM
	IA64 = 6 #Intel Itanium
	INTEL = 0 #x86
	UNKNOWN = 0xffff #Unknown processor
# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680396(v=vs.85).aspx
class PROCESSOR_LEVEL(enum.Enum):
	INTEL_80386 = 3
	INTEL_80486 = 4
	INTEL_PENTIUM = 5
	INTEL_PENTIUM_PRO = 6 #or Pentium II
# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680396(v=vs.85).aspx	
class PRODUCT_TYPE(enum.Enum):
	VER_NT_DOMAIN_CONTROLLER = 0x0000002 #The system is a domain controller.
	VER_NT_SERVER = 0x0000003 #The system is a server.
	VER_NT_WORKSTATION = 0x0000001 #The system is running Windows XP, Windows Vista, Windows 7, or Windows 8.
# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680396(v=vs.85).aspx
class PLATFORM_ID(enum.Enum):
	VER_PLATFORM_WIN32s = 0 #Not supported
	VER_PLATFORM_WIN32_WINDOWS = 1 #Not supported.
	VER_PLATFORM_WIN32_NT = 2 #The operating system platform is Windows.
# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680396(v=vs.85).aspx
class SUITE_MASK(enum.IntFlag):
	VER_SUITE_BACKOFFICE = 0x00000004 #Microsoft BackOffice components are installed.
	VER_SUITE_BLADE = 0x00000400 #Windows Server 2003, Web Edition is installed.
	VER_SUITE_COMPUTE_SERVER = 0x00004000 #Windows Server 2003, Compute Cluster Edition is installed.
	VER_SUITE_DATACENTER = 0x00000080 #Windows Server 2008 R2 Datacenter, Windows Server 2008 Datacenter, or Windows Server 2003, Datacenter Edition is installed.
	VER_SUITE_ENTERPRISE = 0x00000002 #Windows Server 2008 R2 Enterprise, Windows Server 2008 Enterprise, or Windows Server 2003, Enterprise Edition is installed.
	VER_SUITE_EMBEDDEDNT = 0x00000040 #Windows Embedded is installed.
	VER_SUITE_PERSONAL = 0x00000200 #Windows XP Home Edition is installed.
	VER_SUITE_SINGLEUSERTS = 0x00000100 #Remote Desktop is supported, but only one interactive session is supported. This value is set unless the system is running in application server mode.
	VER_SUITE_SMALLBUSINESS = 0x00000001 #Microsoft Small Business Server was once installed on the system, but may have been upgraded to another version of Windows.
	VER_SUITE_SMALLBUSINESS_RESTRICTED = 0x00000020 #Microsoft Small Business Server is installed with the restrictive client license in force.
	VER_SUITE_STORAGE_SERVER = 0x00002000 #Windows Storage Server is installed.
	VER_SUITE_TERMINAL = 0x00000010 # Terminal Services is installed. This value is always set. If VER_SUITE_TERMINAL is set but VER_SUITE_SINGLEUSERTS is not set, the system is running in application server mode.


# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680396(v=vs.85).aspx
class MINIDUMP_SYSTEM_INFO:
	def __init__(self):
		self.ProcessorArchitecture = None
		self.ProcessorLevel = None
		self.ProcessorRevision = None
		self.Reserved0 = None
		self.NumberOfProcessors = None
		self.ProductType = None
		self.MajorVersion = None
		self.MinorVersion = None
		self.BuildNumber = None
		self.PlatformId = None
		self.CSDVersionRva = None
		self.Reserved1 = None
		self.SuiteMask = None
		self.Reserved2 = None
		self.VendorId = []
		self.VersionInformation = None
		self.FeatureInformation = None
		self.AMDExtendedCpuFeatures = None
		self.ProcessorFeatures = []
		
	@staticmethod
	def parse(buff):
		msi = MINIDUMP_SYSTEM_INFO()
		msi.ProcessorArchitecture = PROCESSOR_ARCHITECTURE(int.from_bytes(buff.read(2), byteorder = 'little', signed = False))
		msi.ProcessorLevel = PROCESSOR_LEVEL(int.from_bytes(buff.read(2), byteorder = 'little', signed = False))
		msi.ProcessorRevision = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
		#the below field is present in the documentation from MSDN, however is not present in the actual dump
		#msi.Reserved0 = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
		msi.NumberOfProcessors = int.from_bytes(buff.read(1), byteorder = 'little', signed = False)
		msi.ProductType = PRODUCT_TYPE(int.from_bytes(buff.read(1), byteorder = 'little', signed = False))
		msi.MajorVersion = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		msi.MinorVersion = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		msi.BuildNumber = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		msi.PlatformId = PLATFORM_ID(int.from_bytes(buff.read(4), byteorder = 'little', signed = False))
		msi.CSDVersionRva = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		#msi.Reserved1 = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		msi.SuiteMask = SUITE_MASK(int.from_bytes(buff.read(2), byteorder = 'little', signed = False))
		msi.Reserved2 = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
		if msi.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.INTEL:
			for i in range(3):
				msi.VendorId.append(int.from_bytes(buff.read(4), byteorder = 'little', signed = False))
			msi.VersionInformation = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
			msi.FeatureInformation = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
			msi.AMDExtendedCpuFeatures = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		else:
			for i in range(2):
				msi.ProcessorFeatures.append(int.from_bytes(buff.read(8), byteorder = 'little', signed = False))
		
		return msi
		
class MinidumpSystemInfo:
	def __init__(self):
		self.ProcessorArchitecture = None
		self.ProcessorLevel = None
		self.ProcessorRevision = None
		self.NumberOfProcessors = None
		self.ProductType = None
		self.MajorVersion = None
		self.MinorVersion = None
		self.BuildNumber = None
		self.PlatformId = None
		self.CSDVersion = None
		self.SuiteMask = None
		self.VendorId = None
		self.VersionInformation = None
		self.FeatureInformation = None
		self.AMDExtendedCpuFeatures = None
		self.ProcessorFeatures = None
		
		#extra
		self.OperatingSystem = None
		
	def guess_os(self):
		if self.MajorVersion == 10 and self.MinorVersion == 0 and self.ProductType == PRODUCT_TYPE.VER_NT_WORKSTATION:
			self.OperatingSystem = "Windows 10"
		elif self.MajorVersion == 10 and self.MinorVersion == 0 and ProductType != self.ProductType.VER_NT_WORKSTATION:
			self.OperatingSystem =  "Windows Server 2016 Technical Preview"
		elif self.MajorVersion == 6 and self.MinorVersion == 3 and self.ProductType == self.ProductType.VER_NT_WORKSTATION:
			self.OperatingSystem =  "Windows 8.1"
		elif self.MajorVersion == 6 and self.MinorVersion == 3 and self.ProductType != self.ProductType.VER_NT_WORKSTATION:
			self.OperatingSystem =  "Windows Server 2012 R2"
		elif self.MajorVersion == 6 and self.MinorVersion == 2 and self.ProductType == self.ProductType.VER_NT_WORKSTATION:
			self.OperatingSystem =  "Windows 8"
		elif self.MajorVersion == 6 and self.MinorVersion == 2 and self.ProductType != self.ProductType.VER_NT_WORKSTATION:
			self.OperatingSystem =  "Windows Server 2012"
		elif self.MajorVersion == 6 and self.MinorVersion == 1 and self.ProductType == self.ProductType.VER_NT_WORKSTATION:
			self.OperatingSystem =  "Windows 7"
		elif self.MajorVersion == 6 and self.MinorVersion == 1 and self.ProductType != self.ProductType.VER_NT_WORKSTATION:
			self.OperatingSystem =  "Windows Server 2008 R2"
		elif self.MajorVersion == 6 and self.MinorVersion == 0 and self.ProductType == self.ProductType.VER_NT_WORKSTATION:
			self.OperatingSystem =  "Windows Vista"
		elif self.MajorVersion == 6 and self.MinorVersion == 0 and self.ProductType != self.ProductType.VER_NT_WORKSTATION:
			self.OperatingSystem =  "Windows Server 2008"
		# Can't accurately report on Windows Server 2003/R2
		# elif (MajorVersion == 5 and MinorVersion == 2 and ProductType == self.ProductType.VER_NT_WORKSTATION)
		#	self.OperatingSystem =  "Windows Vista"
		#elif (MajorVersion == 5 and MinorVersion == 2 and ProductType != self.ProductType.VER_NT_WORKSTATION)
		#	self.OperatingSystem =  "Windows Server 2008"
		elif self.MajorVersion == 5 and self.MinorVersion == 1:
			self.OperatingSystem =  "Windows XP"
		elif self.MajorVersion == 5 and self.MinorVersion == 0:
			self.OperatingSystem =  "Windows 2000"
		
	def parse(dir, buff):
		t = MinidumpSystemInfo()
		buff.seek(dir.Location.Rva)
		chunk = io.BytesIO(buff.read(dir.Location.DataSize))
		si = MINIDUMP_SYSTEM_INFO.parse(chunk)
		t.ProcessorArchitecture = si.ProcessorArchitecture
		t.ProcessorLevel = si.ProcessorLevel
		t.ProcessorRevision = si.ProcessorRevision
		t.NumberOfProcessors = si.NumberOfProcessors
		t.ProductType = si.ProductType
		t.MajorVersion = si.MajorVersion
		t.MinorVersion = si.MinorVersion
		t.BuildNumber = si.BuildNumber
		t.PlatformId = si.PlatformId
		t.CSDVersion = MINIDUMP_STRING.get_from_rva(si.CSDVersionRva, buff)
		t.SuiteMask = si.SuiteMask
		t.VendorId = si.VendorId
		t.VersionInformation = si.VersionInformation
		t.FeatureInformation = si.FeatureInformation
		t.AMDExtendedCpuFeatures = si.AMDExtendedCpuFeatures
		t.ProcessorFeatures = si.ProcessorFeatures
		try:
			t.guess_os()
		except Exception as e:
			logging.log(1, 'Failed to guess OS! MajorVersion: %s MinorVersion %s BuildNumber %s ProductType: %s' % (t.MajorVersion, t.MinorVersion, t.BuildNumber, t.ProductType ))
			t.OperatingSystem = None
		return t
		
	
	def __str__(self):
		t = '== System Info ==\n'
		t += 'ProcessorArchitecture %s\n' % self.ProcessorArchitecture
		t += 'OperatingSystem -guess- %s\n' % self.OperatingSystem
		t += 'ProcessorLevel %s\n' % self.ProcessorLevel
		t += 'ProcessorRevision %s\n' % hex(self.ProcessorRevision)
		t += 'NumberOfProcessors %s\n' % self.NumberOfProcessors
		t += 'ProductType %s\n' % self.ProductType
		t += 'MajorVersion %s\n' % self.MajorVersion
		t += 'MinorVersion %s\n' % self.MinorVersion
		t += 'BuildNumber %s\n' % self.BuildNumber
		t += 'PlatformId %s\n' % self.PlatformId
		t += 'CSDVersion: %s\n' % self.CSDVersion
		t += 'SuiteMask %s\n' % self.SuiteMask
		t += 'VendorId %s\n' % ' '.join( [hex(x) for x in self.VendorId] )
		t += 'VersionInformation %s\n' % self.VersionInformation
		t += 'FeatureInformation %s\n' % self.FeatureInformation
		t += 'AMDExtendedCpuFeatures %s\n' % self.AMDExtendedCpuFeatures
		t += 'ProcessorFeatures %s\n' % ' '.join( [hex(x) for x in self.ProcessorFeatures] )
		
		return t