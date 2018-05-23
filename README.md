# minidump
Python library to parse and read Microsoft minidump file format and create minidumps on Windows machines.

# Requirements
Python >= 3.6

# Basic Usage
```minidump.py --all <mindidump file>  ```  
See help for possible options.

# Advanced usage
The script offers a conveinent way to navigate through the process' memory via the ```MinidumpFileReader``` object.  
Brief description on exposed functions:
1. Search for binary pattern in a specific module's address space:  
  ```search_module(module_name, pattern)```
2. Search for binary pattern in the whole process' memory space:  
	```search(pattern)```
3. Read ```size``` bytes starting from memory address ```virt_addr```:  
	```read(virt_addr, size)```
4. Read a pointer @address ```pos```:  
  -takes process architecture into account (x86/x64)  
  ```get_ptr(pos)```

# Creating minidump file
The ```createminidump.py``` script in the utils folder uses the Windows API to create minidump files. This script can also dump processes running on a different user context by enabling ```SeDebugPrivilege```.  
Of course it only works if you are running it as administrator or a use that has ```SeDebugPrivilege```.
