import sys
import ntpath
import pefile
import winappdbg
import winappdbg.win32
from winappdbg import *
from winappdbg.win32 import *
import os
import os.path

from shutil import copyfile


#Global Variables should be accessed from Hook
g_szDump = None
g_peFILE = None
g_OldEP = None
g_ImageBase = None
g_SizeOfImage = None
g_HandleChild = 0

#Dump Hook
def HookZwWriteVirtualMemory(event):
	print("[+]HookZwWriteVirtualMemory")

	global g_ImageBase
	global g_HandleChild
	curHandle = win32.GetCurrentProcess()
	process = event.get_process()
	thread = event.get_thread()
	stackData = thread.read_stack_dwords(6)

	#Read Parameters from Stack
	processHandle = stackData[1]
	baseAddress = stackData[2]
	buffer = stackData[3]
	numberOfBytesToWrite = stackData[4]
	numberOfBytesWritten = stackData[5]

	#4th to 8th calls should be dumped to file
	#Dump if wiriting to remote process and memory around imagebase
	if curHandle != processHandle and (baseAddress & 0xFFF00000) == (g_ImageBase & 0xFFF00000):
		try:
			# Dump Parameters
			print("[+]Dumping")
			print("\tHANDLE ProcessHandle 0x%08X" % processHandle)
			print("\tPVOID BaseAddress 0x%08X" % baseAddress)
			print("\tPVOID Buffer 0x%08X" % buffer)
			print("\tULONG NumberOfBytesToWrite 0x%08X" % numberOfBytesToWrite)
			print("\tPULONG NumberOfBytesWritten 0x%08X" % numberOfBytesWritten)
			print("")

			memdump = process.read(buffer, numberOfBytesToWrite)

			#Append to our Binary File
			f = open(g_szDump, 'ab')
			f.write(memdump)
			f.close()

			#Save Child Handle for Termination
			if g_HandleChild == 0:
				g_HandleChild = processHandle


		except Exception, e:
			print(str(e))
			print("[+]Failed at HookdwNtWriteVirtualMemory")

#Suspend and Kill Hook
def HookZwSetContextThread(event):
	print("[+]HookZwSetContextThread")

	global g_HandleChild
	process = event.get_process()
	thread = event.get_thread()
	stackData = thread.read_stack_dwords(10)
	procName = ntpath.basename(process.get_filename())
	pidParent = process.get_pid()

	#Read Parameters from Stack
	threadHandle = stackData[1]
	context = stackData[2]

	#Dump Parameters
	print("\tHANDLE ThreadHandle, 0x%08X" % threadHandle)
	print("\tPCONTEXT Context 0x%08X" % context)

	try:
		dwEIP = process.read_dword(context + 0xB8)
		dwEAX = process.read_dword(context + 0xB0)
		dwEBX = process.read_dword(context + 0xA4)

		print("EIP @ 0x%08X = 0x%08X" % (context + 0xB8, dwEIP))
		print("EAX @ 0x%08X = 0x%08X" % (context + 0xB0, dwEAX))
		print("EBX @ 0x%08X = 0x%08X" % (context + 0xA4, dwEBX))

	except Exception, e:
		print(str(e))
		print("[+]Failed at HookdwNtSetContextThread")

	#Kill Child
	procList = System().find_processes_by_filename(procName)
	for proc, name in procList:
		pidChild = proc.get_pid()
		if pidParent != pidChild:
			print("[+]Terminating Child %s with PID %d" % (name, pidChild))
			proc.kill()


	#Break Process
	print("[+]Terminating Parent %s with PID %d" % (procName, pidParent))
	process = event.get_process()
	#process.suspend()
	process.kill()
	print("[+]Finished")

#LoadDll Event Hook Class
class EventHandlerHook(EventHandler):
	def load_dll(self, event):
		module = event.get_module()

		if module.match_name("ntdll.dll"):
			pid = event.get_pid()

			#Resolve Module Names and set Breakpoints
			dwZwWriteVirtualMemory = module.resolve("ZwWriteVirtualMemory")
			dwZwSetContextThread = module.resolve("ZwSetContextThread")

			event.debug.break_at(pid, dwZwWriteVirtualMemory, HookZwWriteVirtualMemory)
			event.debug.break_at(pid, dwZwSetContextThread, HookZwSetContextThread)

def Main():
	if len(sys.argv) != 2:
		print("usage: %s %s" % (sys.argv[0], "binary.exe"))
		return

	#Copy File
	global g_szDump
	global g_OldEP
	global g_ImageBase
	global g_SizeOfImage

	#Prepare Output Name and Remove File
	g_szDump = sys.argv[1][:-4] + "_runpe_unpacked" + sys.argv[1][-4:]
	if os.path.exists(g_szDump):
		os.remove(g_szDump)

	#Parse Original File
	g_peFILE = pefile.PE(sys.argv[1])

	#Get stub entry point
	g_OldEP = g_peFILE.OPTIONAL_HEADER.AddressOfEntryPoint
	g_ImageBase = g_peFILE.OPTIONAL_HEADER.ImageBase
	g_SizeOfImage = g_peFILE.OPTIONAL_HEADER.SizeOfImage

	#Init Debugger
	debugger = Debug(EventHandlerHook())

	try:
		debugger.execv(sys.argv[1:])

		debugger.loop()

	finally:
		debugger.stop()

if __name__ == "__main__":
	Main()