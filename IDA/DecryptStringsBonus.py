import idautils
import sys, os, time, struct, re, string

# !!! set your pyemu path plz2u !!!
from future.backports.urllib.response import addbase

sys.path.append(r'C:\PythonModules\pyemu')
sys.path.append(r'C:\PythonModules\pyemu\lib')

from PyEmu import *

###################################################################################################
#Emulator Stuff
#Global Variable
emu = 0

def GetSection(sectionName):
	for seg in idautils.Segments():
		if idc.SegName(seg) == sectionName:
			return seg
	return 0

def LoadSection(emulator, sectionName):
	sectionStart = GetSection(sectionName)
	sectionEnd = idc.SegEnd(sectionStart)

	print("start = 0x%08X, end = 0x%08X" % (sectionStart, sectionEnd))
	print "[+] Loading %s section bytes into memory" % sectionName

	iter = sectionStart
	while iter <= sectionEnd:
		byte = idc.GetOriginalByte(iter)

		#Skip bad Addr
		if byte != BADADDR:
			emulator.set_memory(iter, idc.GetOriginalByte(iter), size=1)

		iter += 1

	print "[+] %s section loaded into memory" % sectionName
	print

def LoadImports(emulator):
	print "[+] Loading import section bytes into memory"
	importstart = GetSection(".idata")
	importend = SegEnd(importstart)

	currentimport = importstart
	fakeaddress = 0x70000000
	while currentimport <= importend:
		importname = Name(currentimport)

		emulator.os.add_fake_library(importname, fakeaddress)
		emulator.set_memory(currentimport, fakeaddress, size=4)

		currentimport += 4
		fakeaddress += 4

	print "[+] Import section loaded into memory"
	print


#Loads NullTerminated String from Emulator Memory
def GetString(emu, address):
	retString = ""

	idx = 0
	while True:
		c = emu.get_memory(address + idx, 1)

		#Append Char into Buffer
		if c == 0:
			break

		retString += chr(c)
		idx += 1
	return retString

#Sets NullTerminated String from Emulator Memory
def SetString(emu, address, string):

	idx = 0
	for c in string:
		emu.set_memory(address + idx, c)
		idx += 1

	#NullTermination
	emu.set_memory(address + idx, 0)


#import name
#import address
def hookSprintf(name, address):
	global emu

	#print "[+]hookSprintf"

	#Prepare EIP to [ESP]
	pESP = emu.get_register("esp")
	dwRET = emu.get_memory(pESP)
	emu.set_register("eip", dwRET)

	#Resolve Parameters
	pEAX = emu.get_register("eax")

	#Get Parameters
	szBuffer1 = emu.get_memory(pESP + 4)
	szFormat = emu.get_memory(pESP + 8)
	szBuffer2 = emu.get_memory(pESP + 12)
	character = emu.get_memory(pESP + 16)

	#Load String from DestBuffer
	szDecrypted = GetString(emu, szBuffer2)

	#Append char
	szDecrypted += chr(character)

	#Write concatenated to DestBuffer
	SetString(emu, szBuffer2, szDecrypted)

	szDecrypted = GetString(emu, szBuffer2)
	#print "[+]Decrypting: \"%s\"" % szDecrypted
	#print

	# Return True to Continue
	return True

def hookStrcpy(name, address):
	global emu

	#print "[+]hookStrcpy"
	#print

	#Prepare EIP to [ESP]
	pESP = emu.get_register("esp")
	dwRET = emu.get_memory(pESP)
	emu.set_register("eip", dwRET)

	#Get Buffer
	szDest = emu.get_memory(pESP + 4)
	szSource = emu.get_memory(pESP + 8)

	szDecrypted = GetString(emu, szSource)
	SetString(emu, szDest, szDecrypted)

	#Return True to Continue
	return True
###################################################################################################

###################################################################################################
# Find Crypto Stuff
#Get Executable Segments
def GetExecutableSegments():
	segments = []
	for segment in idautils.Segments():
		#print SegName(segment), hex(segment)
		
		#Get Segment Attribute
		segPermission = GetSegmentAttr(segment, SEGATTR_PERM)
		if segPermission & SEGPERM_EXEC:
			print "[+]Code Segment %s 0x%08X" % (SegName(segment), segment)
			segments.append(segment)
	return segments

#Get Function List
def GetFunctions(segmentBase):
	functions = Functions(SegStart(segmentBase), SegEnd(segmentBase))
	return functions

#First function instruction
#Returns a list with tuples (function, xorAddr, xorMnemonic, operand1, operand2)
def FindXor(function):
	xorInst = []
	
	#Get Start and End Address
	funcStart = idc.GetFunctionAttr(function, FUNCATTR_START)
	funcEnd = idc.GetFunctionAttr(function, FUNCATTR_END)
	
	#Iterate over Instructions
	for addr in Heads(funcStart, funcEnd):
		mnem = idc.GetMnem(addr)
	   
		#Find XOR and check if operands are not equal
		if mnem == "xor":
		
			#Compare operands
			op1 = idc.GetOpnd(addr, 0)
			op2 = idc.GetOpnd(addr, 1)
			
			#Get Type
			op1Type = idc.GetOpType(addr, 0)
			op2Type = idc.GetOpType(addr, 1)
			
			#Not Equal than it is probably no optimization
			#Also one operand should be an immediate
			if op1 != op2 and (op1Type ==  idaapi.o_imm or op2Type == idaapi.o_imm):
				tup = (function, addr, mnem, op1, op2)
				xorInst.append(tup)
				
	return xorInst
###################################################################################################
	
###################################################################################################
# Decrypt Stuff
def DecryptStackStrings(addrDecryptFunction):
	global emu
	print "[+]DecryptStackStrings"

	#Get All XrefsTo this function
	calls = idautils.CodeRefsTo(addrDecryptFunction, 1)

	# Iterate all Calls Decrypt Strings
	for call in calls:
		print "[+]Call at 0x%08X %s" % (call, idc.GetFunctionName(call))

		# Resolve Parameters
		# Param1. DestBuffer
		# Param2. Length
		# Param3. StackStringEncrypted
		destBuffer, length = GetDecryptString1Parameters(call)
		print "[+]Params dest = 0x%08X len = 0x%08X" % (destBuffer, length)

		#Get Emulation Boundaries
		emulStart, emulEnd = GetDecryptString1EmulationBoundaries(call, length)
		print "[+]Start 0x%08X, End 0x%08X" % (emulStart, emulEnd)

		#Inits Registers
		PrepareEmuRegister(emu, emulStart)

		#Try to Emulate and Update the ida databse
		try:
			#Emulate
			szDecryptedString = Emulate(emu, emulStart, emulEnd)

			#Valid Decrypted String
			if 0 < len(szDecryptedString):
				print "[+]Decrypted: \"%s\" at 0x%08X" % (szDecryptedString, call)
				#Add Comment and Patch Database
				idc.MakeRptCmt(call, szDecryptedString)

				#If DestBuffer is an address and not a register
				#Make Name and Patch IDB
				if destBuffer != 0 and destBuffer != -1:
					idc.MakeNameEx(destBuffer, "" + szDecryptedString, SN_NOCHECK)

					# Patch decrypted Buffer and convert to String
					idx = 0
					for c in szDecryptedString:
						idc.PatchByte(destBuffer + idx, ord(c))
						idx += 1

					idc.PatchByte(destBuffer + idx, 0)
					idc.MakeStr(destBuffer, destBuffer + idx)

		except:
			print "[+]EmulStart = 0x%08X, EmulEnd = 0x%08X" % (emulStart, emulEnd)
			emu.dump_regs()
			e = sys.exc_info()[0]
			print e
			
		print

#Performs the Emulation and Returns the Dumped String
def Emulate(emu, emulStart, emulEnd):
	emu.execute(start=emulStart, end=emulEnd)

	#At this point we are after strcp and eax holds
	#the String
	pString = emu.get_register("eax")

	szDecrypted = GetString(emu, pString)
	return szDecrypted

#Inits all the necessary Registers before performing the emulation
def PrepareEmuRegister(emu, emulStart):
	#Iterate unitl function start search for all mov reg, immediate
	#And init reg with these values

	instStartFunc = idc.GetFunctionAttr(emulStart, FUNCATTR_START)
	emulIter = emulStart

	#Iterate until func Start and Set Registers
	while emulIter != instStartFunc:
		instMnem = idc.GetMnem(emulIter)

		idc.GetDisasm(emulIter)

		if instMnem == "mov":
			# Compare operands
			op0 = idc.GetOpnd(emulIter, 0)
			op1 = idc.GetOpnd(emulIter, 1)
			op0Val = idc.GetOperandValue(emulIter, 0)
			op1Val = idc.GetOperandValue(emulIter, 1)

			# Get Type
			op0Type = idc.GetOpType(emulIter, 0)
			op1Type = idc.GetOpType(emulIter, 1)

			#Load Registers
			if op0Type == idaapi.o_reg and op1Type == idaapi.o_imm:
				#print "addr: 0x%08X op0: %s op1: %s opVal0: 0x%08X opVal1: 0x%08X" % (emulIter, op0, op1, op0Val, op1Val)

				#Set Register with immediate
				emu.set_register(op0, op1Val)

		emulIter = idc.PrevHead(emulIter)

	#Iterate Backwards until call and execute all movs and leas
	while emulIter != emulStart:
		instMnem = idc.GetMnem(emulIter)

		if instMnem == "mov":
			#print idc.GetDisasm(emulIter)
			emu.execute(start=emulIter, end=idc.NextHead(emulIter))

		elif instMnem == "lea":
			#print idc.GetDisasm(emulIter)
			emu.execute(start = emulIter, end = idc.NextHead(emulIter))

		emulIter = idc.NextHead(emulIter)


#Resolves the Parameters pushed on the stack prior to DecryptString1
#Returns a tuple(addrDestination, length)
def GetDecryptString1Parameters(callAdress):
	#Parameters to resolve
	paramDestBuffer = 0
	paramLength = 0

	instStartFunc = idc.GetFunctionAttr(callAdress, FUNCATTR_START)
	instPrev = callAdress

	#Push Count
	cnt = 0
	while True:
		instPrev = idc.PrevHead(instPrev)

		#Get Mnemonic
		instPrevMnem = idc.GetMnem(instPrev)

		#Found Push
		if instPrevMnem == "push":
			if cnt == 0:
				#First Param can be a stack addr or immediate
				#paramDestBuffer = idc.GetOpnd(instPrev, 0)
				paramDestBuffer = idc.GetOperandValue(instPrev, 0)
			elif cnt == 1:
				#Seocond Param
				#paramLength = idc.GetOpnd(instPrev, 0)
				paramLength = idc.GetOperandValue(instPrev, 0)
			else:
				pass

			cnt += 1

		if paramDestBuffer != 0 and paramLength != 0:
			break
		elif instStartFunc == instPrev:
			print "[+]Could Not Resolve one of the Parameters"
			break

	return (paramDestBuffer, paramLength)

#Starts from Call and Iterates until function start or until call is reached
def GetDecryptString1EmulationBoundaries(callAddr, stringLength):
	emulStart = 0
	emulEnd = 0

	emulStart = idc.PrevHead(callAddr)
	emulEnd = idc.NextHead(callAddr)

	instStartFunc = idc.GetFunctionAttr(callAddr, FUNCATTR_START)

	#Go all the way up until function start is reaced
	#or until a call
	while True:
		#Function Start found
		if emulStart == instStartFunc:
			break

		#Check if Previous is Call
		instPrev = idc.PrevHead(emulStart)
		if instPrev == idc.BADADDR:
			break

		instPrevMnem = idc.GetMnem(instPrev)
		if instPrevMnem == "call":
			break

		emulStart = instPrev

	return (emulStart, emulEnd)

#Inits Global Emulator Variable
def InitEmulator():
	global emu

	#Init a Big Enough Stack or otherwise it will crash on last string
	emu = IDAPyEmu(stack_size = 0x2000)
	#emu.debug(1)

	LoadSection(emu, ".text")
	LoadSection(emu, ".data")
	LoadImports(emu)

	# Hook Libary Functions
	emu.set_library_handler("sprintf", hookSprintf)
	emu.set_library_handler("strcpy", hookStrcpy)

#Main
def Main():
	InitEmulator()
	codeSegments = GetExecutableSegments()
	
	#Iterate Segments
	for segment in codeSegments:
		functions = GetFunctions(segment)
		
		#Iterate Functions and search XOR
		for function in functions: 
			
			flag = GetFunctionFlags(function)
			if flag == -1 or flag & FUNC_LIB:
				continue
		
			#print hex(function), GetFunctionName(function)
			xorList = FindXor(function)
			
			if 0 < len(xorList):
				print "[+]Found Possible Crypto at 0x%08X in function %s" % (function, GetFunctionName(function))

				# Itrate over tuples (function, xorAddr, xorMnemonic, operand1, operand2)
				for xor in xorList:
					print "[+]Crypto Inst: 0x%08X: %s %s %s" % (xor[1], xor[2], xor[3], xor[4])

				print

				#hardcoded addresses are not good
				if function == 0x00402CB8:
					DecryptStackStrings(function)
				else:
					pass
					
#Script Entry
if __name__ == "__main__":
	Main()