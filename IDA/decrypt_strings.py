import idautils
import sys

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
def DecryptString0(addrDecryptFunction):
	print "[+]DecryptString0"
	
	#Get All Calls to this function
	calls = idautils.CodeRefsTo(addrDecryptFunction, 1)
	
	#Iterate all Calls Decrypt Strings
	for call in calls:
		print "[+]Call at 0x%08X %s" % (call, idc.GetFunctionName(call))
		
		pDecrypted, pEncrypted = GetDecryptString0Parameters(call)
			
		print "[+]Parameters: 0x%08X 0x%08X" % (pDecrypted, pEncrypted)
		
		#Get String
		szEncryptedString = idc.GetString(pEncrypted)
		
		#Handle one Byte Empty Strings
		if szEncryptedString == None:
			#Read Byte
			szEncryptedString = ""
			idx = 0
			while True:
				byte = idc.Byte(pEncrypted + idx)
				szEncryptedString += chr(byte)
				
				
				if byte == 0:
					break
				idx += 1

		szDecryptedString = DecryptString0Algo(szEncryptedString, 0xFE)
		print "[+]Dec: \"%s\"" % szDecryptedString
		print
		
		#Rename and Add Comments
		idc.MakeRptCmt(pEncrypted, szDecryptedString)
		idc.MakeNameEx(pEncrypted, "crypt" + szDecryptedString, SN_NOCHECK | SN_NOWARN)
		idc.MakeNameEx(pDecrypted, "" + szDecryptedString, SN_NOCHECK | SN_NOWARN)
		
		#Patch decrypted Buffer and convert to String
		idx = 0
		for c in szDecryptedString:
			idc.PatchByte(pDecrypted + idx, ord(c))
			idx += 1
			
		idc.PatchByte(pDecrypted + idx, 0)
		idc.MakeStr(pDecrypted, pDecrypted + idx)
		
		print
		
def DecryptString0Algo(encryptedString, xorKey):
	decryptedString = ""
		
	for c in encryptedString:
		decryptedString += chr((ord(c) ^ xorKey))
		
	return decryptedString

#Resolves the Addresses Pushed to DecryptString0
#Returns a tuple(szDestinationBuffer, szEncrypted)
def GetDecryptString0Parameters(addr):
	szDestination = 0
	szEncrypted = 0
	
	#Resolve Pushes
	instPrev = addr
	instStartFunc = idc.GetFunctionAttr(addr, FUNCATTR_START)
	
	#Find Push Instructions
	cnt = 0
	while True:
		#Get Previous instruction
		instPrev = idc.PrevHead(instPrev)
	   
		#Get Mnemonic
		instPrevMnem = idc.GetMnem(instPrev)
		
		#First push is dest
		#Second push is encrypted
		if instPrevMnem == "push":
			if cnt == 0:
				szDestination = GetResolvePushImmediate(instPrev)
			elif cnt == 1:
				szEncrypted = GetResolvePushImmediate(instPrev)
			
			cnt += 1
		
		#Break Loop if Found of if at the end of function
		if szDestination != 0 and szEncrypted != 0:
			break
		elif instStartFunc == instPrev:
			print "[+]Could Not Resolve one of the Parameters"
			break	
	
	return (szDestination, szEncrypted)

#This Function Resolves the push operand
#until it finds an immediate
def GetResolvePushImmediate(addr):
	#Push Has one Operand
	#operandResolve = idc.GetOpnd(addr, 0)		   #Returns Operand String like in ida disassembly offset_...
	operandResolve = idc.GetOperandValue(addr, 0)	#Returns an integer

	#Get Type
	opType = idc.GetOpType(addr, 0)
	
	#Return Value
	immPush = 0x0
	
	#If Register Trace it back until immediate Found
	if opType == idaapi.o_imm:
		return operandResolve
	elif opType == idaapi.o_reg:
		
		#Resolve Register
		#push eax now trace all operands which are m
		instPrevAddr = addr
		instStartFunc = idc.GetFunctionAttr(addr, FUNCATTR_START)
	
		while True:
			#Read Prev Addr and Mnemonic
			instPrevAddr = idc.PrevHead(instPrevAddr)			
			instMnem = idc.GetMnem(instPrevAddr)
			
			#Check if operand 0
			if instMnem == "mov":
				#operand1 = idc.GetOpnd(instPrevAddr, 0)
				#operand2 = idc.GetOpnd(instPrevAddr, 1)
				operand1 = idc.GetOperandValue(instPrevAddr, 0)
				operand2 = idc.GetOperandValue(instPrevAddr, 1)
				
				#Found Operand, Check Operand 2 
				#if Immedeate --> Done
				#else operandResolve = operand 2
				if operand1 == operandResolve:
					if idc.GetOpType(instPrevAddr, 1) == idaapi.o_imm:
						#Done
						immPush = operand2
						break
					else:
						operandResolve = operand2

			
			if instStartFunc == instPrevAddr:
				print "[+]Could Not Resolve the Register"
				break
	
	return immPush

#Main
def Main():
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
				
				#hardcoded addresses are not good
				if function == 0x00402C72:
					DecryptString0(function)
				else:
					pass
					
#Script Entry
if __name__ == "__main__":
	Main()