import idautils

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
		
	
#Main
def main():
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
					
#Script Entry
if __name__ == "__main__":
	main()