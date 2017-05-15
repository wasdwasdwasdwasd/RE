import idautils

def DumpStructure(name):
	#Get ID first
	structID = idc.GetStrucIdByName(name)
	if structID != idc.BADADDR:

		off = 0
		structSize = idc.GetStrucSize(structID)
		print "%s.%-30s : %s" % ("Struct", "Member", "Offset")
		while off != structSize:
			memberName = idc.GetMemberName(structID, off)
			print "%s.%-30s : 0x%08X" % (name, memberName, off)

			off += idc.GetMemberSize(structID, off)

def TraceRegister(address, reg, structName):
	print "[+]TraceRegister"
	print "\tTracing [%s] from 0x%08X" % (reg, address)

	#Parameters
	funcStart = idc.GetFunctionAttr(address, FUNCATTR_START)
	funcEnd = idc.GetFunctionAttr(address, FUNCATTR_END)
	structID = idc.GetStrucIdByName(structName)

	# Trace Register
	iter = address
	while iter != funcEnd:
		iterMnem = idc.GetMnem(iter)

		if iterMnem == "mov" or iterMnem == "lea" or iterMnem == "cmp":
			#Get Instruction Info
			op0 = idc.GetOpnd(iter, 0)
			op1 = idc.GetOpnd(iter, 1)

			op0Type = idc.GetOpType(iter, 0)
			op1Type = idc.GetOpType(iter, 1)

			op0Val = idc.GetOperandValue(iter, 0)
			op1Val = idc.GetOperandValue(iter, 1)

			#Write Access
			#Skip [eax + ebp + Buf] caused by
			if reg in op0 and not ("ebp" in op0):
				if op0Type == idaapi.o_displ:
					# Write Access
					#Annotate Operand0 as Struct Member
					print "[+]Annotating dest reg write access"

					OpStroffEx(iter, 0, structID, 0)

					print "\t0x%08X %s" % (iter, idc.GetDisasm(iter))
					print

				#lea or mov overwrite only, cmp has no effect
				if op0Type == idaapi.o_reg and iterMnem != "cmp":
					print "[+]Tracereg was overwritten"

					#Check if source is our reg
					if reg in op1:
						print "[+]Annotating source reg"
						OpStroffEx(iter, 1, structID, 0)

					print "\t0x%08X %s" % (iter, idc.GetDisasm(iter))
					print

					break

			#Read Access
			# Skip [eax + ebp + Buf] caused by
			if reg in op1 and not ("ebp" in op1):
				if op1Type == idaapi.o_displ:
					# Read Access
					# Annotate Operand1 as Struct Member
					print "[+]Annotating reg1 read access"
					OpStroffEx(iter, 1, structID, 0)
					print "\t0x%08X %s" % (iter, idc.GetDisasm(iter))
					print
				if op1Type == idaapi.o_reg:
					print "reg1 reg read --> should trace this reg at 0x%08X" % iter
					print "\t0x%08X %s" % (iter, idc.GetDisasm(iter))
					print

					# Read Access
					# New Tracereg
					print "--------------------------------------REGISTER RECURSION START"
					print "[+]new tracereg %s, oldtracereg %s" % (op0, reg)
					print "\t0x%08X %s" % (iter, idc.GetDisasm(iter))
					TraceRegister(idc.NextHead(iter), op0, structName)
					print "--------------------------------------REGISTER RECURSION END"
					print
		elif iterMnem == "call":
			callOpnd = idc.GetOpnd(iter, 0)
			callType = idc.GetOpType(iter, 0)
			callTarget = idc.GetOperandValue(iter, 0)
			print "[+]Calltarget [0x%08X]" % callTarget

			#Displacement Call
			if callType == idaapi.o_displ:
				#Check Reg If our Reg then annotate
				if reg in callOpnd:
					#Annotate
					print "[+]Annotating reg0 call access displ"
					OpStroffEx(iter, 0, structID, 0)
					print "\t0x%08X %s" % (iter, idc.GetDisasm(iter))

			#Recursivly Trace Calls
			if idc.isCode(callTarget):
				print "--------------------------------------CALL RECURSION START"
				TraceRegister(callTarget, reg, structName)
				print "--------------------------------------CALL RECURSION END"
			else:
				#Probably API Function
				#If reg == EAX return, because overwritten by lib function
				if reg == "eax":
					break
		elif iterMnem == "push":
			op0 = idc.GetOpnd(iter, 0)
			op0Type = idc.GetOpType(iter, 0)

			#Push Displacement
			if op0Type == idaapi.o_displ and reg in op0:
				print "[+]Annotating push access"
				OpStroffEx(iter, 0, structID, 0)
				print "\t0x%08X %s" % (iter, idc.GetDisasm(iter))

		#Next Instruction
		iter = idc.NextHead(iter)

#Main
def main():
	#Find All CodeXrefs to 0x00408DC8
	pConfig = 0x00408DC8

	structName = "Config"
	DumpStructure(structName)
	print

	#Get all the config Xrefs
	dataRefs = idautils.DataRefsTo(pConfig)
	for dataRef in dataRefs:
		print "[+]Starting Annotatring from 0x%08X" % dataRef
		print "\t%s" % idc.GetDisasm(dataRef)

		#First Xref is a mov in a usual case
		xrefMnem = idc.GetMnem(dataRef)
		if xrefMnem == "mov":

			#Check if Writing or Reading Memory
			op0 = idc.GetOpnd(dataRef, 0)
			op1 = idc.GetOpnd(dataRef, 1)

			op0Type = idc.GetOpType(dataRef, 0)
			op1Type = idc.GetOpType(dataRef, 1)

			op0Val = idc.GetOperandValue(dataRef, 0)
			op1Val = idc.GetOperandValue(dataRef, 1)

			traceReg = ""

			#Prepare the Trace Register
			if op0Type == idaapi.o_mem and op0Val == pConfig:
				#Write Access to Config
				traceReg = op1

			else:
				#Read Access to Config
				traceReg = op0

			#Recursive Resolve Registers
			TraceRegister(idc.NextHead(dataRef), traceReg, structName)
			print



#Script Entry
if __name__ == "__main__":
	main()