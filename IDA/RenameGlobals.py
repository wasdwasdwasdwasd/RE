import idautils
import sys

#This Function Resolves the push operand
#until it finds an immediate
def GetResolvePushImmediate(addr):
	#Push Has one Operand
	operandResolve = idc.GetOperandValue(addr, 0)	#Returns an integer

	#Get Type
	opType = idc.GetOpType(addr, 0)
	
	#Return Value
	immPush = -1
	
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

#Worker function which traces the register to the first argument pushed
#to one of the init funcs
def traceRegisterToStringAddr(addr, reg, initfuncs):
	start = idc.GetFunctionAttr(addr, FUNCATTR_START)
	iter = addr
	stringAddr = -1
	
	traceReg = reg
	resolvePush = False
	while start <= iter:
		mnem = idc.GetMnem(iter)
		
		if mnem == "push" and resolvePush == True:
			stringAddr = GetResolvePushImmediate(iter)
			resolvePush = False
			
			if stringAddr != -1:
				break

		#Compare with init funcs
		elif mnem == "call" and traceReg == "eax":			
			addr = idc.GetOperandValue(iter, 0)
			if addr in initfuncs:
				resolvePush = True

		#Trace Register
		elif mnem == "mov":
			operand1 = idc.GetOperandValue(iter, 0)
			operand2 = idc.GetOperandValue(iter, 1)
			
			#Found Operand, Check Operand 2 
			#if Immedeate --> Done
			#else operandResolve = operand 2
			if operand1 == traceReg:
				if idc.GetOpType(iter, 1) == idaapi.o_imm:
					#Done
					stringAddr = operand2
					break
				else:
					traceReg = operand2

		#Iterate
		iter = idc.PrevHead(iter)
			
	return stringAddr
	
def getString(stringAddr):
	string = ""
	idx = 0
	while True:
		byte = idc.Byte(stringAddr + idx)
		string += chr(byte)
		
		if byte == 0:
			break
		idx += 1
	return string

def renameMemory(mem, string):
	string = "g_" + string
	idc.MakeRptCmt(mem, string)
	idc.MakeNameEx(mem, string, SN_NOCHECK | SN_NOWARN)
		
#This function will iterate from end to start
#and trace all the reg to mem writes
#it will follow the register written to memory
#and if the register is the output of any of the initfuncs
#it will trace the parameters and get the string and rename the memory
def renameGlobals(start, end, initfuncs):
	iter = end
	
	#Iterate addresses
	while start <= iter:
		mnem = idc.GetMnem(iter)

		#if mov
		if mnem == "mov":
			#Get Type
			op1Type = idc.GetOpType(iter, 0)
			op2Type = idc.GetOpType(iter, 1)
			
			#reg-to-mem
			if op1Type == idaapi.o_mem and op2Type == idaapi.o_reg:
				#save memory address and trace register
				mem = idc.GetOperandValue(iter, 0)
				reg = idc.GetOpnd(iter, 1)
	
				stringAddr = traceRegisterToStringAddr(iter, reg, initfuncs)
				if stringAddr != -1:
					string = getString(stringAddr)
					print "[+]Renamed 0x%08X to %s" % (mem, string)
					renameMemory(mem, string)
		
		#Iterate
		iter = idc.PrevHead(iter)
	
	
#Main
def main():
	#Init function 
	start = 0x1000AAF0
	end = 0x1000BAD4
	initfuncs = []
	
	initfuncs.append(0x101D4A40)	#InitBool
	initfuncs.append(0x101D4A44)	#InitInt
	initfuncs.append(0x101D4A48)	#InitFloat
	initfuncs.append(0x101D4A4C)	#InitString
	initfuncs.append(0x101D4A50)	#InitStringList
	initfuncs.append(0x101D4A54)	#InitColor
	initfuncs.append(0x101D4A5C)	#InitVector

	#Rename globals
	renameGlobals(start, end, initfuncs)
					
#Script Entry
if __name__ == "__main__":
	main()