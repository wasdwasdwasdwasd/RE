import sys
import pefile

from shutil import copyfile
from capstone import *
from capstone.x86 import  *
from capstone.x86_const import  *

def Main():
	if len(sys.argv) != 2:
		print("usage: %s %s" % (sys.argv[0], "binary.exe"))
		return

	#Copy File
	fileCopy = sys.argv[1][:-4] + "_unpacked_" + sys.argv[1][-4:]
	copyfile(sys.argv[1], fileCopy)

	#Parse File
	peFILE = pefile.PE(fileCopy)

	#Get stub entry point
	oldEP = peFILE.OPTIONAL_HEADER.AddressOfEntryPoint
	imageBase = peFILE.OPTIONAL_HEADER.ImageBase
	print("[+]EntryPoint %s" % hex(oldEP))

	#Get stub section
	stubSection = None
	for section in peFILE.sections:
		if section.contains_rva(oldEP):
			stubSection = section
	
	if stubSection == None:
		print("[+]Invalid AddressOfEntryPoint")
		return
		
	virtSize = stubSection.Misc_VirtualSize
	fileSize = stubSection.SizeOfRawData

	#Check Size, stub section was 0x1000
	if 0x1000 < virtSize:
		print("[+]The file %s was probably unpacked already" % sys.argv[1])
		return

	print("[+]VirtualSize of section %s" % hex(virtSize))
	print("[+]FileSize of section %s" % hex(fileSize))
	asmStub = peFILE.get_data(oldEP, fileSize)

	#Init Disassembler
	md = Cs(CS_ARCH_X86, CS_MODE_32)
	md.detail = True

	#Packer Data
	decryptBase = 0
	decryptSize = 0
	decryptKey = 0
	originalEP = 0

	#Disassemble and get values
	instPrev = None;
	for instCur in md.disasm(asmStub, imageBase + oldEP):
		# Debug Print Instruction
		print("0x%X:\t%s\t%s" % (instCur.address, instCur.mnemonic, instCur.op_str))

		if instPrev != None:

			#Get decryptSize
			#PUSH Operation followed by MOV
			if instPrev.id == X86_INS_PUSHF and instCur.id == X86_INS_MOV:
				operandImm = instCur.op_find(X86_OP_IMM, 1)
				decryptSize = operandImm.imm
				
			#Get ecryptBase and decryptKey
			#XOR operation followed by DEC or INC
			if instPrev.id == X86_INS_XOR and (instCur.id == X86_INS_DEC or instCur.id == X86_INS_INC):
				operandMem = instPrev.op_find(X86_OP_MEM, 1)
				operandImm = instPrev.op_find(X86_OP_IMM, 1)
				decryptBase = operandMem.value.mem.disp
				decryptKey = operandImm.imm

			#Get OEP
			#MOV operation followed by JMP
			if instPrev.id == X86_INS_MOV and instCur.id == X86_INS_JMP:
				operandImm = instPrev.op_find(X86_OP_IMM, 1)
				originalEP = operandImm.imm
				break

		instPrev = instCur
		
	print("[+]Decrypt Size 0x%x" % decryptSize)
	print("[+]Decrypt Base 0x%x" % decryptBase)
	print("[+]Decrypt Key 0x%x" % decryptKey)
	print("[+]OEP Size 0x%x" % originalEP)
	
	#Decode Buffer
	decodeBuffer = bytearray(peFILE.get_data(decryptBase - imageBase, decryptSize))
	for i in range(decryptSize - 1, -1, -1):
		decodeBuffer[i] = decodeBuffer[i] ^ decryptKey

	#Write Buffer to FILE and Patch OEP
	peFILE.set_bytes_at_rva(decryptBase - imageBase, bytes(decodeBuffer))
	peFILE.OPTIONAL_HEADER.AddressOfEntryPoint = originalEP - imageBase
	peFILE.write(fileCopy)
	print("[+]%s unpacked to %s" % (sys.argv[1], fileCopy))
	
if __name__ == "__main__":
	Main()