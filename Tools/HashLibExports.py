import pefile

def rotleft(dword, amount):
	return ((dword << amount) & 0xFFFFFFFF) | ((dword >> (32 - amount)) & 0xFFFFFFFF)

def hashFunc(name):
	result = 0
	
	if 0 < len(name):
		for c in name:
			result = rotleft(result, 7)
			result = result ^ (ord(c) & 0xFFFFFFFF)

	return result

def main():	
	#Common Libs
	libs = ["C:\\Windows\\SysWOW64\\ntdll.dll", 
			"C:\\Windows\\SysWOW64\\kernel32.dll",
			"C:\\Windows\\SysWOW64\\advapi32.dll",
			"C:\\Windows\\SysWOW64\\ws2_32.dll",
			"C:\\Windows\\SysWOW64\\wininet.dll"]

	fh = open("HashExports.txt", "w")
	hashResult = ""
	
	#Parse Libs and Calc Hash
	for lib in libs:
		print "[+][Processing %s]" % lib
		peFILE = pefile.PE(lib)
		
		hashResult += "Lib: " + lib	+ "\n"	
		for export in peFILE.DIRECTORY_ENTRY_EXPORT.symbols:
			#print "0x%08X %s" % (export.address, export.name)
			if export.name is None:
				continue
			
			hashResult += str(hex(hashFunc(export.name))).rstrip("L") + "\t" + export.name + "\n"
		
		hashResult += "\n"
	
	fh.writelines(hashResult)
	fh.close()
	

if __name__ == "__main__":
	main()