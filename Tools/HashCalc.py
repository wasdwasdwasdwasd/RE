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
	try:
		while True:
			string = raw_input("Enter a string: ")	
			print "[+][Hash: 0x%08X][%s]" % (hashFunc(string), string)
			
	except KeyboardInterrupt:
		return
	

if __name__ == "__main__":
	main()