from socket import *
from threading import Thread
from time import sleep

#C&C Config
g_serverIP = "127.0.0.1"
g_serverPort = 8080

#Command and Control Thread
def threadWorker(connSocket, addrInfo, idx):
	global g_serverIP
	
	print "[+]Worker Thread"

	#Receive Commands
	try:
		while True:
			data = connSocket.recv(4096)
			print "[+]Worker %d: %s" % (idx, data)

			#Echo
			connSocket.send(data)

	except:
		print "[-]Worker Thread Exception"
		
	connSocket.close()
	return 0

def main():	
	global g_serverIP
	global g_serverPort

	serverData = (g_serverIP, g_serverPort)

	sock = socket(AF_INET, SOCK_STREAM)
	sock.bind(serverData)	
	sock.listen(1)
	
	#Server Lifetime
	idx = 0
	while 1:
		print "[+]Listening on %s:%d" % (g_serverIP, g_serverPort)
		print "[+]Accepting"
		connSocket, addrInfo = sock.accept()
		
		thread = Thread(target = threadWorker, args=(connSocket, addrInfo, idx))
		thread.start()
		idx += 1
		
	sock.close()

if __name__ == "__main__":	
	main()