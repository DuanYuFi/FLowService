import socket
import threading

from scapy.all import *

class SocketServer():

    def __init__(self, listen_addr, listen_port, max_conn=1, threshold=100):

        # threading.Thread.__init__(self)

        self.listen_addr = listen_addr
        self.listen_port = listen_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.listen_addr, self.listen_port))
        self.sock.listen(max_conn)
        self.buffers = {}

        self.go = threading.Event()
        self.go.clear()

        self.THRESHOLD = threshold
    
    def start(self):

        self.go.clear()

        while not self.go.is_set():
            try:
                conn, addr = self.sock.accept()
                name = conn.recv(1024).decode()

                if name in self.buffers:
                    print("Name %s already in use." % name)
                    conn.close()
                    continue
                
                self.buffers[name] = []
                print("Connected by", addr, name)

                t = threading.Thread(target=self.handle_conn, args=(conn, addr, name))
                t.start()

                t2 = threading.Thread(target=self.handle_analyze, args=(name,))
                t2.start()
            
            except Exception as e:
                print(e)
                self.go.set()


    def handle(self, data: bytes, name):
        pkg = Ether(data)
        self.buffers[name].append(pkg)

    def handle_analyze(self, name):
        pass

    def handle_conn(self, conn, addr, name):
        while not self.go.is_set():
            try:
                data = conn.recv(1024)
                if not data:
                    break
                
                self.handle(data, name)

            except (ConnectionResetError, ConnectionAbortedError):
                self.go.set()

            except Exception as e:
                print(e)
                self.go.set()

        conn.close()
        self.buffers.pop(name)
        print("Disconnected by", addr)
    


class SocketClient:

    def __init__(self, host, port, name):
        self.host = host
        self.port = port
        self.name = name
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        self.sock.send(self.name.encode())
    
    def send(self, data):
        self.sock.send(data)
    
    def recv(self, buffersize=1024):
        return self.sock.recv(buffersize)

    def disconnect(self):
        self.sock.close()
    
    def connect(self, host, port):
        self.sock.connect((host, port))
        self.send(self.name.encode())
