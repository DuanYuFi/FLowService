from scapy.all import *
from Socket import *

class FlowListener:
    def __init__(self, server_addr, server_port, name, interfaces=None):
        self.conn = SocketClient(server_addr, server_port, name)
        self.server_addr = server_addr
        self.server_port = server_port
        self.client_addr = self.conn.sock.getsockname()[0]
        self.client_port = self.conn.sock.getsockname()[1]

        if interfaces is None:
            self.interfaces = None
        elif isinstance(interfaces, str):
            self.interfaces = ifaces[interfaces]
        elif isinstance(interfaces, int):
            self.interfaces = ifaces.dev_from_index(interfaces)
        elif isinstance(interfaces, (list, tuple)):
            self.interfaces = []
            for interface in interfaces:
                if isinstance(interface, str):
                    self.interfaces.append(ifaces[interface])
                elif isinstance(interface, int):
                    self.interfaces.append(ifaces.dev_from_index(interface))
                else:
                    raise ValueError("Invalid interface type")

    def handler(self, pkg):

        dst = None if IP not in pkg else pkg[IP].dst
        dport = None if TCP not in pkg else pkg[TCP].dport
        src = None if IP not in pkg else pkg[IP].src
        sport = None if TCP not in pkg else pkg[TCP].sport
        

        if dst == self.server_addr and dport == self.server_port:
            return 
        
        if src == self.server_addr and sport == self.server_port:
            return 

        self.conn.send(bytes(pkg))

    def run(self, filter=None):
        sniff(filter=filter, iface=self.interfaces, prn=self.handler)
    
    def stop(self):
        self.conn.disconnect()