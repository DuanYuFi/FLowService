import time
from os import path, remove
import json
import asyncio

from scapy.all import *
from fastapi import WebSocket

from utils.common import nowTimeStamp, dealTLSResult, dealHTTPResult
from Socket import SocketServer
from config.sniffer import FLOW_TMP_PATH, FLOW_RESULT_PATH


def get_ngrams(query):
    tempQuery = str(query)
    ngrams = []
    for i in range(0,len(tempQuery)-3):
        ngrams.append(tempQuery[i:i+3])
    #print(ngrams)
    return ngrams

class FlowAnalyzer(SocketServer):
    
    def handle_analyze(self, name):

        while not self.go.is_set() and name in self.buffers:

            print(len(self.buffers[name]))

            if self.ws is None:
                self.go.wait(0.1)
                continue

            # print(len(self.buffers[name]))

            if len(self.buffers[name]) > self.THRESHOLD:
                try:
                    pkgs = self.buffers[name][:self.THRESHOLD]
                    self.buffers[name] = self.buffers[name][self.THRESHOLD:]

                    tag = f"flow-{name}-{nowTimeStamp()}"
                    filename = path.join(FLOW_TMP_PATH, f"{tag}.pcap")

                    print("Analyzing", filename)

                    wrpcap(filename, pkgs)
                    analyzer = PacketsAnalyzer(filename)
                    analyzer.analyze()
                    remove(filename)

                    report = analyzer.getReport()
                    # filename = path.join(FLOW_RESULT_PATH, f"{tag}.txt")
                    # with open(filename, "w") as f:
                    #     f.write(json.dumps(report))
                    report = {"client_name": name, "data": report}
                    asyncio.set_event_loop(self.event_loop)
                    asyncio.get_event_loop().run_until_complete(self.ws.send_json(report))
                except Exception as e:
                    e.with_traceback()
                    print(e)

            self.go.wait(0.5)
    
    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.ws = ws
        print("Connected.")

    def disconnect(self):
        print("Disconnected.")
        self.ws = None


from utils.ddos import DOSIdentifier
from utils.arp import ARPIdentifier
from config.common import TMP_TLS_INPUT_PATH, TMP_TLS_OUTPUT_PATH, TMP_HTTP_INPUT_PATH, TMP_HTTP_OUTPUT_PATH
from utils.TLS.api.TLS_to_Csv import TlsAnalyzer
from utils.TLS.api.TLS_predict import generate_TLS_csv
from utils.HTTP.api.HTTP_to_Csv import HttpAnalyzer
from utils.HTTP.api.HTTP_predict import select_HTTP_warning

def analyzeDosPacketByFilename(filename: str) -> list:
    ddosI = DOSIdentifier(filename=filename)
    result = ddosI.judge()
    if result != {}:
        return [result]
    return []


def analyzeARPPacketByFilename(filename: str) -> list:
    arpI = ARPIdentifier(filename=filename)
    result = arpI.judge()
    if result != {}:
        return [result]
    return []


def analyzeTLSPacketByFilename(filename: str) -> list:
    load_layer("tls")
    pkgs: PacketList = rdpcap(filename)
    HTTPS_pkgs: PacketList = PacketList([])
    pkg: Packet
    for pkg in pkgs:
        if pkg.haslayer("TLS"):
            HTTPS_pkgs.append(pkg)

    response_data = []
    if len(HTTPS_pkgs) != 0:
        timestamp = nowTimeStamp()
        tag = "https_%d" % timestamp
        input_path = path.join(TMP_TLS_INPUT_PATH, '%s.pcap' % tag)
        output_path = path.join(TMP_TLS_OUTPUT_PATH, '%s.csv' % tag)
        wrpcap(input_path, HTTPS_pkgs)
        analyzer = TlsAnalyzer(input_path)
        analyzer.save_csv(output_path)
        result = generate_TLS_csv(output_path)
        response_data = dealTLSResult(result, HTTPS_pkgs)
    return response_data


def analyzeHTTPPacketByFilename(filename: str) -> list:
    pkgs: PacketList = rdpcap(filename)
    HTTP_pkgs: PacketList = PacketList([])
    pkg: Packet
    for pkg in pkgs:
        if "Raw" not in pkg:
            continue
        data = pkg["Raw"].load
        if b"HTTP" in data:
            HTTP_pkgs.append(pkg)

    response_data = []
    if len(HTTP_pkgs) != 0:
        timestamp = nowTimeStamp()
        tag = "https_%d" % timestamp
        input_path = path.join(TMP_HTTP_INPUT_PATH, '%s.pcap' % tag)
        output_path = path.join(TMP_HTTP_OUTPUT_PATH, '%s.csv' % tag)
        
        wrpcap(input_path, HTTP_pkgs)
        analyzer = HttpAnalyzer(input_path)
        analyzer.save_csv(output_path)
        result = select_HTTP_warning(output_path)
        # print("= " * 10 + "HTTP")
        # print(result)
        response_data = dealHTTPResult(result, HTTP_pkgs)
    return response_data


class PacketsAnalyzer:
    def __init__(self, filename):
        self.pcapFilename = filename
        self.recordList = []

    def analyze(self):
        # print("TLS analyze")
        # self.appendReport(analyzeTLSPacketByFilename(self.pcapFilename))
        print("Dos analyze")
        self.appendReport(analyzeDosPacketByFilename(self.pcapFilename))
        print("Arp analyze")
        self.appendReport(analyzeARPPacketByFilename(self.pcapFilename))
        print("HTTP analyze")
        self.appendReport(analyzeHTTPPacketByFilename(self.pcapFilename))

    def getReport(self):
        return self.recordList

    def appendReport(self, reportList):
        self.recordList += reportList


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()

    parser.add_argument("host", help="host of service")
    parser.add_argument("port", help="port of service")
    parser.add_argument("-m", "--max_conn", help="max connection", type=int)
    parser.add_argument("-t", "--threshold", help="threshold of packet number to analyze", type=int)

    args = parser.parse_args()

    server = FlowAnalyzer(args.host, args.port, args.max_conn, args.threshold)
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
        print("Server stopped")
        exit(0)