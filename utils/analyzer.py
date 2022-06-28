from os import path, remove
from utils.ddos import DOSIdentifier
from utils.arp import ARPIdentifier
from scapy.all import PacketList, Packet
from scapy.all import load_layer, wrpcap, rdpcap
from config.common import TMP_TLS_INPUT_PATH, TMP_TLS_OUTPUT_PATH, TMP_HTTP_INPUT_PATH, TMP_HTTP_OUTPUT_PATH
from utils.TLS.api.TLS_to_Csv import TlsAnalyzer
from utils.TLS.api.TLS_predict import generate_TLS_csv
from utils.HTTP.api.HTTP_to_Csv import HttpAnalyzer
from utils.HTTP.api.HTTP_predict import select_HTTP_warning
from utils.common import nowTimeStamp, dealTLSResult, dealHTTPResult

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
        print("TLS analyze")
        self.appendReport(analyzeTLSPacketByFilename(self.pcapFilename))
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

    def __del__(self):
        try:
            remove(self.pcapFilename)
        except OSError:
            pass