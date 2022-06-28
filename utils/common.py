from scapy.all import ifaces,PacketList

import time
import datetime
import pathlib

from config.common import TMP_HTTP_INPUT_PATH,TMP_HTTP_OUTPUT_PATH,TMP_TLS_OUTPUT_PATH,TMP_TLS_INPUT_PATH
from config.sniffer import FLOW_TMP_PATH

def get_ngrams(query):
    tempQuery = str(query)
    ngrams = []
    for i in range(0,len(tempQuery)-3):
        ngrams.append(tempQuery[i:i+3])
    #print(ngrams)
    return ngrams

def nowTimeDate():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

def nowTimeStamp():
    return time.time_ns()

def nowTimeTag():
    return datetime.datetime.now().replace(tzinfo=datetime.timezone.utc).isoformat()

def notEmpty(raw:str):
    if len(raw.strip()) ==0:
        return False
    return True

def getIfaceList()->list:
    interfaces_list = []
    i = 1
    for iface in ifaces.data:
        if notEmpty(ifaces.data[iface].ip):
            interfaces_list.append({
                "ip": ifaces.data[iface].ip,
                "name":ifaces.data[iface].name
            })
    
    interfaces_list.sort(key = lambda x: x["name"])

    for i, iface in enumerate(interfaces_list):
        iface["id"] = i + 1
    return interfaces_list

def dispackHTTP(pkgs:PacketList):
    
    HTTP_header_list = []

    for pkg in pkgs:
        if "Raw" not in pkg:
            continue
        data = pkg["Raw"].load
        if b"HTTP" not in data:
            continue
        data = data.split(b'\r\n\r\n')[0]
        data = data.split(b'\r\n')
        dic = {}

        dic[b"method"] = data[0]
        data = data[1:]

        try:
            for each in data:
                if len(each) == 0:
                    continue
                tmp = each.split(b':')
                try:
                    dic[tmp[0].decode()] = tmp[1].decode()
                except UnicodeDecodeError:
                    dic[tmp[0].decode()] = tmp[1].hex()

                
            HTTP_header_list.append(dic)
        except:
            HTTP_header_list.append(dict())
        
    return HTTP_header_list

def dealTLSResult(result, pkgs:PacketList):
    response_data = []
    
    keys = result['id'].keys()
    for each in keys:
        this_data = {
            "uuid":str(result['id'][each]),
            "target":f"{str(result['destAddress'][each])}:{str(result['destPort'][each])} (ip)",
            "possibility":result["predict_proba"][each],
            "timestamp":nowTimeTag(),
            "type":"TLS",
            "detail":{
                
            }
        }
        response_data.append(this_data)

    return response_data



def dealHTTPResult(result, pkgs:PacketList):
    response_data = []
    dispacked_package = dispackHTTP(pkgs)
    keys = result['id'].keys()
    for each in keys:
        this_data = {
            "uuid":str(result['id'][each]),
            "target":f"{str(result['destAddress'][each])}:{str(result['destPort'][each])} (ip)",
            "possibility":result["predict_proba"][each],
            "timestamp":nowTimeTag(),
            "type":"HTTP",
            "detail": dispacked_package[int(each)]
        }
        response_data.append(this_data)

    return response_data

def foldersInit():
    pathlib.Path(TMP_TLS_INPUT_PATH).mkdir(parents=True, exist_ok=True)
    pathlib.Path(TMP_TLS_OUTPUT_PATH).mkdir(parents=True, exist_ok=True)
    pathlib.Path(TMP_HTTP_OUTPUT_PATH).mkdir(parents=True, exist_ok=True)
    pathlib.Path(TMP_HTTP_INPUT_PATH).mkdir(parents=True, exist_ok=True)
    pathlib.Path(FLOW_TMP_PATH).mkdir(parents=True, exist_ok=True) 
