from uuid import uuid4
from scapy.all import rdpcap
from config.sniffer import ARP_THRESHOLD
from utils.common import nowTimeTag
import json

class ARPIdentifier:
    def __init__(self,filename) -> None:
        self.filename = filename
    def fen(self,data):
        ip=[]
        packets=[]
        l=len(data)
        for i in range(0,l):
            if data[i].haslayer('ARP'):
                ip.append(data[i].src)
                packets.append(data[i])
        return ip,packets

    def anayl(self,datas,pcap_data):
        l=len(datas)
        size=[]
        for i in range(0,l):
            size.append(0)
        ports=[[]for _ in range(l)]
        data_list = [[] for _ in range(l)]
        pcap_data.sort(key = lambda element: element.src)

        i = 0

        while i < l:
            for j in range(0,len(pcap_data)):
                if i >= l:
                    break
                if pcap_data[j].src==datas[i]:
                    data_list[i].append(pcap_data[j].time)
                    if pcap_data[j].haslayer("TCP"):
                        ports[i].append(pcap_data[j]['TCP'].dport)
                        size[i] += len(pcap_data[j]['TCP'].payload)

                    elif pcap_data[j].haslayer("UDP"):
                        ports[i].append(pcap_data[j]['UDP'].dport)
                        size[i] += len(pcap_data[j]['UDP'].payload)
                else:
                    i += 1
            if i == l:
                ports[i - 1]=list(set(ports[i - 1]))
            else:
                ports[i]=list(set(ports[i]))
        return data_list,datas,ports,size

    def judgeARP(self,datas,maclist,portlist,size):
        mac_addr = ''
        ports=[]
        maxn = 0
        max_size=0
        for i in range(0,len(datas)):
            maxx=0
            if len(datas[i])<=5:
                continue
            else:
                start = 0
                end = 1
                cnt = 1
                #for j in range(0,len(datas[i])):
                while end < len(datas[i]):
                    if datas[i][end]-datas[i][start]<=1:
                        end+=1
                    else:    
                        cnt=end-start
                        maxx=max(maxx,cnt)
                        start+=1
            if maxx > maxn:
                mac_addr = maclist[i]
                ports=portlist[i]
                maxn=maxx
                max_size=size[i]

           # maxn=max(maxx,maxn)
        score_percent=''

        if maxn>=ARP_THRESHOLD:
            score_percent=1
        else:
            score_percent= maxn/ ARP_THRESHOLD

        if score_percent < 0.5:
            return {}

        return_data = {
            'uuid': str(uuid4()),
            'target': f"{mac_addr} (mac)",
            'possibility': score_percent,
            'timestamp': nowTimeTag(),
            'type': 'ARP',
            'detail': {
                "Number of accesses in one second":maxn,
                "Access ports":ports,
                "Flow data size":"{:.2%}".format(max_size/1000)[:-1]+"KB"
            }
        }
        return return_data
    def judge(self):
        file=rdpcap(self.filename)
        final,new_file=self.fen(file)
        result,iplist,port_list,size=self.anayl(final,file)
        #print(result,iplist)
        temp=self.judgeARP(result,iplist,port_list,size=size)
        return temp

