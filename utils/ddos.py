from sys import maxsize
from config.sniffer import DOS_THRESHOLD
from scapy.all import rdpcap
from utils.common import nowTimeTag
from uuid import uuid4

class DOSIdentifier:
    def __init__(self,filename) -> None:
        self.filename = filename

    def fen(self,data):
        ip=[]
        l=len(data)
        for i in range(0,l):
            ip.append(data[i].src)
        return ip

    def anayl(self,datas,pcap_data):
        l=len(datas)
        size=[]
        for i in range(0,l):
            size.append(0)
        ports=[[]for _ in range(l)]
        data_list = [[] for _ in range(l)]
        pcap_data.sort(key = lambda element: element.src)
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

    def judgeddos(self,datas,maclist,portlist,size):
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

        if maxn>=DOS_THRESHOLD:
            score_percent=1
        else:
            score_percent= maxn/ DOS_THRESHOLD

        if score_percent < 0.5:
            return {}

        return_data = {
            'uuid': str(uuid4()),
            'target': f"{mac_addr} (mac)",
            'possibility': score_percent,
            'timestamp': nowTimeTag(),
            'type': 'DOS',
            'detail': {
                "Number of accesses in one second":maxn,
                "Access ports":ports,
                "Flow data size":"{:.2%}".format(max_size/1000)[:-1]+"KB"
            }
        }
        return return_data

        # if datas[i][j+10]-datas[i][j]<=1:
        #   return True # 可疑DDos
        # else:
        #    return False # 应该不是

    def judge(self):
        file = rdpcap(self.filename)
        final=self.fen(file)
        result,iplist,port_list,size=self.anayl(final,file)
        temp=self.judgeddos(result,iplist,port_list,size=size)
        return temp
