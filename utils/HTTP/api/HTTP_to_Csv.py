import os

import numpy as np
import pandas as pd


class HttpAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path

    def get_http_info(self):
        headers = [
            ['srcAddress', 'srcPort', 'destAddress', 'destPort', 'requestMethod', 'host', 'getParam', 'postParam']]
        sum_df = pd.DataFrame(headers)

        http_cmd = f'tshark -r {self.file_path} -Y "http && http.request" -T fields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e http.request.method -e http.host -e http.request.uri.query -e http.file_data'
        data = os.popen(http_cmd).read()

        http_infos = []
        for line in data.splitlines():
            info = line.split('\t')
            if ':' in info[5]:
                info[5] = ':'.join(info[5].split(':')[:-1])
            http_infos.append(info)

        data = np.array(http_infos)
        df = pd.DataFrame(data.reshape(-1, 8))
        df = df.T.reset_index(drop=True).T
        sum_df = pd.concat([sum_df, df])
        return sum_df

    def save_csv(self, csv_path):
        http_info = self.get_http_info()
        http_info.to_csv(csv_path, index=False, header=False)
        return True


if __name__ == '__main__':
    analyzer = HttpAnalyzer('../test/botnet-capture-20110810-neris.pcap')
    analyzer.save_csv('../test/http.csv')
