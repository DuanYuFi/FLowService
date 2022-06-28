import binascii
import os
import tempfile
import uuid

import OpenSSL
import numpy as np
import pandas as pd


class TlsAnalyzer:
    def __init__(self, file_path):
        self.tmp_pcap_fd, self.tmp_pcap_path = tempfile.mkstemp(suffix='.pcap')
        filter_tls_cmd = f'tshark -r {file_path} -Y tls -w {self.tmp_pcap_path}'
        os.system(filter_tls_cmd)
        print(f'Created temp file at {self.tmp_pcap_path}')

    def get_stream_info(self):
        stream_cmd = f'tshark -r {self.tmp_pcap_path} -q -z conv,tcp'
        headers = [['srcAddress', 'srcPort', 'destAddress', 'destPort', 'pktsIn', 'bytesIn', 'pktsOut', 'bytesOut']]
        sum_df = pd.DataFrame(headers)
        data = os.popen(stream_cmd).read()

        data = np.array(data.split('|')[-1].split('=')[0].split())
        data = list(data.reshape(-1, 11))

        for i, line in enumerate(data):

            if line[4].endswith('bytes'):
                data[i][4] = line[4].replace('bytes', '')
            elif line[4].endswith('kB'):
                data[i][4] = str(int(line[4][:-2]) * 1024)
            elif line[4].endswith('mB'):
                data[i][4] = str(int(line[4][:-2]) * 1024 * 1024)
            elif line[4].endswith('gB'):
                data[i][4] = str(int(line[4][:-2]) * 1024 * 1024 * 1024)

            if line[6].endswith('bytes'):
                data[i][6] = line[6].replace('bytes', '')
            elif line[6].endswith('kB'):
                data[i][6] = str(int(line[6][:-2]) * 1024)
            elif line[6].endswith('mB'):
                data[i][6] = str(int(line[6][:-2]) * 1024 * 1024)
            elif line[6].endswith('gB'):
                data[i][6] = str(int(line[6][:-2]) * 1024 * 1024 * 1024)

            ip_src = ':'.join(line[0].split(':')[:-1])
            port_src = line[0].split(':')[-1]
            ip_dst = ':'.join(line[2].split(':')[:-1])
            port_dst = line[2].split(':')[-1]
            data[i][0] = ip_src
            data[i][2] = ip_dst
            data[i] = np.insert(data[i], 1, port_src)
            data[i] = np.insert(data[i], 4, port_dst)

        data = np.array(data)
        stream_count = data.shape[0]

        df = pd.DataFrame(data)
        df = df.drop([2, 9, 10, 11, 12], axis=1)
        df = df.T.reset_index(drop=True).T
        sum_df = pd.concat([sum_df, df])
        return stream_count, sum_df

    def get_app_protocol(self, stream_count):
        headers = [['appProtocol']]
        sum_df = pd.DataFrame(headers)
        data = ['TLS' for i in range(stream_count)]
        data = np.array(data)
        df = pd.DataFrame(data.reshape(-1, 1))
        sum_df = pd.concat([sum_df, df])
        return sum_df

    def get_tls_version_sni(self, stream_count):
        headers = [['tlsVersion', 'tlsSni']]
        sum_df = pd.DataFrame(headers)

        tls_versions_snis = []
        for i in range(stream_count):
            tls_version_sni_cmd = f'tshark -r {self.tmp_pcap_path} -Y "tls.handshake.type == 1 && tcp.stream eq {i}" -T fields -e tls.handshake.version -e tls.handshake.extensions_server_name'
            data = os.popen(tls_version_sni_cmd).read()

            data = data.replace('0x00000301', 'TLS1.0')
            data = data.replace('0x00000302', 'TLS1.1')
            data = data.replace('0x00000303', 'TLS1.2')

            tmp = data.strip().split()
            if len(tmp) == 0:
                tls_versions_snis.append(['', ''])
            elif len(tmp) == 1:
                tls_versions_snis.append([tmp[0], ''])
            else:
                tls_versions_snis.append(tmp)

        data = np.array(tls_versions_snis)
        df = pd.DataFrame(data)
        df = df.T.reset_index(drop=True).T
        sum_df = pd.concat([sum_df, df])
        return sum_df

    def get_cert_info(self, stream_count):
        headers = [['tlsSubject', 'tlsIssuerDn']]
        sum_df = pd.DataFrame(headers)

        cert_info = []
        for i in range(stream_count):
            cert_cmd = f'tshark -r {self.tmp_pcap_path} -Y "tls.handshake.type == 11 && tcp.stream eq {i}" -T fields -e tls.handshake.certificate'
            data = os.popen(cert_cmd).read()
            server_cert_hex = data.strip().split(',')[0]

            if server_cert_hex == '':
                cert_info.append('')
                cert_info.append('')

            else:
                subject_info, issuer_info = self.parse_cert(server_cert_hex)
                cert_info.append(subject_info)
                cert_info.append(issuer_info)

        data = np.array(cert_info)
        df = pd.DataFrame(data.reshape(-1, 2))
        df = df.T.reset_index(drop=True).T
        sum_df = pd.concat([sum_df, df])
        return sum_df

    def parse_cert(self, cert_hex):
        cert_bytes = binascii.unhexlify(cert_hex)
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bytes)
        subject = cert.get_subject()

        subject_info = ''
        for i in subject.get_components():
            key, value = i
            info = f'{key.decode()}={value.decode()}'
            subject_info += info + ', '
        subject_info = subject_info[:-2]

        issuer = cert.get_issuer()
        issuer_info = ''
        for i in issuer.get_components():
            key, value = i
            info = f'{key.decode()}={value.decode()}'
            issuer_info += info + ', '
        issuer_info = issuer_info[:-2]
        return subject_info, issuer_info

    def get_event_id(self, stream_count):
        headers = [['eventId']]
        sum_df = pd.DataFrame(headers)
        event_ids = []
        for i in range(stream_count):
            event_ids.append(uuid.uuid4())
        event_ids = np.array(event_ids)
        df = pd.DataFrame(event_ids.reshape(-1, 1))
        sum_df = pd.concat([sum_df, df])
        return sum_df

    def save_csv(self, csv_path):
        stream_count, stream_info = self.get_stream_info()
        app_protocol = self.get_app_protocol(stream_count)
        tls_version_sni = self.get_tls_version_sni(stream_count)
        cert_info = self.get_cert_info(stream_count)
        event_id = self.get_event_id(stream_count)

        sum_df = pd.concat([stream_info, app_protocol, tls_version_sni, cert_info, event_id], axis=1)
        sum_df = sum_df.T.reset_index(drop=True).T
        sum_df.to_csv(csv_path, index=False, header=False)

        os.close(self.tmp_pcap_fd)
        os.remove(self.tmp_pcap_path)
        return True


if __name__ == '__main__':
    analyzer = TlsAnalyzer('botnet-capture-20110810-neris.pcap')
    analyzer.save_csv('tls.csv')
