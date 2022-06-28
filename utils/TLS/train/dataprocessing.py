import re
import pandas as pd
import tldextract
from sklearn.preprocessing import LabelEncoder



def dataTransform(data):
    bytesOut = data['bytesOut']
    bytesIn = data['bytesIn']
    pktsOut = data['pktsOut']
    pktsIn = data['pktsIn']
    tlsSubject = data['tlsSubject']
    tlsIssuerDn = data['tlsIssuerDn']
    tlsSni = data['tlsSni']
    tlsVersion = data['tlsVersion']

    outRatio = []  # 出流量/出包数
    inRatio = []  # 入流量/入包数
    orgName = []
    sni = []



    for i in range(len(bytesIn)):
        outRatio.append(bytesOut[i] / pktsOut[i])   #出流量/出包数
        inRatio.append(bytesIn[i] / pktsIn[i])      #入流量/入包数



    pattern_O = 'O=.*?([,/]+|$)'

    for tmp in tlsSubject:  # 证书发布，O
        if pd.isna(tmp):
            orgName.append('NULL')
        else:
            res = re.search(pattern_O, tmp)
            if res:
                res = res.group()
                if res.startswith('O='):
                    res = res[2:]
                if res.endswith(','):
                    res = res[:-1]
                if res.endswith('.'):
                    res = res[:-1]
                if res.endswith('./'):
                    res = res[:-2]
                orgName.append(res)
            else:
                orgName.append('null')

    pattern_CN = 'CN=.*?(/|$)'
    commonName = []

    for tmp in tlsSubject: # 证书发布，CN
        if pd.isna(tmp):
            commonName.append('NULL')
        else:
            res = re.search(pattern_CN, tmp)
            if res:
                res = res.group()
                if res.startswith('CN='):
                    res = res[3:]
                if res.endswith('/'):
                    res = res[:-1]
                commonName.append(res)
            else:
                commonName.append('null')

    pattern_CN = 'CN=.*?(/|$)'
    dn_commonName = []

    for tmp in tlsIssuerDn:
        if pd.isna(tmp):
            dn_commonName.append('NULL')
        else:
            res = re.search(pattern_CN, tmp)
            if res:
                res = res.group()
                if res.startswith('CN='):
                    res = res[3:]
                if res.endswith('/'):
                    res = res[:-1]
                dn_commonName.append(res)
            else:
                dn_commonName.append('null')


    for tmp in tlsSni:   # 顶级域名
        if pd.isna(tmp):
            sni.append('NULL')
        else:
            tld = tldextract.extract(tmp)
            sni.append(tld.domain)

    X = pd.DataFrame({
        'O': orgName,
        'CN': commonName,
        'Dn': dn_commonName,
        'Sni': sni,
        'Version': tlsVersion,
        'OutRatio': outRatio,
        'InRatio': inRatio
    })
    return X


def encoder(data):


    org_encoder = LabelEncoder().fit(data['O'])
    cmName_encoder = LabelEncoder().fit(data['CN'])
    dncm_encoder = LabelEncoder().fit(data['Dn'])
    sni_encoder = LabelEncoder().fit(data['Sni'])
    version_encoder = LabelEncoder().fit(data['Version'])
    encoders = [org_encoder, cmName_encoder, dncm_encoder, sni_encoder, version_encoder]

    return encoders