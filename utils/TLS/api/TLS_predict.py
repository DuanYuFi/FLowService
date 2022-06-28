from os import path
import numpy as np
import pandas as pd
try:
    import utils.TLS.api.dataprocessing as dp
except:
    import dataprocessing as dp
import joblib
import json
import time
from sklearn.preprocessing import MinMaxScaler
from config.common import TLS_MODEL_PATH


def TLS_predict_func(test_path):
    data = pd.read_csv(test_path)

    X = dp.dataTransform(data)
    encoders = joblib.load(path.join(TLS_MODEL_PATH,"encoders.pkl"))
    keys = ['O', 'CN', 'Dn', 'Sni', 'Version']
    n = 0
    for key in keys:
        X[key] = X[key].map(lambda x: '<unknown>' if x not in encoders[n].classes_ else x)
        encoders[n].classes_ = np.append(encoders[n].classes_, '<unknown>')
        X[key] = encoders[n].transform(X[key])
        n += 1

    X = MinMaxScaler().fit_transform(X)
    rfc = joblib.load(path.join(TLS_MODEL_PATH,"model.pkl"))
    # print('= ' * 20)
    # print(X)
    results = rfc.predict(X)
    results_1 = rfc.predict_proba(X)
    # print(results_1)
    predic = []
    for each in results_1:
        predic.append((abs(each[0]-each[1]))/each[0])


    # print(results)
    #results = results[results['label']==1]

    results = pd.DataFrame({
        'id': data['eventId'],
        'label': results,
        'srcAddress':data['srcAddress'],
        'srcPort':data['srcPort'],
        'destAddress':data['destAddress'],
        'destPort':data['destPort'],
        'appProtocol':'tls',
        'predict_proba':predic

    })

    # print(results)


    return results

    #results.to_csv('../result/result.csv', index=False)

def select_TLS_warning(path):
    data = TLS_predict_func(path)
    data = data[data['label']==1]
    data_1 = pd.DataFrame({
        'id': data['id'],
        'label': '疑似恶意流量',
        'srcAddress':data['srcAddress'],
        'srcPort':data['srcPort'],
        'destAddress':data['destAddress'],
        'destPort':data['destPort'],
        'appProtocol':data['appProtocol'],
        'predict_proba': data['predict_proba']

    })
    data_json = data_1.to_json()
    return data_1,data_json

def generate_TLS_csv(path):
    data,data_json = select_TLS_warning(path=path)
    a = json.loads(data_json)
    return a