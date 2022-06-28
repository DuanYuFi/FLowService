import joblib
import utils.HTTP.api.dataprocessing as dp
import pandas as pd
import uuid
import random
from config.common import HTTP_MODEL_PATH
from os.path import join
import json

def HTTP_predict_func_1(file_path='../test/http.csv'):

    data = pd.read_csv(file_path)
    parameters = dp.dataTransform(data)
    #print(parameters)

    parameters_results = [[] for x in range(0,len(parameters))]
    results_predic=[[] for x in range(0,len(parameters))]

    uuid_list = []
    TF_list =  [0 for x in range(0,len(parameters))]
    for i in range(0,len(parameters)):
        uuid_list.append(uuid.uuid4())



   
    for i in range(0,len(parameters)):
        if parameters[i] == []:
            parameters_results[i] = [0]          # 正常的
        else:
            each_result,each_predic = HTTP_predict_func(parameters[i])
            #print(each_predic)
            each_result = list(set(each_result))
            parameters_results[i] = each_result
            results_predic[i] = (abs(each_predic[0][0] - each_predic[0][1])/each_predic[0][0])
            # print(parameters[i])
        
    print(parameters_results)
    for i in range(0, len(parameters)):

        if parameters_results[i] == [0]:
            TF_list[i] = 0
        elif 0 in parameters_results[i]:
            parameters_results[i].remove(0)
            TF_list[i] = 1
        else:
            TF_list[i] = 1
    
    results = pd.DataFrame({
        'id': uuid_list,
        'srcAddress':data['srcAddress'],
        'srcPort':data['srcPort'],
        'destAddress':data['destAddress'],
        'destPort':data['destPort'],
        'requestMethod':data['requestMethod'],
        'host':data['host'],
        'label':parameters_results,
        'TF_list':TF_list,
        'parameters':parameters,
        'predict_proba':results_predic

    })
    print(results["TF_list"])

    # print(results)
    # print(results['label'])
    return results



def select_HTTP_warning(path='../test/http.csv'):
    data = HTTP_predict_func_1(path)
    #print(data)
    data = data[data['TF_list'] == 1]
    data_1 = pd.DataFrame({
        'id': data['id'],
        'srcAddress':data['srcAddress'],
        'srcPort':data['srcPort'],
        'destAddress':data['destAddress'],
        'destPort':data['destPort'],
        'requestMethod':data['requestMethod'],
        'host':data['host'],
        'label':data['label'],
        'parameters':data['parameters'],
        'predict_proba':data['predict_proba']

    })
    data_json = data_1.to_json(default_handler=str)
    return json.loads(data_json)


def HTTP_predict_func(data):
    rfc = joblib.load(join(HTTP_MODEL_PATH, "model.pkl"))  # 模型

    test_query = data
    test1 = dp.Transform_single(test_query)
    result1 = rfc.predict(test1)
    results_2 = rfc.predict_proba(test1)

    return result1,results_2


def get_ngrams(query):
    tempQuery = str(query)
    ngrams = []
    for i in range(0,len(tempQuery)-3):
        ngrams.append(tempQuery[i:i+3])
    #print(ngrams)
    return ngrams

# data = ["' or '1'='1\n", '{{ [].class.base.subclasses() }}\n', '{{config.items()}}\n', "{{ ''.__class__.__mro__[2].__subclasses__() }}\n", "{{'a'.toUpperCase()}}\n", "' || myappadmin.adduser('admin', 'newpass') || '", '’ or ‘1’=’1\n', "'||utl_http.request('httP://192.168.1.1/')||'\n", '{% for key, value in config.iteritems() %}<dt>{{ key|e }}</dt><dd>{{ value|e }}</dd>{% endfor %}\n', "{{''.class.mro()[1].subclasses()}}\n"]
# print(HTTP_predict_func(data))

# HTTP_predict_func_1()

#select_TLS_warning()

# print(HTTP_predict_func(['"<DIV STYLE=""background-image:\0075\0072\006C\0028\'\006a\0061\0076\0061\0073\0063\0072\0069\0070\0074\003a\0061\006c\0065\0072\0074\0028.1027\0058.1053\0053\0027\0029\'\0029"">"']))
