import re
import pandas as pd
import tldextract
from sklearn.preprocessing import LabelEncoder
from sklearn.datasets import load_files
from sklearn.model_selection  import train_test_split#引入交叉验证函数
from sklearn.feature_extraction.text import TfidfVectorizer# 导入文本特征值得求解库 ，对文本的数据进行处理都是要使用到这个库的
import urllib
import os
import joblib
from os.path import join
from config.common import HTTP_MODEL_PATH



def dataTransform(data):
    getParam = data['getParam']
    postParam = data['postParam']

    payloads = [[] for x in range(0,len(getParam))]
    for i in range(0,len(getParam)):
        # print(getParam[i])
        if ( pd.isna(getParam[i]) and pd.isna(postParam[i]) ):
            payloads[i] = []
        if ( pd.isna(getParam[i]) or pd.isna(postParam[i]) ) :
            try:
                if ( pd.isna(getParam[i]) ):
                    payloads[i] = postParam[i].split('&')
                    for each in range(0,len(payloads[i])):
                        payloads[i][each] = payloads[i][each].split('=')[1]
                if( pd.isna(postParam[i]) ):
                    payloads[i] = getParam[i].split('&')
                    for each in range(0, len(payloads[i])):
                        payloads[i][each] = payloads[i][each].split('=')[1]
            except:
                pass

    return payloads




def Transform_single(data):
    vectorizer1 = joblib.load(join(HTTP_MODEL_PATH, "vectorizer.pkl"))
    X= vectorizer1.transform(data)
    return X



def get_ngrams(query):
    tempQuery = str(query)
    ngrams = []
    for i in range(0,len(tempQuery)-3):
        ngrams.append(tempQuery[i:i+3])
    #print(ngrams)
    return ngrams

def get_query_list(filename):
    directory = str(os.getcwd())
    # directory = str(os.getcwd())+'/module/waf'
    filepath = directory + "/" + filename
    data = open(filepath,'r',encoding="utf-8").readlines()
    query_list = []
    for d in data:
        d = str(urllib.parse.unquote(d))   #converting url encoded data to simple string
        # print(d)
        query_list.append(d)
    return list(set(query_list))

