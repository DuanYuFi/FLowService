from numpy import *
import joblib
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
import os
from sklearn.ensemble import RandomForestClassifier
import urllib

# def transform():
#     vectorizer = TfidfVectorizer(tokenizer=get_ngrams)
#     test_query = get_query_list('../data/train_data/test.txt')
#     print(test_query)
#     X_test = vectorizer.transform(test_query)
#     return X_test


def dataTransform():
    rce_query_list = get_query_list('../data/train_data/rce.txt')
    sql_query_list = get_query_list('../data/train_data/sql.txt')
    ssti_query_list = get_query_list('../data/train_data/ssti.txt')
    xss_query_list = get_query_list('../data/train_data/xss.txt')
    xxe_query_list = get_query_list('../data/train_data/xxe.txt')
    #test_query_list = get_query_list('../data/train_data/test.txt')

    rce_y = [1 for i in range(0,len(rce_query_list))]
    sql_y = [2 for i in range(0, len(sql_query_list))]
    ssti_y = [3 for i in range(0, len(ssti_query_list))]
    xss_y = [4 for i in range(0, len(xss_query_list))]
    xxe_y = [5 for i in range(0, len(xxe_query_list))]


    queries = rce_query_list + sql_query_list + ssti_query_list + xss_query_list + xxe_query_list
    Y = rce_y + sql_y + ssti_y + xss_y + xxe_y


    vectorizer = TfidfVectorizer(tokenizer=get_ngrams)
    #vectorizer = TfidfVectorizer()
    # 把不规律的文本字符串列表转换成规律的 ( [i,j],tdidf值) 的矩阵X
    # 用于下一步训练分类器 lgs

    #print(queries)
    X = vectorizer.fit_transform(queries)

    #X_test = vectorizer.fit_transform(test_query)


    #shuffled_X, shuffled_Y = shuffle(X, Y)

    # 使用 train_test_split 分割 X y 列表
    # X_train矩阵的数目对应 y_train列表的数目(一一对应)  -->> 用来训练模型
    # X_test矩阵的数目对应 	 (一一对应) -->> 用来测试模型的准确性
    X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.1, random_state=42)  #划分训练样本和测试样本 9：1
    #print(X_test)
    # X_test = vectorizer.transform(test_query)
    # print(X_test)


    rfc = RandomForestClassifier(n_jobs=-1, max_features="auto", random_state=11)    # 采用随机森林分类器
    #print(X_test)
    score = cross_val_score(rfc, X_train, Y_train)
    print('交叉验证准确度：', str(score.mean()))
    # print("X_train:   ")
    # print(X_train)
    # print("X_test:   ")
    # print(X_test)

    rfc.fit(X_train, Y_train)
    #print('*' * 30)
    #a = rfc.predict(X_test)
    #print(a)
    #print('*' * 30)
    # print(Y_test)

    test_query = get_query_list('../data/train_data/test.txt')
    print(test_query)
    X_test = vectorizer.transform(test_query)
    # print(test_query)
    joblib.dump(vectorizer,'../model/vectorizer.pkl')
    results = rfc.predict(X_test)
    print(results)

    tmp = 0
    count = 0
    for res in results:
        if res == Y_test[count]:
            tmp += 1
        count += 1
    print('预测准确度为：', tmp / len(results))
    #
    #print(X_test)
    joblib.dump(rfc, '../model/model.pkl')
    return rfc


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
def get_ngrams(query):
    tempQuery = str(query)
    ngrams = []
    for i in range(0,len(tempQuery)-3):
        ngrams.append(tempQuery[i:i+3])
    #print(ngrams)
    return ngrams