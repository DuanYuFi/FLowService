# -*- coding: utf-8 -*-
import numpy as np
import pandas as pd


import re
import joblib
import dataprocessing as dp
from sklearn.utils import shuffle
from sklearn.preprocessing import MinMaxScaler
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score


def train_func(train_path):
    data = pd.read_csv(train_path)
    X = dp.dataTransform(data)
    encoders = dp.encoder(X)
    keys = ['O', 'CN', 'Dn', 'Sni', 'Version']
    n = 0
    for key in keys:
        X[key] = encoders[n].transform(X[key])
        n += 1

    joblib.dump(encoders, '../model/encoders.pkl')
    X = MinMaxScaler().fit_transform(X)
    label = data['label']
    Y = label


    shuffled_X, shuffled_Y = shuffle(X, Y)

    X_train, X_test, Y_train, Y_test = train_test_split(shuffled_X, shuffled_Y, test_size=0.1)  #划分训练样本和测试样本 9：1
    rfc = RandomForestClassifier(n_jobs=-1, max_features="auto", random_state=11)    # 采用随机森林分类器
    score = cross_val_score(rfc, X_train, Y_train)
    print('交叉验证准确度：', str(score.mean()))
    rfc.fit(X_train, Y_train)

    results = rfc.predict(X_test)
    tmp = 0
    count = 0
    for res in results:
        if res == Y_test.iloc[count]:
            tmp += 1
        count += 1
    print('预测准确度为：', tmp / len(results))

    joblib.dump(rfc, '../model/model.pkl') # 模型



if __name__ == '__main__':
    train_path = '../data/train.csv'
    train_func(train_path)
