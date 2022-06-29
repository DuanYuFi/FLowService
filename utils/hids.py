import requests
import uuid
import json
global_ip="https://proxy.john-doe.fun"


def gethostinfo():
    session = requests.session()
    burp0_url = "{}/login".format(global_ip)
    burp0_cookies = {"beegosessionID": "6214a72e4b5b39b56858c3eb97f5465f"}
    burp0_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:101.0) Gecko/20100101 Firefox/101.0",
                     "Accept": "*/*", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                     "Accept-Encoding": "gzip, deflate",
                     "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                     "X-Requested-With": "XMLHttpRequest", "Origin": "{}", "Referer": "{}/login",
                     "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin",
                     "Te": "trailers", "Connection": "close"}
    burp0_data = {"username": "yulong", "password": "1"}
    login_data = session.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data)
    if json.loads(login_data.text)['status'] != True:
        print("Login Error!!!")

    Cookies = {"beegosessionID": "6214a72e4b5b39b56858c3eb97f5465f"}
    host_list = session.get("{}/json/client?page=1&q=&limit=24".format(global_ip), cookies=burp0_cookies)
    host_json = json.loads(host_list.text)
    # print(host_json)
    host_info = []
    # print(len(host_json))
    for i in host_json:
        host_info_now = session.get("{}/json/info/{}/".format(global_ip, i['ip']))
        host_info.append({"ip": i['ip'], "info": json.loads(host_info_now.text)})
    print(host_info)
    return host_info


def getnotice():
    session = requests.session()
    burp0_url = "{}/login".format(global_ip)
    burp0_cookies = {"beegosessionID": "6214a72e4b5b39b56858c3eb97f5465f"}
    burp0_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:101.0) Gecko/20100101 Firefox/101.0",
                     "Accept": "*/*", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                     "Accept-Encoding": "gzip, deflate",
                     "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                     "X-Requested-With": "XMLHttpRequest", "Origin": "{}", "Referer": "{}/login",
                     "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin",
                     "Te": "trailers", "Connection": "close"}
    burp0_data = {"username": "yulong", "password": "1"}
    login_data = session.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data)
    if json.loads(login_data.text)['status'] != True:
        print("Login Error!!!")

    Cookies = {"beegosessionID": "6214a72e4b5b39b56858c3eb97f5465f"}
    notice=[]
    temp=0
    while True:
        notice_list = session.get("{}/json/notice?status=undeal&page={}".format(global_ip,str(temp)), cookies=burp0_cookies)
        if notice_list.text=="null" or temp > 10:
            # print(notice)
            return notice
        #print(notice_list.text)
        notice_json=json.loads(notice_list.text)

        notice += notice_json
        temp+=1
   # getnotice()


def gettasks():
    session = requests.session()
    burp0_url = "{}/login".format(global_ip)
    burp0_cookies = {"beegosessionID": "6214a72e4b5b39b56858c3eb97f5465f"}
    burp0_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:101.0) Gecko/20100101 Firefox/101.0",
        "Accept": "*/*", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest", "Origin": "{}", "Referer": "{}/login",
        "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin",
        "Te": "trailers", "Connection": "close"}
    burp0_data = {"username": "yulong", "password": "1"}
    login_data = session.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data)
    if json.loads(login_data.text)['status'] != True:
        print("Login Error!!!")

    Cookies = {"beegosessionID": "6214a72e4b5b39b56858c3eb97f5465f"}
    tasks = []
    temp = 0
    while True:
        task_list = session.get("{}/json/tasks?page={}".format(global_ip, str(temp)), cookies=burp0_cookies)
        if (task_list.text == "null"):
            print(tasks)
            return tasks
        task_json = json.loads(task_list.text)
        tasks.append(task_json)
        temp += 1
    # gettasks()


def check_in_ip(ip):
    session = requests.session()
    burp0_url = "{}/login".format(global_ip)
    burp0_cookies = {"beegosessionID": "6214a72e4b5b39b56858c3eb97f5465f"}
    burp0_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:101.0) Gecko/20100101 Firefox/101.0",
        "Accept": "*/*", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest", "Origin": "{}", "Referer": "{}/login",
        "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin",
        "Te": "trailers", "Connection": "close"}
    burp0_data = {"username": "yulong", "password": "1"}
    login_data = session.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data)
    if json.loads(login_data.text)['status'] != True:
        print("Login Error!!!")

    Cookies = {"beegosessionID": "6214a72e4b5b39b56858c3eb97f5465f"}
    host_list = session.get("{}/json/client?page=1&q=&limit=24".format(global_ip), cookies=burp0_cookies)
    host_json = json.loads(host_list.text)
    # print(host_json)
    host_ip = []
    # print(len(host_json))
    for i in host_json:
        host_info_now = session.get("{}/json/info/{}/".format(global_ip, i['ip']))
        host_ip.append(i['ip'])
    if ip in host_ip:
        return True
    else:
        return False


def delete_file(ip, filename):
    session = requests.session()
    burp0_url = "{}/login".format(global_ip)
    burp0_cookies = {"beegosessionID": "6214a72e4b5b39b56858c3eb97f5465f"}
    burp0_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:101.0) Gecko/20100101 Firefox/101.0",
        "Accept": "*/*", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest", "Origin": "{}", "Referer": "{}/login",
        "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin",
        "Te": "trailers", "Connection": "close"}
    burp0_data = {"username": "yulong", "password": "1"}
    login_data = session.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data)
    if json.loads(login_data.text)['status'] != True:
        print("Login Error!!!")

    Cookies = {"beegosessionID": "6214a72e4b5b39b56858c3eb97f5465f"}
    if not check_in_ip(ip):
        return "IP NOT FOUND"
    else:
        # (uuid.uuid4())
        burp0_json = {"command": filename, "host_list": [ip], "name": str(uuid.uuid4()), "type": "delete"}
        task_info = session.post("{}/json/tasks?pass=0".format(str(global_ip)), headers=burp0_headers,
                                 cookies=burp0_cookies, json=burp0_json)
        print(json.loads(task_info.text))
        return task_info.text
    # print(delete_file("172.16.128.2","/tmp/1"))


def kill_proc(ip, procname):
    session = requests.session()
    burp0_url = "{}/login".format(global_ip)
    burp0_cookies = {"beegosessionID": "6214a72e4b5b39b56858c3eb97f5465f"}
    burp0_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:101.0) Gecko/20100101 Firefox/101.0",
        "Accept": "*/*", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest", "Origin": "{}", "Referer": "{}/login",
        "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin",
        "Te": "trailers", "Connection": "close"}
    burp0_data = {"username": "yulong", "password": "1"}
    login_data = session.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data)
    if json.loads(login_data.text)['status'] != True:
        print("Login Error!!!")

    Cookies = {"beegosessionID": "6214a72e4b5b39b56858c3eb97f5465f"}
    if not check_in_ip(ip):
        return "IP NOT FOUND"
    else:
        burp0_json = {"command": procname, "host_list": [ip], "name": str(uuid.UUID), "type": "kill"}
        task_info = session.post("{}/json/tasks?pass=0".format(str(global_ip)), headers=burp0_headers,
                                 cookies=burp0_cookies, json=burp0_json)
        return task_info
    pass
def get_hids_warings():
    result = []
    for each in getnotice():
        detail = json.loads(each['raw'])
        detail.update({
            'source': each['source'],
            'type': each['type']})
        result.append({ "client_name":each['ip'], "data":[
            {
                "uuid": each['_id'],
                "target": each['info'],
                "possibility": "1",
                "timestamp":each['time'],
                "type":each['description'],
                "detail": detail
            }
        ] })
    result = json.dumps(result)
    return result
if __name__ == '__main__':

    a = get_hids_warings()
    print(a)




"""
    host_list=session.get('{}/#!/analyze')
    print(host_list.text)
    ip_list=re.findall(r"b(?:[0-9]{1,3}.){3}[0-9]{1,3}b",host_list.text)
    print(ip_list)"""