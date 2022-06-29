import requests
import json
import time

def get_honey_warnings():
  url = "https://172.16.128.6:4433/api/v1/attack/detail?api_key=KZmkUoMVfnlmkorRsRdwXqjmbumqikCDXvcHyifBojNmgzOXbWOjMMFDRuAJCBgf"

  payload = json.dumps({
    "start_time": 0,
    "end_time": 0,
    "intranet": -1,
    "source": 0,
    "threat_label": []
  })

  headers = {
    'Content-Type': 'application/json'
  }

  response = requests.post( url, headers=headers, data=payload,verify=False)

  data = json.loads(response.text)
  result = []
  for each in data['data']['detail_list']:
    result.append(
      {
        'client_name':each['service_name'],
        'data': [{
          'uuid':each['client_id'],
          'target':each['attack_ip'],
          'possibility':"1",
          'timestamp':each['create_time'],
          'type':each['threat_name'],
          'detail':{
            'ip_location':each['ip_location'],
            'client_name':each['client_name'],
            'service_port':each['service_port'],
            'threat_level':each['threat_level']
          }
        }]
       }
    )
  result = json.dumps(result)
  return result


if __name__ == "__main__":
  print(get_honey_warnings())