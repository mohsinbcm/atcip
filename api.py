import requests
import json
import time
from pprint import pprint

def getBearerToken():
    grant_type="client_credentials"
    client_id = "6cdfff40-0227-4a4c-b6e1-2a620962a69e"
    client_secret = "OP[u@z/Z/7LdZ3nQjER62nvp91WLQpN6"
    resource = "8ea06436-258f-4d0a-9b9b-5b33883492ea"

    body= {"grant_type":grant_type, "client_id":client_id, "client_secret":client_secret, 'resource':resource}

    bearer_token = None

    auth_url = "https://login.microsoftonline.com/6674bfc2-bad1-429f-921e-f00c522c9af2/oauth2/token"
    response = requests.post(auth_url, data=body)
    json_data = json.loads(response.text)
    bearer_token = (json_data['access_token'])

    headers = {"Authorization": "Bearer "+bearer_token}
    return headers


def createContract(policyno,stdt,endt,suminsured,intrst,prm,coords):
    create_url = "https://stcip-5zlghd-api.azurewebsites.net/api/v1/contracts?workflowId=8&contractCodeId=8&connectionId=1"
    data = {
                "workflowFunctionID": 22,
                "workflowActionParameters": [
                {"name": "policyno","value": str(policyno),"workflowFunctionParameterId": 64},
                {"name": "stdt","value": str(stdt),"workflowFunctionParameterId": 65},
                {"name": "endt","value": str(endt),"workflowFunctionParameterId": 66},
                {"name": "suminsured","value": str(suminsured),"workflowFunctionParameterId": 67},
                {"name": "intrst","value": str(intrst),"workflowFunctionParameterId": 68},
                {"name": "prm","value": str(prm),"workflowFunctionParameterId": 69},
                {"name": "coords","value": str(coords),"workflowFunctionParameterId": 70}
                ]
            }
    res = requests.post(create_url, json=data, headers=getBearerToken())
    res.raise_for_status()
    return res.text

def transferResponsibility(contractID):
    trans_url = "https://stcip-5zlghd-api.azurewebsites.net/api/v2/contracts/{}/actions".format(contractID)
    data = {"workflowFunctionId":29,"workflowActionParameters":[{"name":"ins_pro","value":"0xdaba80c7ea110c2750cd28a95d965c0b89990d80"},{"name":"feedr","value":"0x0e5c1a904c06a8c9a3a3688c57cff923e503ba23"}]}
    res = requests.post(trans_url,headers=getBearerToken(),json=data)
    res.raise_for_status()
    return res.text

def createAndTransfer(policyno,stdt,endt,suminsured,intrst,prm,coords):
    contractID = createContract(policyno,stdt,endt,suminsured,intrst,prm,coords)
    while not getStatus(contractID)>-1:
        pass
    return (contractID,transferResponsibility(contractID))

def getStatus(contractID, text=None):
    try:
        status_url="https://stcip-5zlghd-api.azurewebsites.net/api/v2/contracts/{}".format(contractID)
        res = requests.get(status_url, headers=getBearerToken())
        res.raise_for_status()
        constractprops = res.json()["contractProperties"]
        status = int([dic['value'] for dic in constractprops if dic['workflowPropertyId']==74][0])
        if status>=0 and status<=5:
            if text:
                if status == 3:
                    claim = int([dic['value'] for dic in constractprops if dic['workflowPropertyId']==82][0])
                    return (['Create', 'Insurance not Verified', 'Insured', 'Claim Initiated', 'Terms Void', 'No Claim'][status],claim)
                else:
                    return ['Create', 'Insurance not Verified', 'Insured', 'Claim Initiated', 'Terms Void', 'No Claim'][status]
            else:
                if status == 3:
                    claim = int([dic['value'] for dic in constractprops if dic['workflowPropertyId']==82][0])
                    return status,claim
                else:
                    return status
        else:
            raise ValueError
    except IndexError:
        return -1

if __name__=="__main__":
    # res_url = "https://stcip-5zlghd-api.azurewebsites.net/api/v1/applications/7"

    # res2 = requests.get(res_url, headers=getBearerToken())
    # print(json.dumps(json.loads(res2.text), indent=4))
    # print(createAndTransfer('wwww','2019','2020',4000,1,130,"28E23N"))
    print(transferResponsibility(25))
    # print(json.dumps(getStatus(8), indent=4))
    # print(getStatus(21))
    # print('Use from within the app for now')
    # res = requests.get("https://stcip-5zlghd-api.azurewebsites.net/api/v2/applications/workflows/7",headers=getBearerToken())
    #id=25
    #super shortcut ahead should get this from roleassignment API
    # data = {"workflowFunctionId":25,"workflowActionParameters":[{"name":"ins_pro","value":"0xdaba80c7ea110c2750cd28a95d965c0b89990d80"},{"name":"feedr","value":"0x0e5c1a904c06a8c9a3a3688c57cff923e503ba23"}]}
    # res = requests.post("https://stcip-5zlghd-api.azurewebsites.net/api/v2/contracts/10/actions",headers=getBearerToken(),json=data)
    # print(json.dumps(res.json(), indent=2))
    