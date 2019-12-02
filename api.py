import requests
import json
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

res_url = "https://stcip-5zlghd-api.azurewebsites.net/api/v1/applications/"

res2 = requests.get(res_url, headers=headers)
print(res2.text)