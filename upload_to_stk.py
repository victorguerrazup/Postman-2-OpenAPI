import os
import requests
import json
import argparse
import time

access_token = {'token': 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjAyMTNlYjgwLTEzMzAtNDllZi1iMzIxLTRlNzE2YmQyNmM0OSIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50X2lkX3YyIjoiMDFIQVFZV0pHUEIxRVk1TkVYNjg3UlFSTlAiLCJhY2NvdW50X25hbWUiOiJTVEstQ2xhcm8iLCJhY2NvdW50X3NsdWciOiJzdGstY2xhcm8iLCJhY2NvdW50X3R5cGUiOiJFTlRFUlBSSVNFIiwiYXR0cmlidXRlcyI6e30sImF1ZCI6WyJmNmZmYzQ1YS02N2RjLTQ5MGQtYjFhYS1hYTVmYWNmODNlMWYiXSwiYXpwIjoiZWYzNDBhNzgtZTRiNi00MTEwLTg3MmUtNzc3ZGFmMTdmYzU1IiwiY2xpZW50SWQiOiJmNmZmYzQ1YS02N2RjLTQ5MGQtYjFhYS1hYTVmYWNmODNlMWYiLCJjbGllbnRfaWQiOiJmNmZmYzQ1YS02N2RjLTQ5MGQtYjFhYS1hYTVmYWNmODNlMWYiLCJlbWFpbCI6InZpY3Rvci5ndWVycmFAenVwLmNvbS5iciIsImV4cCI6MTcyODQ0MzE5NiwiZmFtaWx5X25hbWUiOiJHdWVycmEiLCJnaXZlbl9uYW1lIjoiVmljdG9yIiwiaWF0IjoxNzI4NDQxOTk2LCJpc3MiOiJodHRwczovL2F1dGguc3RhY2tzcG90LmNvbS9zdGstY2xhcm8vb2lkYyIsImp0aSI6IkcyVVp1RXNTN3RNbWtrQzR2S2tXYVNIMTFPa0lDVU1KbkZUdnpvZUJXdlB3ZkZ4ZEZhcG5qUjVLVkVkdzZlcUsiLCJtYXhfYWdlIjoxNzI4MTg0OTYyLCJuYW1lIjoiVmljdG9yIEd1ZXJyYSIsIm5iZiI6MTcyODQ0MTk5NiwicHJlZmVycmVkX3VzZXJuYW1lIjoidmljdG9yLmd1ZXJyYUB6dXAuY29tLmJyIiwicmVhbG0iOiJzdGstY2xhcm8iLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsic3R1ZGlvX2FkbWluIiwiZGVmYXVsdCB1c2VyIHJvbGU6IGY1YjI3NDMzLTI1OTItNGI5YS1hMmYyLTcxZGY3N2FmODE1ZCIsImNyZWF0b3IiLCJkZXZlbG9wZXIiLCJhaV9kZXZlbG9wZXIiLCJhY2NvdW50X2FkbWluIl19LCJyb2xlcyI6WyJzdHVkaW9fYWRtaW4iLCJkZWZhdWx0IHVzZXIgcm9sZTogZjViMjc0MzMtMjU5Mi00YjlhLWEyZjItNzFkZjc3YWY4MTVkIiwiY3JlYXRvciIsImRldmVsb3BlciIsImFpX2RldmVsb3BlciIsImFjY291bnRfYWRtaW4iXSwic2NvcGUiOiJhdHRyaWJ1dGVzIHJvbGVzIHByb2ZpbGUgZW1haWwiLCJzdWIiOiJmNmZmYzQ1YS02N2RjLTQ5MGQtYjFhYS1hYTVmYWNmODNlMWYiLCJ0ZW5hbnQiOiJzdGstY2xhcm8iLCJ0ZW5hbnRfaWQiOiJlZjM0MGE3OC1lNGI2LTQxMTAtODcyZS03NzdkYWYxN2ZjNTUiLCJ0b2tlblR5cGUiOiJDTElFTlRfU0VSVklDRV9BQ0NPVU5UIiwidG9rZW5fdHlwZSI6IkNMSUVOVF9QRVJTT05BTCIsInVzZXJfaWQiOiJmNWIyNzQzMy0yNTkyLTRiOWEtYTJmMi03MWRmNzdhZjgxNWQiLCJ1c2VybmFtZSI6InZpY3Rvci5ndWVycmFAenVwLmNvbS5iciJ9.MD8DIrobyL3iURESyUMFosDzfSrDTwc3C_SX8CWGrKFj1xv7w_7r6YkscKBa4WHxQPJJSt255Uyxjb9nF3FuNbH5LO_KzeAV768cC0CiVAWScbZ7AJ5xhaMUe0e8HkoDKvGrhWWYij4ny-gw4KFcUOEi9CWvQQ3WGX8YfH5KLfwbjtdbMAf7jjhHd5VuDHALEwmg7NTB4xa9wT0woZTed4RtuWyOhELwWHA9AkvBlCCcAVnxhOmiqhAKzNZOBQ3qhHFGasRocVObwD9_NNRrOWrYPLlUbGdhW6mI-sSqECpy4NGbLrYnKPY6nBeVLFr2Bin9Du1ucVWTUbLoGsz45-lvso7VTE-6exX9n0P-ne5T0EZuBqPXCTbdzfg8d-J30-XkP0S49-JkDGlCRFZbprxhLBSJcqYLK_RN__pKGl7PR9j4skpFV-cDgfbFny1Bl19cwFlqSrC3m_OQyUylg0uBlHoNo1miphkOWn_lvwxluUO4i5J5eVMo3IcFy3Lia_z2Uv1MLN7IeOtmaTu5ZguYE1jl0SOeO3QdKBZlIAcdarSdhz7Hza0PhBMv_CtK3rAouxauclfXjkyeWyjpdoZpkYF-lzGop04ndG7MufX76xcCZxTroJM3wB5eD036PwBUCREgKqbgCiXdR7hop2wbsU0zJ0eBYaKqnTYhQKc', 'expiry': 1728443196}

options = {
  'auth_url': 'https://idm.stackspot.com/stk-claro/oidc/oauth/token',
  'stk_ai_url': 'https://genai-code-buddy-api.stackspot.com',
  'client_id': 'f6ffc45a-67dc-490d-b1aa-aa5facf83e1f', 
  'client_key': 'z49hwLAnva5l6AyjOfddqVUdrH0nn57eHJ97N1ja8ca27U0CSgcEgr6557uEZO86',
  'ks_slug_openapi': 'claro-flex-apis',
  'ks_slug_custom': 'qa-buddy'
}

def is_token_expired():
  if 'expiry' not in access_token:
    return True
  else:
    return access_token['expiry'] <= int(time.time())

def get_access_token(client_id, client_secret):
  global access_token
  payload = f'client_id={client_id}&grant_type=client_credentials&client_secret={client_secret}'
  headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
  }

  response = requests.request('POST', options['auth_url'], headers=headers, data=payload)

  if response.status_code != 200:
    print(f'Erro ao realizar autenticação\nStatus Code: {response.status_code}\nBody:\n{response.text}')
    exit(-1)
  else:
    access_token = {'token': response.json()['access_token'], 'expiry': int(time.time()) + int(response.json()['expires_in']) }

def get_upload_file_form_data(file_name, file_type):
  token = access_token['token']
  payload = json.dumps({
    'file_name': file_name,
    'target_id': options['ks_slug_openapi'] if file_type == 'openapi' else options['ks_slug_custom'],
    'target_type': 'KNOWLEDGE_SOURCE',
    'expiration': 3600
  })
  headers = {
    'Content-Type': 'application/json',
    'Authorization': f'Bearer {token}'
  }

  response = requests.request('POST', f"{options['stk_ai_url']}/v1/file-upload/form", headers=headers, data=payload)

  if response.status_code != 201:
    print(f'Erro ao recuperar Form Data para o arquivo {file_name}!!\nStatus Code: {response.status_code}\nBody:\n{response.text}')
    exit(-1)
  else:
    return response.json()

def send_file_to_aws(file_name, file_path, form_data):
  payload = {
    'key': form_data['form']['key'],
    'x-amz-algorithm': form_data['form']['x-amz-algorithm'],
    'x-amz-credential': form_data['form']['x-amz-credential'],
    'x-amz-date': form_data['form']['x-amz-date'],
    'x-amz-security-token': form_data['form']['x-amz-security-token'],
    'policy': form_data['form']['policy'],
    'x-amz-signature': form_data['form']['x-amz-signature']
    }
  files=[
    ('file',(file_name ,open(file_path,'rb'),'application/json'))
  ]

  response = requests.request("POST", form_data['url'], headers={}, data=payload, files=files)
  
  if response.status_code != 204:
    print(f"Erro ao enviar o arquivo '{file_name}'\nStatus Code: {response.status_code}\nBody:\n{response.text}")
    exit(-1)

def get_upload_file_status(file_id):
  token = access_token['token']
  headers = {
    'Authorization': f'Bearer {token}'
  }

  response = requests.request('GET', f"{options['stk_ai_url']}/v1/file-upload/{file_id}", headers=headers, data={})

  if response.status_code != 200:
    print(f'Erro ao recuperar o arquivo {file_id}!!\nStatus Code: {response.status_code}\nBody:\n{response.text}')
    exit(-1)
  else:
    return response.json()

def send_custom_ks(file_path, file_type):
  token = access_token['token']
  with open(file_path, 'r') as file:
    content = file.read()
  payload = json.dumps({
    'content': content,
  })
  headers = {
    'Content-Type': 'application/json',
    'Authorization': f'Bearer {token}'
  }

  response = requests.request('POST', f"{options['stk_ai_url']}/v1/knowledge-sources/{options['ks_slug_openapi'] if file_type == 'openapi' else options['ks_slug_custom']}/custom", headers=headers, data=payload)

  if response.status_code != 204:
    print(f'Erro ao recuperar Form Data para o arquivo {file_path}!!\nStatus Code: {response.status_code}\nBody:\n{response.text}')
    exit(-1)
  
# Função para ler e fazer upload dos arquivos de um diretório
def process_directory(directory, type):
  for root, dirs, files in os.walk(directory):
    for dir in dirs:
      process_directory(os.path.join(root, dir), type)
    for file in files:
      file_path = os.path.join(root, file)
      form_data = get_upload_file_form_data(file, type)
      send_file_to_aws(file, file_path, form_data)
      get_upload_file_status(form_data['id'])

def load_options_file(options_file):
  global options
  with open(options_file, 'r') as file:
    options = json.load(file)
    
if __name__ == '__main__':
  # Criando o parser de argumentos
  parser = argparse.ArgumentParser(description='Envia os esquemas no formato OpenAPI para o Stackspot AI')
  
  # Adicionando os argumentos
  parser.add_argument('-ci', '--client_id', type=str, required=False, help='Client ID para autenticação no Stackspot')
  parser.add_argument('-ck', '--client_key', type=str, required=False, help='Client Key para autenticação no Stackspot')
  parser.add_argument('--ks_openapi', type=str, required=False, help='Slug do knowledge source para envio dos arquivos OpenAPI')
  parser.add_argument('--ks_custom', type=str, required=False, help='Slug do knowledge source para envio dos arquivos Custom')
  parser.add_argument('-o', '--options', type=str, required=False, help='Arquivo de opções no formato JSON')
  parser.add_argument('-i', '--input', type=str, required=False, default=os.getcwd(), help='Diretório de entrada com os arquivos OpenAPI e Custom')
  
  # Parseando os argumentos
  args = parser.parse_args()
  
  if args.options != None:
    load_options_file(args.options)
  
  if args.client_id != None:
    options['client_id'] = args.client_id
    
  if args.client_key != None:
    options['client_key'] = args.client_key
    
  if args.ks_openapi != None:
    options['ks_slug_openapi'] = args.ks_openapi
    
  if args.ks_custom != None:
    options['ks_slug_custom'] = args.ks_custom
   
  if is_token_expired():
    get_access_token(options['client_id'], options['client_key'])
  
  openapi_dir = os.path.join(args.input, 'openapi')
  custom_dir = os.path.join(args.input, 'custom')
  
  # Processar os diretórios 'openapi' e 'custom'
  process_directory(openapi_dir, 'openapi')
  process_directory(custom_dir, 'custom')