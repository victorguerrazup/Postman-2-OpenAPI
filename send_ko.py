import os
import requests
import json
import argparse
import time
import sys
from tqdm import tqdm

access_token = {'token': '', 'expiry': 1728443196}

options = {
  'auth_url': '',
  'stk_ai_url': '',
  'client_id': '', 
  'client_key': '',
  'ks_slug_openapi': '',
  'ks_slug_custom': ''
}

files_to_upload = []

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

def get_upload_file_status(file_id, file_name):
  token = access_token['token']
  headers = {
    'Authorization': f'Bearer {token}'
  }

  max_attempts = 10
  attempts = 0

  while attempts < max_attempts:
    response = requests.request('GET', f"{options['stk_ai_url']}/v1/file-upload/{file_id}", headers=headers, data={})

    if response.status_code != 200:
      print(f'Erro ao recuperar o arquivo {file_name}!!\nStatus Code: {response.status_code}\nBody:\n{response.text}')
      return None
    
    status = response.json().get('status')
    
    if status not in ['NEW', 'ERROR']:
      return response.json()
    elif status == 'ERROR':
      print(f'Erro ao processar o arquivo {file_name}!!\nErro: {response.json().get('error_description', '')}')
      return None

    # Incrementa o número de tentativas e espera 1 segundo antes de tentar novamente
    attempts += 1
    time.sleep(5)

  print(f'Número máximo de tentativas atingido para o arquivo {file_name}.')
  return None

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

def load_files(directory):
  for root, dirs, files in os.walk(directory):
    for dir in dirs:
      load_files(os.path.join(root, dir))
    for file in files:
      files_to_upload.append({'name': file, 'path': os.path.join(root, file)})
      
# Função para ler e fazer upload dos arquivos de um diretório
def process_directory(directory, type):
  load_files(directory)
  for file in tqdm(files_to_upload, desc=f"Processando diretório '{type}'", unit=" arquivo", file=sys.stdout):
    file_path = file['path']
    form_data = get_upload_file_form_data(file['name'], type)
    send_file_to_aws(file['name'], file_path, form_data)
    get_upload_file_status(form_data['id'], file['name'])

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
  parser.add_argument('-o', '--options', type=str, required=True, help='Arquivo de opções no formato JSON')
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