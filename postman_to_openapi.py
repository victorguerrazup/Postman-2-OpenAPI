import os
import json
import glob
import re
import copy
import argparse

# Dicionário para armazenar variáveis de ambiente
environment_variables = {}

# Definição dos parâmetros de cabeçalho
parameters = {
  'x-application-key': {
    'name': 'x-application-key',
    'in': 'header',
    'required': True,
    'schema': {'type': 'string'},
    'example': '{app_key}'
  },
  'x-application-id': {
    'name': 'x-application-id',
    'in': 'header',
    'required': True,
    'schema': {'type': 'string'},
    'example': '{app_id}'
  },
  'x-organization-slug': {
    'name': 'x-organization-slug',
    'in': 'header',
    'required': True,
    'schema': {'type': 'string'},
    'example': '{org_slug}'
  },
  'x-channel-id': {
    'name': 'x-channel-id',
    'in': 'header',
    'required': True,
    'schema': {'type': 'string'},
    'example': '{channel_id}'
  },
  'x-app-version': {
    'name': 'x-app-version',
    'in': 'header',
    'required': True,
    'schema': {'type': 'string'},
    'example': '{app_version}'
  },
  'x-platform-version': {
    'name': 'x-platform-version',
    'in': 'header',
    'required': False,
    'schema': {'type': 'string'},
    'example': '{platform_version}'
  },
  'x-platform': {
    'name': 'x-platform',
    'in': 'header',
    'required': False,
    'schema': {'type': 'string'},
    'example': '{platform}'
  },
  'x-uid': {
    'name': 'x-uid',
    'in': 'header',
    'required': False,
    'schema': {'type': 'string'},
    'example': '{user_id}'
  },
  'x-customer-id': {
    'name': 'x-customer-id',
    'in': 'header',
    'required': False,
    'schema': {'type': 'string'},
    'example': '{customer_id}'
  },
  'x-msisdn': {
    'name': 'x-msisdn',
    'in': 'header',
    'required': False,
    'schema': {'type': 'string'},
    'example': '{msisdn}'
  }
}

# Definição dos esquemas de segurança
security_schemes = {
  'bearerAuth': {
    'type': 'http',
    'scheme': 'bearer',
    'bearerFormat': 'JWT'
  },
  'basicAuth': {
    'type': 'http',
    'scheme': 'Basic'
  }
}

# Template básico do OpenAPI
openapi_template = {
  'openapi': '3.0.0',
  'info': {
    'title': 'APIs',
    'version': '1.0.0'
  },
  'servers': [],
  'paths': {},
  'components': {
    'securitySchemes': {},
    'parameters': {}
  }
}

# Dicionário para armazenar hosts, variáveis e descrição de coleção
hosts = {}
collection_variables = {}
collection_descriptions = {}

# Função para obter arquivos com base em um filtro e diretório
def get_files(folder, filter='/*.json'):
  return glob.glob(f'{folder}{filter}')

# Função para ler variáveis de ambiente de arquivos JSON
def read_environment_variables(environments_dir, environments_filter):
  env_files = get_files(environments_dir, environments_filter)
  if not env_files:
    print('Nenhum arquivo de environment encontrado no diretório.')
    return
  for env_file in env_files:
    with open(env_file, 'r') as file:
      json_content = json.load(file)
      name = re.sub(r'[\s-]+', '_', json_content['name'])
      if 'values' in json_content:
        for variable in json_content['values']:
          key = variable['key']
          environment_variables.setdefault(key, {})[name] = variable['value']
      else:
        print("A chave 'values' não foi encontrada no JSON.")

# Função para ler arquivos de coleção Postman
def read_collection_files(collections_dir, collections_filter):
  collection_files = get_files(collections_dir, collections_filter)
  if not collection_files:
    print('Nenhum arquivo de collection encontrado no diretório.')
    return
  for collection_file in collection_files:
    with open(collection_file, 'r') as file:
      collection_content = json.loads(file.read().replace('{{', '{').replace('}}', '}'))
      if 'description' in collection_content['info'] and collection_content['info']['description'].lower().startswith('stk_ignore'):
        print(f'Collection ignorada: {collection_file}')
        return
      collection_variables.clear()
      if 'description' in collection_content['info']:
        collection_descriptions[collection_content['info']['name']] = collection_content['info']['description']
      for var in collection_content.get('variable', []):
        collection_variables[var['key']] = var['value']
      process_items(collection_content['item'])

# Função para processar os itens da coleção
def process_items(items):
  for item in items:
    if 'item' in item:
      process_items(item['item'])
    if 'request' not in item:
      continue
    path = '/' + '/'.join(item['request']['url']['path'])
    method = item['request']['method'].lower()
    host = '.'.join(item['request']['url']['host'])
    if host not in hosts:
      hosts[host] = copy.deepcopy(openapi_template)
    process_servers(host)

    # Verifica se o caminho e método já existem
    exists_path = hosts[host]['paths'].get(path) != None
    exists_path_method = hosts[host]['paths'].get(path, {}).get('method') != None
    if not exists_path:
      hosts[host]['paths'][path] = {}
    if not exists_path_method:
      hosts[host]['paths'][path][method] = {
        'summary': item['name'],
        'description': item['request'].get('description', ''),
        'parameters': [],
        'responses': {}
      }

    components_in_openapi = hosts[host]['components']
    method_in_openapi = hosts[host]['paths'][path][method]

    # Processa autenticação, cabeçalhos, parâmetros de URL e corpo da requisição
    process_auth(item['request'].get('auth', {}).get('type', '').lower(), components_in_openapi, method_in_openapi)
    process_headers(item['request'].get('header', []), components_in_openapi, method_in_openapi)
    process_url_parameters(item['request']['url'].get('variable', []), method_in_openapi)
    if 'body' in item['request']:
      process_request_body(item['request']['body'], item['request']['header'], method_in_openapi)
    process_responses(item.get('response', []), method_in_openapi['responses'])

# Função para processar os servidores
def process_servers(host):
  processed_host = replace_environment_variables(host)
  if type(processed_host) == dict:
    for key in processed_host:
      if not any(server.get('url') == processed_host[key] for server in hosts[host]['servers']):
        hosts[host]['servers'].append({
          'url': processed_host[key],
          'description': key
        })
  else:
    if not any(server.get('url') == processed_host for server in hosts[host]['servers']):
      hosts[host]['servers'].append({
        'url': processed_host
      })

# Função para processar autenticação
def process_auth(auth_type, components_in_openapi, method_in_openapi):
  if auth_type == 'bearer':
    components_in_openapi['securitySchemes'].setdefault('bearerAuth', security_schemes['bearerAuth'])
    method_in_openapi['security'] = [{'bearerAuth': []}]
  elif auth_type == 'basic':
    components_in_openapi['securitySchemes'].setdefault('basicAuth', security_schemes['basicAuth'])
    method_in_openapi['security'] = [{'basicAuth': []}]

# Função para processar cabeçalhos
def process_headers(headers, components_in_openapi, method_in_openapi):
  for header in headers:
    header_key = header['key'].lower()
    if header_key == 'authorization':
      process_auth_header(header, components_in_openapi, method_in_openapi)
    elif header_key in parameters:
      ref_value = f'#/components/parameters/{header_key}'
      ref_object = {'$ref': ref_value}
      parameter = copy.deepcopy(parameters[header_key])
      parameter_example = parameter['example']
      processed_parameter_example = process_variable_name(parameter_example)
      if processed_parameter_example in environment_variables:
        value = replace_environment_variables(parameter_example)
        if type(value) == dict:
          parameter.pop('example', None)
          parameter['examples'] = []
          for key in value:
            parameter['examples'].append({
              'summary': key,
              'value': value[key]
            })
        else:
          parameter.pop('examples', None)
          parameter['example'] = value
      elif processed_parameter_example in collection_variables:
        parameter.pop('examples', None)
        parameter['example'] = replace_collection_variables(parameter_example)
      components_in_openapi['parameters'].setdefault(header_key, parameter)
      if not any(param.get('$ref') == ref_value for param in method_in_openapi['parameters']):
        method_in_openapi['parameters'].append(ref_object)
    else:
      if not any(param.get('name') == header['key'] for param in method_in_openapi['parameters']):
        parameter = {
          'name': header['key'],
          'in': 'header',
          'required': False,
          'schema': {'type': 'string'},
          'example': '',
          'examples': []
        }
        processed_value = process_variable_name(header['value'])
        if processed_value in environment_variables:
          value = replace_environment_variables(header['value'])
          if type(value) == dict:
            parameter.pop('example', None)
            for key in value:
              parameter['examples'].append({
                'summary': key,
                'value': value[key]
              })
          else:
            parameter.pop('examples', None)
            parameter['example'] = value
        elif processed_value in collection_variables:
          parameter.pop('examples', None)
          parameter['example'] = replace_collection_variables(parameter_example)
        method_in_openapi['parameters'].append(parameter)

# Função para processar cabeçalhos de autenticação
def process_auth_header(header, components_in_openapi, method_in_openapi):
  auth_value = header['value'].lower()
  if auth_value.startswith('bearer'):
    components_in_openapi['securitySchemes'].setdefault('bearerAuth', security_schemes['bearerAuth'])
    method_in_openapi['security'] = [{'bearerAuth': []}]
  elif auth_value.startswith('basic'):
    components_in_openapi['securitySchemes'].setdefault('basicAuth', security_schemes['basicAuth'])
    method_in_openapi['security'] = [{'basicAuth': []}]

# Função para processar parâmetros de URL
def process_url_parameters(variables, method_in_openapi):
  for variable in variables:
    if not any(param.get('name') == variable['key'] for param in method_in_openapi['parameters']):
      method_in_openapi['parameters'].append({
        'name': variable['key'],
        'in': 'path',
        'required': True,
        'schema': {'type': 'string'},
        'example': variable['value']
      })

# Função para processar respostas
def process_responses(responses_in_postman, responses_in_openapi):
  for response in responses_in_postman:
    status_code = str(response['code'])
    if status_code not in responses_in_openapi:
      responses_in_openapi[status_code] = {
        'description': response['name'],
      }
      process_response_body(response, responses_in_openapi[status_code])

# Função para processar o corpo da requisição
def process_request_body(body_in_postman, headers, method_in_openapi):
  if 'requestBody' not in method_in_openapi:
    mode = body_in_postman['mode']
    if mode == 'raw':
      headers = {h['key'].lower(): h['value'].lower() for h in headers}
      is_json_body = (
        'options' in body_in_postman and 
        body_in_postman['options'][mode]['language'] == 'json'
      ) or (
        'content-type' in headers and 
        headers['content-type'] == 'application/json'
      )
      if is_json_body and body_in_postman[mode]:
        method_in_openapi['requestBody'] = {
          'required': True,
          'content': {
            'application/json': {'schema': {} }
          }
        }
        text = replace_collection_variables(body_in_postman[mode])
        raw = json.loads(text)
        method_in_openapi['requestBody']['content']['application/json']['schema']['type'] = type_of_object(raw)
        process_json_raw(raw, method_in_openapi['requestBody']['content']['application/json']['schema'])
    elif mode == 'urlencoded':
      method_in_openapi['requestBody'] = {
        'required': True,
        'content': { 
          'application/x-www-form-urlencoded': {
            'schema': { 
              'type': 'object', 
              'properties': {} 
            } 
          } 
        }
      }
      properties = method_in_openapi['requestBody']['content']['application/x-www-form-urlencoded']['schema']['properties']
      for field in body_in_postman[mode]:
        properties[field['key']] = { 'type': type_of_object(field['value']), 'example': field['value'] }

# Função para processar o corpo da resposta
def process_response_body(response_in_postman, response_in_openapi):
  headers = {header['key'].lower(): header['value'].lower() for header in response_in_postman['header']}
  is_json_body = (
    'content-type' in headers and 
    headers['content-type'] == 'application/json'
  )
  if is_json_body and response_in_postman['body']:
    response_in_openapi['content'] = {
      'application/json': {'schema': {} }
    }
    text = replace_collection_variables(response_in_postman['body'])
    raw = json.loads(text)
    response_in_openapi['content']['application/json']['schema']['type'] = type_of_object(raw)
    process_json_raw(raw, response_in_openapi['content']['application/json']['schema'])

# Função para processar objetos JSON
def process_json_raw(json_raw, object):
  properties = {}
  if 'type' in object and object['type'] == 'object':
    for key in json_raw:
      type_of_key = type_of_object(json_raw[key])
      properties[key] = { 'type': type_of_key }
      if type_of_key == 'object':
        process_json_raw(json_raw[key], properties[key])
      elif type_of_key == 'array':
        properties[key]['items'] = {}
        for item in json_raw[key]:
          properties[key]['items']['type'] = type_of_object(item)
          process_json_raw(item, properties[key]['items'])
      else:
        properties[key]['example'] = json_raw[key]
      object['properties'] = properties
  elif 'type' in object and object['type'] == 'array':
    for item in json_raw:
      object['items'] = {}
      process_json_raw(item, object['items'])

# Função para determinar o tipo de um objeto
def type_of_object(object):
  if type(object) == str:
    return 'string'
  elif type(object) in [int, float, complex]:
    return 'number'
  elif type(object) == bool:
    return 'boolean'
  elif type(object) == dict:
    return 'object'
  elif type(object) == list:
    return 'array'

# Função para substituir variáveis de coleção no texto
def replace_collection_variables(text):
  variables = re.findall(r'\{\w+}', text)
  processed_text = copy.deepcopy(text)
  for variable in variables:
    processed_variable = process_variable_name(variable)
    if processed_variable in collection_variables:
      value = collection_variables.get(processed_variable, '')
      processed_text = processed_text.replace(f'"{variable}"', f'"{value}"')
      processed_text = processed_text.replace(variable, str(value) if value != '' else '0')
  return processed_text

# Função para substituir variáveis de ambiente no texto
def replace_environment_variables(text):
  variables = re.findall(r'\{\w+}', text)
  processed_text = copy.deepcopy(text)
  for variable in variables:
    processed_variable = process_variable_name(variable)
    if processed_variable in environment_variables:
      processed_text = environment_variables[processed_variable]
  return processed_text

# Função para processar o nome de uma variável
def process_variable_name(variable):
  return variable.replace('{', '').replace('}', '')

if __name__ == '__main__':
   # Criando o parser de argumentos
  parser = argparse.ArgumentParser(description='Converte collections do Postman em esquemas OpenAPI')
  
  # Adicionando os argumentos
  parser.add_argument('-ed', '--env_dir', type=str, required=False, default=os.getcwd(), help='Diretório dos arquivos de variáveis de ambiente')
  parser.add_argument('-ef', '--env_filter', type=str, required=False, default='/*postman_environment.json', help='Filtro dos arquivos de variáveis de ambiente')
  parser.add_argument('-cd','--coll_dir', type=str, required=False, default=os.getcwd(), help='Diretório dos arquivos de coleção')
  parser.add_argument('-cf','--coll_filter', type=str, required=False, default='/*postman_collection.json', help='Filtro dos arquivos de coleção')
  parser.add_argument('-o', '--output', type=str, required=False, default=os.getcwd(), help='Diretório de saída para os arquivos gerados')
  
  # Parseando os argumentos
  args = parser.parse_args()
  
  # Leitura de variáveis de ambiente e arquivos de coleção
  read_environment_variables(args.env_dir, args.env_filter)
  read_collection_files(args.coll_dir, args.coll_filter)

  # Criação dos diretórios 'openapi' e 'custom' e salvamento dos arquivos JSON e TXT
  openapi_dir = os.path.join(args.output, 'openapi')
  custom_dir = os.path.join(args.output, 'custom')
  
  os.makedirs(openapi_dir, exist_ok=True)
  os.makedirs(custom_dir, exist_ok=True)
  
  for host in hosts:
    with open(os.path.join(openapi_dir, f'{process_variable_name(host)}.json'), 'w') as file:
      json.dump(hosts[host], file, indent=2)
      
  for coll in collection_descriptions:
    with open(os.path.join(custom_dir, f'{coll}.txt'), 'w') as file:
      file.writelines(collection_descriptions[coll])