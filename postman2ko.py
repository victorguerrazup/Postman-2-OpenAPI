#!/usr/bin/env python3

import os
import json
import glob
import re
import argparse
import sys
import copy
from tqdm import tqdm
from datetime import datetime

# Definição dos parâmetros de cabeçalho
parameters = {
  'x-application-key': {
    'name': 'x-application-key',
    'in': 'header',
    'required': True,
    'schema': {'type': 'string', 'example': '{app_key}'},
  },
  'x-application-id': {
    'name': 'x-application-id',
    'in': 'header',
    'required': True,
    'schema': {'type': 'string', 'example': '{app_id}'},
  },
  'x-organization-slug': {
    'name': 'x-organization-slug',
    'in': 'header',
    'required': True,
    'schema': {'type': 'string', 'example': '{org_slug}'},
  },
  'x-channel-id': {
    'name': 'x-channel-id',
    'in': 'header',
    'required': True,
    'schema': {'type': 'string', 'example': '{channel_id}'},
  },
  'x-app-version': {
    'name': 'x-app-version',
    'in': 'header',
    'required': True,
    'schema': {'type': 'string', 'example': '{app_version}'},
  },
  'x-platform-version': {
    'name': 'x-platform-version',
    'in': 'header',
    'required': False,
    'schema': {'type': 'string', 'example': '{platform_version}'},
  },
  'x-platform': {
    'name': 'x-platform',
    'in': 'header',
    'required': False,
    'schema': {'type': 'string', 'example': '{platform}'},
  },
  'x-uid': {
    'name': 'x-uid',
    'in': 'header',
    'required': False,
    'schema': {'type': 'string', 'example': '{user_id}'},
  },
  'x-customer-id': {
    'name': 'x-customer-id',
    'in': 'header',
    'required': False,
    'schema': {'type': 'string', 'example': '{customer_id}'},
  },
  'x-msisdn': {
    'name': 'x-msisdn',
    'in': 'header',
    'required': False,
    'schema': {'type': 'string', 'example': '{msisdn}'},
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
  'paths': {}
  # 'components': {
  #   'securitySchemes': {},
  #   'parameters': {}
  # }
}

# Dicionário para armazenar variáveis de ambiente
environment_variables = {}

# Dicionário para armazenar variáveis globais
global_variables = {}

# Dicionário para armazenar as variáveis definidas nas coleções.
collection_variables = {}

# Lista de coleções do diretório
collections = []

# Lista das itens ignoradas
ignored_items = { 'collections': [], 'folders': [], 'requests': [] }

# Dicionário para armazenar coleções válidas
validated_collections = { 'doc': [], 'openapi': [] }

# Dicionário para armazenar os erros de validação
validation_errors = {}

# Dicionário para armazenar as documentações das coleções
docs = {}

# Dicionário para armazenar as documentações OpenAPI das coleções
openapi = {}

# String usada para identificar itens que devem ser ignorados durante o processamento.
ignore_str = 'p2k_ignore'

# String usada para identificar itens que estão em andamento (work in progress) e podem ser ignorados.
wip_str = 'p2k_wip'

actual_collection = ''

current_api = ''

actual_request = { 'path': '', 'method': '' }

# Função para adicionar um erro de validação a uma collection específica.
# Se a collection ainda não tiver erros registrados, cria uma nova lista para armazená-los.
def add_validation_error(collection, error):
  if not validation_errors.get(collection):
    validation_errors[collection] = []
  validation_errors[collection].append(error)
  
# Função para adiocionar um item à lista de ignorados
def add_ignored_item(type, item):
  value = item if type == 'collections' else f'{actual_collection}/{item}'
  if item not in ignored_items[type]:
    ignored_items[type].append(value)

# Função para obter arquivos com base em um filtro e diretório
def get_files(folder, filter='*.json'):
  return glob.glob(f'{folder}/{filter}')

# Função auxiliar para processar o conteúdo de um arquivo de variáveis (globais ou de ambiente)
def process_variable_file(file_path, is_global=False):
    with open(file_path, 'r') as file:
        json_content = json.load(file)
        name = re.sub(r'[\s-]+', '_', json_content['name']) if not is_global else None
        process_variable_values(json_content.get('values', []), name, is_global)

# Função auxiliar para processar as variáveis (globais ou de ambiente)
def process_variable_values(values, name, is_global):
    target_dict = global_variables if is_global else environment_variables
    for variable in values:
        if variable['enabled']:
          key = variable['key']
          if is_global:
              target_dict[key] = variable['value']
          else:
              target_dict.setdefault(key, {})[name] = variable['value']

# Função para ler variáveis de arquivos JSON (globais ou de ambiente)
def read_variables(directory, filter_pattern, is_global=False):
    files = get_files(directory, filter_pattern)
    desc = "Processando variáveis globais" if is_global else "Processando variáveis de ambiente"
    for file_path in tqdm(files, desc=desc, unit=" arquivo", file=sys.stdout):
        process_variable_file(file_path, is_global)

# Funções específicas para variáveis globais, de ambiente e de coleção
def read_global_variables():
    read_variables(args.dir, args.global_filter, is_global=True)

def read_environment_variables():
    read_variables(args.dir, args.env_filter, is_global=False)

def read_collection_variables(collection_content):
  collection_variables.clear()
  for variable in collection_content.get('variable', []):
    collection_variables[variable['key']] = variable['value']

# Função para listar as coleções
def load_collections():
  global collections
  collections = get_files(args.dir, args.coll_filter)

# Função para limpar o conteúdo de um diretório, removendo arquivos, links simbólicos e diretórios vazios.
def clean_dir(dir):
  for file_name in os.listdir(dir):
    file_path = os.path.join(dir, file_name)
    try:
      if os.path.isfile(file_path) or os.path.islink(file_path):
        os.unlink(file_path)  # Remove arquivos ou links simbólicos
      elif os.path.isdir(file_path):
        clean_dir(file_path)
        if len(os.listdir(file_path)) == 0:
          os.rmdir(file_path)  # Remove diretórios vazios
    except Exception as e:
      print(f'Erro ao deletar {file_path}. Motivo: {e}')

# Função para validar as variáveis da coleção
def validate_variables(scope):
  if scope == 'collection':
    variables_to_validate = collection_variables
  elif scope == 'environment':
    variables_to_validate = environment_variables
  elif scope == 'globals':
    variables_to_validate = global_variables
  else:
    variables_to_validate = {}
    
  for variable in variables_to_validate:
    if scope == 'environment':
      for environment in variables_to_validate[variable]:
        if str(variables_to_validate[variable].get(environment, '')).strip() == '':
          add_validation_error(f'{scope}[{environment}]', f"Variável '{variable}' sem valor inicial definido.")
    else:
      if str(variables_to_validate.get(variable, '')).strip() == '':
        add_validation_error(actual_collection if scope == 'collection' else scope, f"Variável '{variable}' sem valor inicial definido.")
  
# Funçao para validar se as variáveis da requisição possuem valor inicial definido em algum escopo
def validate_variables_in_requests_exists(item_content):
  variables = re.findall(r'\{\{\w+\}\}', str(item_content['request']))
  str('')
  for variable in map(lambda it: process_variable_name(it), list(set(variables))):
    if not get_variable_value(variable):
      add_validation_error(actual_collection, f"Variável '{variable}' não está definida em nenhum escopo.")
      
# Função para validar o preenchimento da descrição da request
def validate_request_description(item_content):
  request_description = item_content['request'].get('description')
  if request_description == '':
    add_validation_error(actual_collection, f"Requisição '{item_content['name']}' sem descrição.")
   
# Função para validar a existencia de variáveis
def validate_variables_in_path(item_content):
  for subpath in item_content['request']['url']['path']:
    if re.search(r'\{\{\w+\}\}', subpath):
      add_validation_error(actual_collection, f"Requisição '{item_content['name']}' contém variável no caminho.")

# Função para validar o valor dos parâmetros de URL
def validate_request_url_params(item_content):
  for variable in item_content['request']['url'].get('variable', []):
    if not variable.get('value'):
      add_validation_error(actual_collection, f"Parâmetro de URL '{variable['key']}' da requisição '{item_content['name']}' está vazio.")

# Função para validar o valor dos cabeçalhos da requisição
def validate_request_headers(item_content):
  for header in item_content['request'].get('header', []):
    if not header.get('value'):
      add_validation_error(actual_collection, f"Cabeçalho '{header['key']}' da requisição '{item_content['name']}' está vazio.")

# Função para validar o valor dos parãmetros de consulta da requisição
def validate_request_query_params(item_content):
  for query in item_content['request']['url'].get('query', []):
    if not query.get('value'):
      add_validation_error(actual_collection, f"Parâmetro de consulta '{query['key']}' da requisição '{item_content['name']}' está vazio.")

# Função para validar a existencia de exemplos de resposta
def validate_responses(item_content):
  if not item_content.get('response'):
    add_validation_error(actual_collection, f"Requisição '{item_content['name']}' sem exemplos de resposta.")
    
# Função obter as requisições da coleção
def get_requests(collection_content, validate = False, process = False):
  for item in collection_content.get('item', []):
    item_description = item.get('description', '')
    
    # Ignora pastas com as strings de ignorar ou WIP
    if 'item' in item:
      if ignore_str in item_description or wip_str in item_description:
        add_ignored_item('folders', item['name'])
        continue
      get_requests(item, validate, process)
    
    # Ignora itens que não são requisições
    if 'request' not in item:
      continue
    
    request_description = item['request'].get('description', '')
    
    # Ignora requisições com as strings de ignorar ou WIP
    if ignore_str in request_description or wip_str in request_description:
      add_ignored_item('requests', item['name'])
      continue
    
    # Valida variáveis e descrição da request
    if validate:
      validate_variables_in_requests_exists(item)
      validate_request_description(item)
      validate_variables_in_path(item)
      validate_request_url_params(item)
      validate_request_headers(item)
      validate_request_query_params(item)
      validate_responses(item)
    if process:
      process_request(item)
      process_responses(item)
 
# Função para validar as coleções para gerar documentação
def validate_doc():
  for collection in tqdm(collections, desc='Validando documentação das coleções', unit=" arquivo", file=sys.stdout):
    global actual_collection
    with open(collection, 'r') as file:
      collection_content = json.loads(file.read())
    actual_collection = collection_content['info']['name']
    collection_description = collection_content['info'].get('description', '')
    if ignore_str in collection_description or wip_str in collection_description:
      add_ignored_item('collections', actual_collection)
      continue
    if collection_description == '':
      add_validation_error(actual_collection, 'Descrição vazia')
    # else:
      # Verifica se a descrição contém os títulos obrigatórios
      # if '# Pré Requisitos' not in collection_content['info'].get('description', ''):
      #   add_validation_error(actual_collection, "Título 'Pré Requisitos' ausente.")
      # if '# Passo a Passo' not in collection_content['info'].get('description', ''):
      #     add_validation_error(actual_collection, "Título 'Passo a Passo' ausente.")
      # if '# Versionamento' not in collection_content['info'].get('description', ''):
          # add_validation_error(actual_collection, "Título 'Versionamento' ausente.")
    if actual_collection not in validation_errors:
      validated_collections['doc'].append(collection)
     
# Função para validar as coleções para gerar documentação OpenAPI
def validate_openapi():
  validate_variables('globals')
  validate_variables('environment')
  for collection in tqdm(collections, desc='Validando requisições das coleções', unit=" arquivo", file=sys.stdout):
    global actual_collection
    with open(collection, 'r') as file:
      collection_content = json.loads(file.read())
    actual_collection = collection_content['info']['name']
    collection_description = collection_content['info'].get('description', '')
    if ignore_str in collection_description or wip_str in collection_description:
      add_ignored_item('collections', actual_collection)
      continue
    read_collection_variables(collection_content)
    validate_variables('collection')
    get_requests(collection_content, validate = True)
    if actual_collection not in validation_errors:
      validated_collections['openapi'].append(collection)

# Função para processar as coleções para gerar documentação
def process_doc():
  collections_to_process = validated_collections['doc'] if args.validate else collections
  for collection in tqdm(collections_to_process, desc='Processando documentação das coleções', unit=" arquivo", file=sys.stdout):
    global actual_collection
    with open(collection, 'r') as file:
      collection_content = json.loads(file.read())
    actual_collection = collection_content['info']['name']
    collection_description = collection_content['info'].get('description', '')
    if ignore_str in collection_description or wip_str in collection_description:
      add_ignored_item('collections', actual_collection)
      continue
    docs[actual_collection] = f"# {actual_collection}\n\n{collection_description.replace(ignore_str, '').replace(wip_str, '')}"
    
# Função para processar as coleções para gerar documentação OpenAPI
def process_openapi():
  collections_to_process = validated_collections['openapi'] if args.validate else collections
  for collection in tqdm(collections_to_process, desc='Processando requisições das coleções', unit=" arquivo", file=sys.stdout):
    with open(collection, 'r') as file:
      collection_content = json.loads(file.read())
    get_requests(collection_content, process = True)
    
# Função para ajustar os parâmetros da URL pro formato OpenAPI
def adjust_path_params(url):
  path = '/' + '/'.join(url['path'])
  for variable in url.get('variable', {}):
    path = path.replace(f':{ variable["key"] }', f'{{{ variable["key"] }}}')
  return path

# Função auxiliar para extrair informações da requisição
def extract_request_info(request):
  global current_api
  current_api = request['url']['path'][0]
  path = adjust_path_params(request['url'])
  method = request['method'].lower()
  current_host = '.'.join(request['url']['host'])
  protocol = request['url'].get('protocol', None)
  return path, method, current_host, protocol

# Função auxiliar para inicializar o caminho da API
def initialize_api_path(path, method, request_item):
  openapi.setdefault(current_api, copy.deepcopy(openapi_template))

  exists_path_api = openapi[current_api]['paths'].get(path) is not None
  exists_path_api_method = openapi[current_api]['paths'].get(path, {}).get(method) is not None

  if not exists_path_api:
    openapi[current_api]['paths'][path] = {}

  if not exists_path_api_method:
    openapi[current_api]['paths'][path][method] = {
      'summary': request_item['name'],
      'description': request_item['request'].get('description', request_item['name']),
      'parameters': []
    }

# Função para processar os servidores
def process_servers(host, protocol, api = None):
  processed_host = replace_variables(host)
  if protocol is not None:
    processed_host = f'{protocol}://{processed_host}'
  if type(processed_host) == dict:
    for key in processed_host:
      if not any(server.get('url') == processed_host[key] for server in openapi[api]['servers']):
        openapi[api]['servers'].append({
          'url': processed_host[key],
          'description': key
        })
  else:
    if not any(server.get('url') == processed_host for server in openapi[api]['servers']):
      openapi[api]['servers'].append({
        'url': processed_host
      })

# Função auxiliar para ober o método do path sendo processado
def get_method_in_api():
  return openapi[current_api]['paths'][actual_request['path']][actual_request['method']]

# Função auxiliar para checar se parâmetro existe e cria-lo cso não exista
def parameter_exists(parameters):
  method_in_api = get_method_in_api()
  return not any(param.get('name').lower() == parameters['key'].lower() for param in method_in_api.setdefault('parameters', []))

#Função auxiliar para criar e obter os componentes do OpenAPI
def get_openapi_components():
  openapi.setdefault('components', {})
  return openapi['components']

# Função auxiliar para verificar enumeradores nos parâmetros
def check_enum(subitem, method_in_api):
  if 'enum:' in subitem.get('description', '').lower():
      enum_values = subitem['description'].split(':')[1]
      parameter = list(filter(lambda param: param['name'] == subitem['key'], method_in_api['parameters']))[0]
      parameter['schema']['enum'] = [value.strip() for value in enum_values.split(",")]

#Função auxiliar para criarum novo parâmetro
def create_parameter(name, value, location,  required = False):
  parameter = {
    'name': name,
    'in': location,
    'required': required,
    'schema': {'type': 'string', 'example': '', 'examples': []},
  }
  processed_value = replace_variables(value)

  if isinstance(processed_value, dict):
    parameter['schema'].pop('example', None)
    parameter['schema']['examples'] = [{'summary': key, 'value': processed_value[key]} for key in processed_value]
  else:
    parameter['schema'].pop('examples', None)
    parameter['schema']['example'] = processed_value
  
  return parameter

# Função auxiliar para determinar o tipo de um objeto
def type_of_object(obj):
  if isinstance(obj, str):
    return 'string'
  elif isinstance(obj, (int, float, complex)):
    return 'number'
  elif isinstance(obj, bool):
    return 'boolean'
  elif isinstance(obj, dict):
    return 'object'
  elif isinstance(obj, list):
    return 'array'

# Função para processar objetos JSON
def process_json_raw(json_raw, object):
  properties = {}
  if object.get('type', '') == 'object':
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
  elif object.get('type', '') == 'array':
    for item in json_raw:
      object['items'] = {}
      process_json_raw(item, object['items'])

# Função para processar o texto do corpo
def process_raw_body(body_in_postman, headers, method_in_api):
  is_json_body = is_json_content(body_in_postman, headers)

  if is_json_body and body_in_postman.get('raw'):
    method_in_api['requestBody'] = create_json_request_body()
    raw_data = parse_raw_body(body_in_postman['raw'])
    schema = method_in_api['requestBody']['content']['application/json']['schema']
    schema['type'] = type_of_object(raw_data)
    process_json_raw(raw_data, schema)

# Função para processar corpo urlencoded
def process_urlencoded_body(body_in_postman, method_in_api):
  method_in_api['requestBody'] = create_urlencoded_request_body()
  properties = method_in_api['requestBody']['content']['application/x-www-form-urlencoded']['schema']['properties']

  for field in body_in_postman.get('urlencoded', []):
    properties[field['key']] = {
        'type': type_of_object(field['value']),
        'example': field['value']
    }

# Função auxiliar para normalizar os heaers
def get_normalized_headers(headers):
  return {h['key'].lower(): h['value'].lower() for h in headers}

# Função auxiliar para verificar se o contéudo é JSON
def is_json_content(body_in_postman, headers):
  mode = body_in_postman.get('mode')
  return body_in_postman.get('options', {}).get(mode, {}).get('language', '') == 'json' or 'application/json' in headers.get('content-type', '')
    
# Função auxiliar para criar a estrutura do corpo JSON
def create_json_request_body():
  return {
    'required': True,
    'content': {
      'application/json': {
        'schema': {}
      }
    }
  }

# Função auxiliar para criar a estrutura do corpo URL-encoded
def create_urlencoded_request_body():
  return {
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

# Função auxiliar para substituir variáveis no corpo da requisição
def parse_raw_body(raw_body):
    text = replace_variables(raw_body)
    return json.loads(text)
 
# Função auxiliar para processar o corpo da resposta
def process_response_body(response_in_postman, response_in_openapi):
  headers = get_normalized_headers(response_in_postman['header'])
  is_json_body = 'application/json' in headers.get('content-type', '')
  
  if is_json_body and response_in_postman['body']:
    response_in_openapi['content'] = {
      'application/json': {'schema': {} }
    }
    text = replace_variables(response_in_postman['body'])
    raw = json.loads(text)
    response_in_openapi['content']['application/json']['schema']['type'] = type_of_object(raw)
    process_json_raw(raw, response_in_openapi['content']['application/json']['schema'])
 
# Função para processar os parâmetros da URL
def process_request_url_params(request):
  method_in_api = get_method_in_api()
  for variable in request['url'].get('variable', {}):
    if parameter_exists(variable):
      method_in_api['parameters'].append(create_parameter(variable['key'], variable['value'], 'path', True))
    check_enum(variable, method_in_api)

# Função para processar a autenticação da requisição
def process_request_auth(request):
  method_in_api = get_method_in_api()
  if 'auth' in request:
    components_in_openapi = get_openapi_components()
    auth_type = request['auth']['type'].lower()
    if auth_type == 'bearer':
      components_in_openapi.setdefault('securitySchemes', {}).setdefault('bearerAuth', security_schemes['bearerAuth'])
      method_in_api['security'] = [{'bearerAuth': []}]
    elif auth_type == 'basic':
      components_in_openapi.setdefault('securitySchemes', {}).setdefault('basicAuth', security_schemes['basicAuth'])
      method_in_api['security'] = [{'basicAuth': []}]

# Função para processar cabeçalhos de autenticação
def process_auth_header(header, method_in_api):
  auth_value = header['value'].lower()
  components_in_openapi = get_openapi_components()
  if auth_value.startswith('bearer'):
    components_in_openapi.setdefault('securitySchemes', {}).setdefault('bearerAuth', security_schemes['bearerAuth'])
    method_in_api['security'] = [{'bearerAuth': []}]
  elif auth_value.startswith('basic'):
    components_in_openapi.setdefault('securitySchemes', {}).setdefault('basicAuth', security_schemes['basicAuth'])
    method_in_api['security'] = [{'basicAuth': []}]
    
#Função para processar os cabeçalhos da requisição
def process_request_headers(request):
  method_in_api = get_method_in_api()
  for header in request.get('header', []): 
    header_name = header['key'].lower()

    # Processa cabeçalhos de autorização
    if header_name == 'authorization':
      process_auth_header(header, method_in_api)
      continue
    
    if parameter_exists(header):
      method_in_api['parameters'].append(create_parameter(header_name, header['value'], 'header', not header.get('disabled', False)))
    check_enum(header, method_in_api)

# Função para processar os parêmtros de busca da requisição
def process_request_query_params(request):
  method_in_api = get_method_in_api()
  for query in request.get('query', []): 
    query_name = query['key'].lower()

    if query_name:
      if parameter_exists(query):
        method_in_api['parameters'].append(create_parameter(query_name, query['value'], 'header', not query.get('disabled', False)))
      check_enum(query, method_in_api)

# Função para processar o corpo da requisição
def process_request_body(request):
  method_in_api = get_method_in_api()
  body_in_postman = request.get('body')

  if not body_in_postman:
    return

  if not method_in_api.get('requestBody'):
    mode = body_in_postman.get('mode')
    if mode == 'raw':
      headers = get_normalized_headers(request['header'])
      process_raw_body(body_in_postman, headers, method_in_api)
    elif mode == 'urlencoded':
        process_urlencoded_body(body_in_postman, method_in_api)

# Função para processar as respostas da requisição
def process_responses(item):
  method_in_api = get_method_in_api()
  responses_in_openapi = method_in_api.setdefault('responses', {})
  for response in item.get('response', []):
    status_code = str(response['code'])
    if status_code not in responses_in_openapi:
      responses_in_openapi[status_code] = {
        'description': response['name'],
      }
      process_response_body(response, responses_in_openapi[status_code])
  
# Função para processar a requisição    
def process_request(request_item):
  path, method, current_host, protocol = extract_request_info(request_item['request'])
  actual_request['method'] = method
  actual_request['path'] = path
  
  initialize_api_path(path, method, request_item)
  process_servers(current_host, protocol, current_api)
  
  process_request_url_params(request_item['request'])
  process_request_auth(request_item['request'])
  process_request_headers(request_item['request'])
  process_request_query_params(request_item['request'])
  process_request_body(request_item['request'])

# Função para validar as coleções
def validate_collections():
  if args.doc:
    validate_doc()
  if args.openapi:
    validate_openapi()

# Função para processar as coleções
def process_collections():
  if args.doc:
    process_doc()
  if args.openapi:
    process_openapi()

# Função para processar o nome de uma variável
def process_variable_name(variable):
  return variable.replace('{{', '').replace('}}', '')

# Função para recuperar o valor das variáveis
def get_variable_value(variable):
  processed_variable = process_variable_name(variable)
  if processed_variable in collection_variables:
    return collection_variables[processed_variable]
  elif processed_variable in environment_variables:
    return environment_variables[processed_variable]
  elif processed_variable in global_variables:
    return global_variables[processed_variable]
  else:
    return None

# Função para substituir as variáveis pelo seu valor
def replace_variables(str_to_process):
  variables = re.findall(r'\{\{\w+\}\}', str_to_process)
  processed_str = copy.deepcopy(str_to_process)
  for variable in variables:
    value = get_variable_value(variable)
    if isinstance(value, dict):
      processed_str = value
    else:
      processed_str = processed_str.replace(variable, str(value))
  return processed_str

# Exibe a saída da execução e grava os logs
def print_output(output_dir):
  output_str = ''
  
  if ignored_items['collections'] or ignored_items['folders'] or ignored_items['requests']:
    if ignored_items['collections']:
      output_str += '\n== Coleções ignoradas =='
      for coll in ignored_items['collections']:
        output_str += f'\n  -> {coll}'
    if ignored_items['folders']:
      output_str += '\n== Pastas ignoradas =='
      for folder in ignored_items['folders']:
        output_str += f'\n  -> {folder}'
    if ignored_items['requests']:
      output_str += '\n== Requisições ignoradas =='
      for req in ignored_items['requests']:
        output_str += f'\n  -> {req}'
    output_str += '\n'
    
  if validated_collections['doc'] or validated_collections['openapi']:
    output_str += '\n== Coleções Válidas =='
    if validated_collections['doc']:
      output_str += '\n  => Documentação:'
      for coll in validated_collections['doc']:
        output_str += f'\n    -> {coll}'
    if validated_collections['openapi']:
      output_str += '\n  => OpenAPI'
      for coll in validated_collections['openapi']:
        output_str += f'\n    -> {coll}'
    output_str += '\n'
      
  if validation_errors:
    output_str += '\n== Erros de Validação =='
    for key in validation_errors:
      output_str += f'\n  => {key}'
      for error in validation_errors[key]:
        output_str += f'\n    -> {error}'
    output_str += '\n'
  
  if args.verbose:
    print(output_str)
      
    # if args.process:
    #   print('\n== Collections Processadas ==')
    #   for coll in processed_collections:
    #     print(f'- {coll}')
        
    # if processing_errors:
    #   print('\n== Erros de Validação ==')
    #   for key in processing_errors:
    #     print(f'- {key}')
    #     for error in processing_errors[key]:
    #       print(f'  - {error}')
  else:
    print('')
    if ignored_items['collections']:
      print(f'Coleções ignoradas: {len(ignored_items["collections"])}')
      
    if args.validate:
      print(f'Coleções com documentação válida: {len(validated_collections["doc"])}')
      print(f'Coleções com requisições válidas: {len(validated_collections["openapi"])}')
        
    if validation_errors:
      sum = 0
      for key in validation_errors:
        sum += len(validation_errors[key])
      print(f'Erros de validação: {sum}')
      
  with open(os.path.join(output_dir, f"log-{datetime.now().strftime('%Y-%m-%d-%H-%M-%S')}.txt"), 'w') as log:
    log.writelines(output_str)
      
    # if args.process:
    #   print(f'Collections Processadas: {len(processed_collections)}')
        
    # if processing_errors:
    #   print(f'Erros de Processamento: {len(processing_errors)}')

#Função para escrever os arquivos de saída
def write_files(dir, files_dict, files_extension):
  for key in files_dict:
    with open(os.path.join(dir, f'{key}.{files_extension}'), 'w') as file:
      if files_extension == 'json':
        json.dump(files_dict[key], file, indent=2)
      else:
        file.writelines(files_dict[key])
  pass

if __name__ == '__main__':
   # Criando o parser de argumentos
  parser = argparse.ArgumentParser(description='Converte coleções do Postman em knowlwdge objects para o Stackspot AI')
  
  # Adicionando os argumentos
  parser.add_argument('-d', '--dir', type=str, required=False, default=os.getcwd(), help='Diretório dos arquivos de variáveis globais e de ambiente, de coleções e dos arquivos de saída')
  parser.add_argument('-o', '--output', type=str, required=False, help='Diretório de saída para os arquivos gerados')
  parser.add_argument('-ef', '--env_filter', type=str, required=False, default='*postman_environment.json', help='Filtro dos arquivos de variáveis de ambiente')
  parser.add_argument('-gf','--global_filter', type=str, required=False, default='*postman_globals.json', help='Filtro dos arquivos de variáveis globais')
  parser.add_argument('-cf','--coll_filter', type=str, required=False, default='*postman_collection.json', help='Filtro dos arquivos de coleção')
  parser.add_argument('-p', '--process', action='store_true', help='Indica que os arquivos devem ser processados')
  parser.add_argument('-v', '--validate', action='store_true', help='Indica que os arquivos devem ser validados')
  parser.add_argument('-V', '--verbose', action='store_true', help='Indica que a saída será completa')
  parser.add_argument('-O', '--openapi', action='store_true', help='Indica que serão gerados arquivos no formato OpenAPI')
  parser.add_argument('-D', '--doc', action='store_true', help='Indica que serão gerados arquivos de documentação')
  
  # Parseando os argumentos
  args = parser.parse_args()
  
  output = args.output if args.output is not None else args.dir
  
  # Criação dos diretórios 'openapi' e 'custom' e salvamento dos arquivos JSON e TXT
  openapi_dir = os.path.join(output, 'KO', 'openapi')
  custom_dir = os.path.join(output, 'KO', 'custom')
  logs_dir = os.path.join(output, 'KO', 'logs')
  
  os.makedirs(openapi_dir, exist_ok=True)
  os.makedirs(custom_dir, exist_ok=True)
  os.makedirs(logs_dir, exist_ok=True)
  
  clean_dir(openapi_dir)
  clean_dir(custom_dir)
  
  read_global_variables()
  read_environment_variables()
  load_collections()
  
  if args.validate:
    validate_collections()
  
  if args.process:
    process_collections()
    write_files(custom_dir, docs, 'txt')
    write_files(openapi_dir, openapi, 'json')
    
  print_output(logs_dir)
