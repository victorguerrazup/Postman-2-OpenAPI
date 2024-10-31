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
  'paths': {},
  'components': {
    'securitySchemes': {},
    'parameters': {}
  }
}

ignore_str = 'p2o_ignore'

# Dicionário para armazenar hosts, variáveis e descrição de coleção
hosts = {}
apis = {}
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
      collection_variables.clear()
      if 'p2o_ignore' in  collection_content['info'].get('description', '').lower():
        print(f'Collection ignorada: {collection_file}')
      else:
        collection_descriptions[collection_content['info']['name']] = collection_content['info'].get('description', '')
      for var in collection_content.get('variable', []):
        collection_variables[var['key']] = var['value']
      process_items(collection_content['item'])

# Função para processar os itens da coleção
def process_items(items):
  for item in items:
    if 'p2o_ignore' in item.get('description', ''):
      continue
    if 'item' in item:
      process_items(item['item'])
    if 'request' not in item:
      continue
    if 'p2o_ignore' in item['request'].get('description', ''):
      continue
    current_api = item['request']['url']['path'][0]
    path = '/' + '/'.join(item['request']['url']['path'])
    method = item['request']['method'].lower()
    current_host = '.'.join(item['request']['url']['host'])
      
    # Verifica se o caminho e método já existem
    if current_api not in apis:
      apis[current_api] = copy.deepcopy(openapi_template)
    exists_path_api = apis[current_api]['paths'].get(path) is not None
    exists_path_api_method = apis[current_api]['paths'].get(path, {}).get('method') is not None
    if not exists_path_api:
      apis[current_api]['paths'][path] = {}
    if not exists_path_api_method:
      apis[current_api]['paths'][path][method] = {
        'summary': item['name'],
        'description': item['request'].get('description', ''),
        'parameters': [],
        'responses': {}
      }
      
    process_servers(current_host, item['request']['url'].get('protocol', None), current_api)

    components_in_openapi = apis[current_api]['components']
    method_in_openapi = apis[current_api]['paths'][path][method]
    
    # Processa autenticação, cabeçalhos, parâmetros de URL e corpo da requisição
    process_auth(item['request'].get('auth', {}).get('type', '').lower(), components_in_openapi, method_in_openapi)
    process_headers(item['request'].get('header', []), components_in_openapi, method_in_openapi)
    process_url_parameters(item['request']['url'].get('variable', []), method_in_openapi)
    process_query_parameters(item['request']['url'].get('query', []), method_in_openapi)
    process_request_body(item['request'].get('body'), item['request']['header'], method_in_openapi)
    process_responses(item.get('response', []), method_in_openapi['responses'])

# Função para processar os servidores
def process_servers(host, protocol, api = None):
  processed_host = replace_variables(host)
  if protocol is not None:
    processed_host = f'{protocol}://{processed_host}'
  if type(processed_host) == dict:
    for key in processed_host:
      if not any(server.get('url') == processed_host[key] for server in apis[api]['servers']):
        apis[api]['servers'].append({
          'url': processed_host[key],
          'description': key
        })
  else:
    if not any(server.get('url') == processed_host for server in apis[api]['servers']):
      apis[api]['servers'].append({
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

def process_parameter_value(parameter, value):
  """Processa o valor do parâmetro, ajustando 'example' e 'examples'."""
  if isinstance(value, dict):
    parameter['schema'].pop('example', None)
    parameter['schema']['examples'] = [{'summary': key, 'value': value[key]} for key in value]
  else:
    parameter['schema'].pop('examples', None)
    parameter['schema']['example'] = value

# Função para processar cabeçalhos
def process_headers(headers, components_in_openapi, method_in_openapi):
  for header in headers:
    header_key = header['key'].lower()

    # Processa cabeçalhos de autorização
    if header_key == 'authorization':
      process_auth_header(header, components_in_openapi, method_in_openapi)
      continue

    # Processa cabeçalhos definidos nos parâmetros
    if header_key in parameters:
      ref_value = f'#/components/parameters/{header_key}'
      ref_object = {'$ref': ref_value}
      parameter = copy.deepcopy(parameters[header_key])
      parameter_example = parameter['schema']['example']
      processed_parameter_example = process_variable_name(parameter_example)

      # Substitui variáveis de ambiente ou de coleção
      if processed_parameter_example in collection_variables:
        parameter['schema'].pop('examples', None)
        parameter['schema']['example'] = replace_variables(parameter_example)
      elif processed_parameter_example in environment_variables:
        value = replace_variables(parameter_example)
        process_parameter_value(parameter, value)

      components_in_openapi['parameters'].setdefault(header_key, parameter)
      if not any(param.get('$ref') == ref_value for param in method_in_openapi['parameters']):
        method_in_openapi['parameters'].append(ref_object)
      continue

    # Processa outros cabeçalhos
    if not any(param.get('name') == header['key'] for param in method_in_openapi['parameters']):
      parameter = {
        'name': header['key'],
        'in': 'header',
        'required': False,
        'schema': {'type': 'string', 'example': '', 'examples': []},
      }
      processed_value = process_variable_name(header['value'])

      # Substitui variáveis de ambiente ou de coleção
      if processed_value in environment_variables:
        value = replace_variables(header['value'])
        process_parameter_value(parameter, value)
      elif processed_value in collection_variables:
        parameter['schema'].pop('examples', None)
        parameter['schema']['example'] = replace_variables(header['value'])

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
      parameter = {
        'name': variable['key'],
        'in': 'path',
        'required': True,
        'schema': {'type': 'string', 'example': replace_variables(variable['value'])},
      }
      if 'enum:' in variable.get('description', '').lower():
        enum_values = variable['description'].split(':')[1]
        parameter['schema']['enum'] = [value.strip() for value in enum_values.split(",")]
      method_in_openapi['parameters'].append(parameter)

# Função para processar query parameters
def process_query_parameters(queryParameters, method_in_openapi):
  for query in queryParameters:
    if query['key'] != '':
      parameter = {
      'name': query['key'],
      'in': 'query',
      'required': False,
      'schema': {'type': 'string'},
      'example': replace_variables(query['value'])
      }
      if 'enum:' in query.get('description', '').lower():
        enum_values = query['description'].split(':')[1]
        parameter['schema']['enum'] = [value.strip() for value in enum_values.split(",")]
      method_in_openapi['parameters'].append(parameter)

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
  if body_in_postman is not None:
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
          text = replace_variables(body_in_postman[mode])
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
    text = replace_variables(response_in_postman['body'])
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

# Função para substituir variáveis no texto com base nos dicionários de variáveis de coleção e ambiente.
def replace_variables(text):
  if text is not None:
    processed_text = copy.deepcopy(text)
    variables = re.findall(r'\{\w+\}', text)
    for variable in variables:
      processed_variable = process_variable_name(variable)
      if processed_variable in collection_variables:
        value = collection_variables.get(processed_variable, '')
        processed_text = processed_text.replace(f'"{variable}"', f'"{value}"')
        processed_text = processed_text.replace(variable, str(value) if value != '' else '0')
      elif processed_variable in environment_variables:
        processed_text = environment_variables[processed_variable]
    return processed_text
  return None

# Função para processar o nome de uma variável
def process_variable_name(variable):
  return variable.replace('{', '').replace('}', '')

if __name__ == '__main__':
   # Criando o parser de argumentos
  parser = argparse.ArgumentParser(description='Converte collections do Postman em esquemas OpenAPI')
  
  # Adicionando os argumentos
  parser.add_argument('-d', '--dir', type=str, required=False, default=os.getcwd(), help='Diretório dos arquivos de variáveis de ambiente, de collections e output')
  parser.add_argument('-ed', '--env_dir', type=str, required=False, help='Diretório dos arquivos de variáveis de ambiente')
  parser.add_argument('-ef', '--env_filter', type=str, required=False, default='/*postman_environment.json', help='Filtro dos arquivos de variáveis de ambiente')
  parser.add_argument('-cd','--coll_dir', type=str, required=False, help='Diretório dos arquivos de coleção')
  parser.add_argument('-cf','--coll_filter', type=str, required=False, default='/*postman_collection.json', help='Filtro dos arquivos de coleção')
  parser.add_argument('-o', '--output', type=str, required=False, help='Diretório de saída para os arquivos gerados')
  
  # Parseando os argumentos
  args = parser.parse_args()
  
  env_dir = args.env_dir if args.env_dir is not None else args.dir
  coll_dir = args.coll_dir if args.coll_dir is not None else args.dir
  output = args.output if args.output is not None else args.dir
  
  # Leitura de variáveis de ambiente e arquivos de coleção
  read_environment_variables(env_dir, args.env_filter)
  read_collection_files(coll_dir, args.coll_filter)

  # Criação dos diretórios 'openapi' e 'custom' e salvamento dos arquivos JSON e TXT
  openapi_dir = os.path.join(output, 'openapi')
  custom_dir = os.path.join(output, 'custom')
  
  os.makedirs(openapi_dir, exist_ok=True)
  os.makedirs(custom_dir, exist_ok=True)
  
  for api in apis:
    with open(os.path.join(openapi_dir, f'{process_variable_name(api)}.json'), 'w') as file:
      json.dump(apis[api], file, indent=2)
      
  for coll in collection_descriptions:
    with open(os.path.join(custom_dir, f'{coll.replace('/', '|')}.txt'), 'w') as file:
      file.writelines(collection_descriptions[coll])