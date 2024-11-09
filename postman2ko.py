import os
import json
import glob
import re
import argparse
import sys
from tqdm import tqdm
from datetime import datetime

# Dicionário para armazenar variáveis de ambiente
environment_variables = {}

# Dicionário para armazenar variáveis globais
global_variables = {}

# Dicionário para armazenar as variáveis definidas nas collections.
collection_variables = {}

# Lista de collections do diretório
collections = []

# Lista das itens ignoradas
ignored_items = { 'collections': [], 'folders': [], 'requests': [] }

# Dicionário para armazenar coleções válidas
validated_collections = { 'doc': [], 'openapi': [] }

# Dicionário para armazenar os erros de validação
validation_errors = {}

# String usada para identificar collections que devem ser ignoradas durante o processamento.
ignore_str = 'p2k_ignore'

# String usada para identificar collections que estão em andamento (work in progress) e podem ser ignoradas.
wip_str = 'p2k_wip'

actual_collection = ''

# Função para adicionar um erro de validação a uma collection específica.
# Se a collection ainda não tiver erros registrados, cria uma nova lista para armazená-los.
def add_validation_error(collection, error):
  if validation_errors.get(collection) is None:
    validation_errors[collection] = []
  validation_errors[collection].append(error)
  
# Função para adiocionar um item à lista de ignorados
def add_ignored_item(type, item):
  value = item if type == 'collections' else f'{actual_collection}/{item}'
  if item not in ignored_items[type]:
    ignored_items[type].append(value)

# Função para obter arquivos com base em um filtro e diretório
def get_files(folder, filter='/*.json'):
  return glob.glob(f'{folder}{filter}')

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

# Funções específicas para globais e ambiente
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

# Função para processar o nome de uma variável
def process_variable_name(variable):
  return variable.replace('{{', '').replace('}}', '')

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
    else:
      # Verifica se a descrição contém os títulos obrigatórios
      if '# Pré Requisitos' not in collection_content['info'].get('description', ''):
        add_validation_error(actual_collection, "Título 'Pré Requisitos' ausente.")
      if '# Passo a Passo' not in collection_content['info'].get('description', ''):
          add_validation_error(actual_collection, "Título 'Passo a Passo' ausente.")
      if '# Versionamento' not in collection_content['info'].get('description', ''):
          add_validation_error(actual_collection, "Título 'Versionamento' ausente.")
    if actual_collection not in validation_errors:
      validated_collections['doc'].append(collection)

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
  variables = re.findall(r'\{\{\w+\}\}', str(item_content))
  for variable in map(lambda it: process_variable_name(it), list(set(variables))):
    if not get_variable_value(variable):
      add_validation_error(actual_collection, f"Variável '{variable}' não está definida em nenhum escopo.")
      
# Função para validar o preenchimento da descrição da request
def validate_request_description(item_content):
  request_description = item_content['request'].get('description')
  if request_description == '':
    add_validation_error(actual_collection, f"Requisição '{item_content['name']}' sem descrição.")
      
# Função para validar as requests
def validate_requests(collection_content):
  for item in collection_content.get('item', []):
    if 'item' in item:
      item_description = item.get('description', '')
      if ignore_str in item_description or wip_str in item_description:
        add_ignored_item('folders', item['name'])
        continue
      validate_requests(item)
    if 'request' not in item:
      continue
    request_description = item['request'].get('description', '')
    if ignore_str in request_description or wip_str in request_description:
      add_ignored_item('requests', item['name'])
      continue
    validate_variables_in_requests_exists(item)
    validate_request_description(item)
      
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
    validate_requests(collection_content)
    if actual_collection not in validation_errors:
      validated_collections['openapi'].append(collection)

# Função para validar as coleções
def validate_collections():
  if args.doc:
    validate_doc()
  if args.openapi:
    validate_openapi()

# Função para processar as coleções
def process_collections():
  pass

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

if __name__ == '__main__':
   # Criando o parser de argumentos
  parser = argparse.ArgumentParser(description='Converte collections do Postman em esquemas OpenAPI')
  
  # Adicionando os argumentos
  parser.add_argument('-d', '--dir', type=str, required=False, default=os.getcwd(), help='Diretório dos arquivos de variáveis de ambiente, de collections e output')
  parser.add_argument('-o', '--output', type=str, required=False, help='Diretório de saída para os arquivos gerados')
  parser.add_argument('-ef', '--env_filter', type=str, required=False, default='/*postman_environment.json', help='Filtro dos arquivos de variáveis de ambiente')
  parser.add_argument('-gf','--global_filter', type=str, required=False, default='/*postman_globals.json', help='Filtro dos arquivos de variáeis globais')
  parser.add_argument('-cf','--coll_filter', type=str, required=False, default='/*postman_collection.json', help='Filtro dos arquivos de coleção')
  parser.add_argument('-p', '--process', action='store_true', help='Indica que os arquivos devem ser processados (convertidos)')
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
    
  print_output(logs_dir)