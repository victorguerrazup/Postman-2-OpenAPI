# Postman-2-Knowledge-Objects

Funções para transformar coleções do Postman em documentação e disponibilizar através do [Stackspot AI](https://ai.stackspot.com/)

## Funções

### postman2ko

Converte coleções do Postman em knowlwdge objects para o Stackspot AI

Uso: 
```shell
postman2ko.py [-h] [-d DIR] [-o OUTPUT] [-ef ENV_FILTER] [-gf GLOBAL_FILTER] [-cf COLL_FILTER] [-p] [-v] [-V] [-O] [-D]
```

Opções:
```
-h, --help              Mostra a ajuda
-d DIR, --dir DIR       Diretório dos arquivos de variáveis globais e de ambiente, de coleções e saída
-o OUTPUT, --output OUTPUT 
                        Diretório de saída para os arquivos gerados
-ef ENV_FILTER, --env_filter ENV_FILTER
                        Filtro dos arquivos de variáveis de ambiente
-gf GLOBAL_FILTER, --global_filter GLOBAL_FILTER
                        Filtro dos arquivos de variáveis globais
-cf COLL_FILTER, --coll_filter COLL_FILTER
                         Filtro dos arquivos de coleção
-p, --process           Indica que os arquivos devem ser processados
-v, --validate          Indica que os arquivos devem ser validados
-V, --verbose           Indica que a saída será completa
-O, --openapi           Indica que serão gerados arquivos no formato OpenAPI
-D, --doc               Indica que serão gerados arquivos de documentação
```

#### Exemplos

1 - Validar as coleções para gerar documentação apenas:
```shell
postman2ko.py -d ~/collections -vD
```

2 - Validar as coleções para gerar especificações das APIs apenas:
```shell
postman2ko.py -d ~/collections -vO
```

3 - Validar as coleções para gerar documentação e especificações das APIs:
```shell
postman2ko.py -d ~/collections -vOD
```

4 - Processar as coleções para gerar documentação sem validar:
```shell
postman2ko.py -d ~/collections -pD
```

5 - Processar as coleções para gerar especificações das APIs sem validar:
```shell
postman2ko.py -d ~/collections -pO
```

6 - Processar as coleções para gerar documentação e especificações das APIs sem validar:
```shell
postman2ko.py -d ~/collections -pOD
```

7 - Processar as coleções para gerar documentação e especificações das APIs validando antes:
```shell
postman2ko.py -d ~/collections -vpOD
```


### sendo_ko

Envia os knowlwdge objects gerados para o Stackspot AI

Uso:
```shell
send_ko.py [-h] [-ci CLIENT_ID] [-ck CLIENT_KEY] [--ks_openapi KS_OPENAPI] [--ks_custom KS_CUSTOM] -o OPTIONS [-i INPUT]
```

Opções:
```
  -h, --help            Mostra a ajuda
  -ci CLIENT_ID, --client_id CLIENT_ID
                        Client ID para autenticação no Stackspot
  -ck CLIENT_KEY, --client_key CLIENT_KEY
                        Client Key para autenticação no Stackspot
  --ks_openapi KS_OPENAPI
                        Slug do knowledge source para envio dos arquivos OpenAPI
  --ks_custom KS_CUSTOM
                        Slug do knowledge source para envio dos arquivos Custom
  -o OPTIONS, --options OPTIONS
                        Arquivo de opções no formato JSON
  -i INPUT, --input INPUT
                        Diretório de entrada com os arquivos OpenAPI e Custom
```
#### Exemplos

1 - Enviar KOs
```shell
send_ko.py -i ~/collections/KO -o options.json
```

#### Exemplo de arquivo de options

```json
{
    "auth_url": "https://idm.stackspot.com/stk-claro/oidc/oauth/token",
    "stk_ai_url": "https://genai-code-buddy-api.stackspot.com",
    "client_id": "********************", 
    "client_key": "**********************************************************",
    "ks_slug_openapi": "api-ko",
    "ks_slug_custom": "doc-ko"
  }
```