# Port Scanner

Scanner TCP/UDP em Python, com IPv4, IPv6, domínios, conexões concorrentes e exportação de resultados. Execute apenas em sistemas próprios ou com autorização.

## Começar

Requer Python 3.10 ou superior. A execução usa somente a biblioteca padrão:

```bash
python3 -m port_scanner
```

Sem argumentos, solicita alvo e intervalo no terminal. O comando original `python3 scanner.py` continua disponível.

Para instalar o comando `port-scanner`, em um ambiente com pip:

```bash
python3 -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install .
port-scanner --help
```

## Exemplos

```bash
# TCP: portas específicas e intervalos, 32 conexões simultâneas por padrão
python3 -m port_scanner localhost -p 22,80,443,8000-8010

# IPv6 ou domínio, escolhendo a família
python3 -m port_scanner ::1 -p 8000 --family 6
python3 -m port_scanner example.org -p 443 --family 4

# Ajustar concorrência e tempo de espera em segundos
python3 -m port_scanner 127.0.0.1 -p 1-1024 --workers 16 --timeout 0.5

# UDP: uma sonda de um byte por porta
python3 -m port_scanner 127.0.0.1 -p 53,123 --protocol udp

# Ler banner espontâneo do servidor TCP
python3 -m port_scanner localhost -p 22 --banner

# JSON ou CSV; o arquivo deve ser novo
python3 -m port_scanner localhost -p 8000-8010 --format json -o resultados.json
python3 -m port_scanner localhost -p 8000-8010 --format csv -o resultados.csv

# Mostrar somente portas confirmadas abertas
python3 -m port_scanner localhost -p 1-1024 --open-only
```

Domínios são resolvidos uma vez e todos os endereços únicos da família selecionada são varridos. Cada resultado inclui o endereço, porta e protocolo. Portas repetidas são removidas; portas válidas vão de 1 a 65535. A ajuda completa está em `python3 -m port_scanner --help`.

`--workers` aceita 1 a 256, padrão 32. O timeout deve ser finito, maior que zero e no máximo 3600 segundos, padrão 1 segundo. A leitura opcional do banner pode consumir mais um timeout após a conexão. Mensagens operacionais vão para stderr para preservar JSON/CSV em stdout.

## Interpretação dos resultados

| Estado | Evidência |
| --- | --- |
| `open` | TCP aceitou a conexão ou UDP respondeu à sonda |
| `closed` | O sistema informou recusa/reset de conexão |
| `timeout` | TCP não respondeu dentro do prazo |
| `open\|filtered` | UDP não respondeu: aberta, filtrada ou resposta perdida |
| `error` | Outro erro de rede ou do sistema; veja `error` |

O campo `service` é um nome **provável**, obtido da tabela de portas do sistema operacional. Não confirma qual software está rodando. `--banner` lê até 1024 bytes enviados espontaneamente por servidores TCP, sem enviar comandos; serviços que esperam uma requisição, usam TLS ou não anunciam versão podem não fornecer banner.

UDP não garante entrega. Uma sonda genérica pode ser ignorada mesmo por um serviço ativo; não há identificação universal de portas UDP por ausência de resposta. Consulte a [RFC 768](https://www.rfc-editor.org/rfc/rfc768).

## API Python

```python
from contextlib import closing
from port_scanner import scan_ports

with closing(scan_ports("localhost", ports=[22, 80, 443], workers=8, timeout=0.5)) as results:
    for result in results:
        print(result.address, result.port, result.status, result.service)
```

A chamada antiga `scan_ports("127.0.0.1", 8000, 8002)` continua válida. Opções adicionais: `protocol="udp"`, `family="4"`/`"6"`/`"auto"`, `banner=True` (somente TCP). A validação e a resolução ocorrem ao iniciar a iteração. Entradas inválidas ou falhas de resolução geram `ValueError`; erros por porta viram resultados `error`. Feche o gerador se interromper a leitura antecipadamente.

## Testar

```bash
# Testes determinísticos; integração é ignorada por padrão
python3 -m unittest discover -s tests -v

# Linux/macOS: incluir conexões reais, apenas no loopback
RUN_NETWORK_TESTS=1 python3 -m unittest discover -s tests -v

# PowerShell
$env:RUN_NETWORK_TESTS = "1"
python -m unittest discover -s tests -v
```

A integração verifica TCP aberto/fechado, banner, UDP com resposta/silêncio, IPv6 e os dois comandos de execução. IPv6 é ignorado se indisponível no sistema. O GitHub Actions está configurado para Linux, Windows e macOS, com Python 3.10 e 3.13; o resultado dessas plataformas depende da execução no GitHub.

## Estrutura

```text
port_scanner/
  __init__.py       API pública
  __main__.py       Entrada como módulo
  cli.py            Argumentos, modo interativo e exportação
  scanner.py        Resolução, concorrência e sondas TCP/UDP
  validation.py     Validação e interpretação das portas
tests/             Testes unitários e integração local
docs/              Arquitetura e publicação
.github/workflows/ Integração contínua
scanner.py         Compatibilidade com a entrada original
pyproject.toml     Metadados e instalação
```

Veja [arquitetura](docs/architecture.md) e [preparação para publicação](docs/publishing.md).

## Códigos de saída e limites da rede

- `0`: varredura concluída sem erros de sistema; inclui portas fechadas e timeouts.
- `1`: uma ou mais sondas produziram `error`, mesmo com `--open-only`.
- `2`: entrada, resolução DNS ou arquivo de saída inválido.
- `130`: interrupção por Ctrl+C ou fim da entrada interativa.

Ctrl+C cancela tarefas pendentes e aguarda as conexões já iniciadas, limitadas pelos timeouts. O JSON é fechado ao interromper normalmente, mas os resultados ficam parciais; consulte o código de saída. Encerramento forçado ou falha de escrita pode deixar o arquivo incompleto.

O timeout das sondas não limita o resolvedor DNS do sistema. Firewalls, perda de pacotes e mudanças nos serviços impedem garantir a classificação de todas as portas. Aumente o timeout ou repita a medição quando necessário. O projeto não realiza fingerprinting ativo de aplicações, varredura de sub-redes ou sondas específicas para cada protocolo UDP.
