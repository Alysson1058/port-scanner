# Arquitetura

O projeto usa a biblioteca padrão do Python. A interface depende do núcleo; o núcleo não lê entradas nem imprime resultados.

| Módulo | Responsabilidade |
| --- | --- |
| `validation.py` | IPv4/IPv6, domínios IDNA, portas, intervalos e parâmetros |
| `scanner.py` | Resolução, deduplicação de endereços, fila concorrente e sondas |
| `cli.py` | Argumentos, interação, apresentação, exportação e códigos de saída |
| `__init__.py` | API pública `ScanResult` e `scan_ports` |

## Execução

1. A CLI interpreta os argumentos ou solicita alvo e intervalo.
2. O gerador valida os parâmetros antes de executar operações de rede.
3. `getaddrinfo` resolve o alvo na família selecionada e preserva o escopo IPv6.
4. Uma janela de até `workers` tarefas é enviada ao `ThreadPoolExecutor`.
5. Cada tarefa cria seu próprio socket e o fecha com gerenciador de contexto.
6. Resultados imutáveis são entregues em ordem do resolvedor e porta crescente.
7. A CLI escreve texto, JSON ou CSV progressivamente, sem acumular resultados.

A janela limitada evita criar dezenas de milhares de futures. Uma tarefa lenta pode atrasar a apresentação das seguintes, mas as conexões da janela continuam concorrentes. O conjunto de portas ocupa no máximo 65535 entradas. Endereços e portas repetidos são removidos.

## Protocolos e identificação

TCP usa `connect`. UDP usa socket conectado, envia um byte nulo e aguarda um datagrama; silêncio é `open|filtered`. Recusa/reset é `closed`, timeout TCP é `timeout`, demais falhas são `error`. Um erro em uma porta não impede as próximas.

O nome do serviço é apenas uma consulta a `getservbyport`. Um lock compartilhado serializa essa consulta, pois a implementação da libc pode usar memória estática e misturar nomes entre threads. As conexões de rede continuam concorrentes. O banner é leitura passiva opcional, limitada a 1024 bytes e ao timeout. Um timeout no banner não muda o estado TCP aberto. Caracteres de controle são removidos do banner; na saída textual, detalhes remotos usam representação escapada.

## Recursos, erros e exportação

Fechar o gerador cancela tarefas pendentes e aguarda tarefas iniciadas. O resolvedor usa o prazo do sistema operacional; não há garantia de timeout DNS pelo parâmetro da sonda.

Os campos originais de `ScanResult` (`port`, `status`, `error`) foram preservados. Os novos campos têm valores padrão: `address`, `protocol`, `service` e `banner`.

A exportação cria arquivos exclusivamente, sem sobrescrever existentes. JSON é emitido incrementalmente e fechado no bloco de limpeza, inclusive em Ctrl+C. Saídas interrompidas são parciais. Campos CSV que poderiam iniciar fórmulas recebem um apóstrofo de proteção. O CSV é para leitura em planilhas; JSON preserva os valores originais.

Consulte os códigos de saída e a interpretação dos estados no README. O núcleo não exige privilégios administrativos, sockets raw ou ferramentas externas.
