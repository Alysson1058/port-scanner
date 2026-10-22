"""CLI interativa ou automatizada, com saída estruturada em streaming."""
import argparse
from contextlib import closing
import csv
from dataclasses import asdict
import json
import sys

from .scanner import ScanResult, scan_ports
from .validation import parse_ports, validate_port, validate_target


def read_ip() -> str:
    while True:
        try:
            return validate_target(input('Digite um IP ou domínio válido: ').strip())
        except ValueError:
            print('IP ou domínio inválido. Digite novamente.')


def read_port(prompt: str, minimum: int = 1) -> int:
    while True:
        try:
            port = validate_port(int(input(prompt)))
            if port < minimum:
                raise ValueError
            return port
        except ValueError:
            print('Porta inválida. Digite novamente.')


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description='Scanner TCP/UDP para IPv4, IPv6 e domínios autorizados.')
    result.add_argument('target', nargs='?', help='IP ou domínio; omitido abre modo interativo')
    result.add_argument('-p', '--ports', default='1-1024', help='Ex.: 22,80,443,8000-8010 (padrão: 1-1024)')
    result.add_argument('--protocol', choices=['tcp', 'udp'], default='tcp')
    result.add_argument('--family', choices=['auto', '4', '6'], default='auto')
    result.add_argument('-t', '--timeout', type=float, default=1.0)
    result.add_argument('-w', '--workers', type=int, default=32, help='Conexões simultâneas: 1-256')
    result.add_argument('--banner', action='store_true', help='Ler até 1024 bytes enviados espontaneamente pelo serviço TCP')
    result.add_argument('--format', choices=['text', 'json', 'csv'], default='text')
    result.add_argument('-o', '--output', help='Criar arquivo novo; não sobrescreve arquivos existentes')
    result.add_argument('--open-only', action='store_true', help='Exibir apenas portas confirmadas abertas')
    return result


class Reporter:
    def __init__(self, stream, format):
        self.stream, self.format, self.first = stream, format, True
        self.csv = None
        if format == 'csv':
            self.csv = csv.DictWriter(stream, fieldnames=list(ScanResult.__dataclass_fields__))
            self.csv.writeheader()
        elif format == 'json':
            stream.write('[\n')

    def write(self, result):
        record = asdict(result)
        if self.format == 'json':
            self.stream.write(('' if self.first else ',\n') + json.dumps(record, ensure_ascii=True))
            self.first = False
        elif self.csv:
            # Conteúdo remoto não deve virar fórmula ao abrir a planilha.
            safe = {key: ("'" + value if isinstance(value, str) and value.lstrip().startswith(('=', '+', '-', '@')) else value)
                    for key, value in record.items()}
            self.csv.writerow(safe)
        else:
            labels = {'open': 'aberta', 'closed': 'fechada', 'timeout': 'sem resposta (timeout)',
                      'open|filtered': 'aberta ou filtrada (sem resposta)', 'error': 'erro de rede'}
            message = f'{result.address} {result.protocol.upper()} Porta {result.port} {labels[result.status]}'
            if result.service:
                message += f' [serviço provável: {result.service}]'
            if result.banner:
                message += f' banner={result.banner!r}'
            if result.error:
                message += f' ({result.error!r})'
            print(message, file=self.stream)

    def finish(self):
        if self.format == 'json':
            self.stream.write('\n]\n')


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    output = None
    reporter = None
    try:
        if args.target is None:
            if args.format != 'text' or args.output:
                raise ValueError('Para exportar, informe o alvo como argumento.')
            args.target = read_ip()
            start = read_port('Digite a porta inicial: ')
            end = read_port('Digite a porta final: ', minimum=start)
            ports = range(start, end + 1)
        else:
            ports = parse_ports(args.ports)
        results = scan_ports(args.target, ports=ports, timeout=args.timeout,
                             workers=args.workers, protocol=args.protocol,
                             family=args.family, banner=args.banner)
        has_errors = False
        with closing(results):
            # Validar e resolver o alvo antes de criar o arquivo de saída.
            first = next(results)
            output = open(args.output, 'x', encoding='utf-8', newline='') if args.output else sys.stdout
            reporter = Reporter(output, args.format)
            def report(result):
                nonlocal has_errors
                has_errors |= result.status == 'error'
                if not args.open_only or result.status == 'open':
                    reporter.write(result)
            report(first)
            for result in results:
                report(result)
        if args.format == 'text':
            print('Mapeamento concluído com erros de rede.' if has_errors else 'Mapeamento realizado com sucesso!', file=sys.stderr)
        return 1 if has_errors else 0
    except (KeyboardInterrupt, EOFError):
        print('\nMapeamento interrompido; resultados exportados podem estar incompletos.', file=sys.stderr)
        return 130
    except (ValueError, OSError) as exc:
        print(f'Erro: {exc}', file=sys.stderr)
        return 2
    finally:
        try:
            if reporter:
                reporter.finish()
            if output is not None:
                output.flush()
        except OSError as exc:
            print(f'Erro ao finalizar saída: {exc}', file=sys.stderr)
            return 2
        finally:
            if output is not None and output is not sys.stdout:
                output.close()
