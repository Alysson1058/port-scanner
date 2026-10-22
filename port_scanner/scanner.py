"""Varredura concorrente com janela limitada de tarefas e sockets."""
import errno
import socket
from collections import deque
from collections.abc import Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from threading import Lock
from typing import Literal

from .validation import validate_port, validate_scan


# getservbyport pode usar memória estática na libc (MT-Unsafe).
# Compartilhado entre varreduras; somente a consulta local é serializada.
_SERVICE_LOCK = Lock()


@dataclass(frozen=True)
class ScanResult:
    port: int
    status: Literal['open', 'closed', 'timeout', 'open|filtered', 'error']
    error: str | None = None
    address: str = ''
    protocol: str = 'tcp'
    service: str | None = None
    banner: str | None = None


def _probe(family, address, port, protocol, timeout, banner):
    endpoint = (address[0], port, *address[2:])
    service = None
    try:
        with _SERVICE_LOCK:
            service = socket.getservbyport(port, protocol)
    except OSError:
        pass
    details = dict(address=address[0], protocol=protocol, service=service)
    kind = socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM
    try:
        with socket.socket(family, kind) as connection:
            connection.settimeout(timeout)
            connection.connect(endpoint)
            if protocol == 'udp':
                connection.send(b'\x00')
                connection.recv(1024)
            greeting = None
            if protocol == 'tcp' and banner:
                try:
                    data = connection.recv(1024)
                    greeting = ''.join(c if c.isprintable() else ' ' for c in data.decode('utf-8', errors='replace')).strip() or None
                except OSError:
                    pass  # A conexão aceita continua aberta, mesmo sem banner.
            return ScanResult(port, 'open', banner=greeting, **details)
    except (ConnectionRefusedError, ConnectionResetError):
        return ScanResult(port, 'closed', **details)
    except socket.timeout:
        state = 'timeout' if protocol == 'tcp' else 'open|filtered'
        return ScanResult(port, state, **details)
    except OSError as exc:
        if exc.errno in (errno.ECONNREFUSED, errno.ECONNRESET):
            return ScanResult(port, 'closed', **details)
        return ScanResult(port, 'error', str(exc), **details)


def scan_ports(ip: str, start: int = 1, end: int = 1024, timeout: float = 1.0,
               *, ports: Iterable[int] | None = None, workers: int = 32,
               protocol: str = 'tcp', family: str = 'auto', banner: bool = False) -> Iterator[ScanResult]:
    """Varre todos os endereços únicos do alvo. Valida ao iniciar a iteração.

    Resultados seguem a ordem do resolvedor e portas em ordem crescente.
    No máximo `workers` tarefas ficam pendentes; fechar o gerador cancela a fila.
    """
    target = validate_scan(ip, start, end, timeout)
    if isinstance(workers, bool) or not isinstance(workers, int) or not 1 <= workers <= 256:
        raise ValueError('Workers deve ser um inteiro entre 1 e 256.')
    if protocol not in ('tcp', 'udp') or family not in ('auto', '4', '6'):
        raise ValueError('Protocolo ou família de IP inválidos.')
    if not isinstance(banner, bool) or (banner and protocol != 'tcp'):
        raise ValueError('Banner está disponível apenas para TCP.')
    selected = sorted({validate_port(p) for p in ports}) if ports is not None else range(start, end + 1)
    if not selected:
        raise ValueError('Selecione pelo menos uma porta.')
    kind = socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM
    af = {'auto': socket.AF_UNSPEC, '4': socket.AF_INET, '6': socket.AF_INET6}[family]
    try:
        resolved = socket.getaddrinfo(target, 0, af, kind)
    except socket.gaierror as exc:
        raise ValueError(f'Não foi possível resolver o alvo {target}: {exc}') from exc
    endpoints = list(dict.fromkeys((f, addr) for f, _, _, _, addr in resolved if f in (socket.AF_INET, socket.AF_INET6)))
    if not endpoints:
        raise ValueError('Nenhum endereço disponível para a família solicitada.')
    jobs = iter((f, addr, p) for f, addr in endpoints for p in selected)
    executor = ThreadPoolExecutor(max_workers=workers)
    pending = deque()
    try:
        for _ in range(workers):
            job = next(jobs, None)
            if job is None:
                break
            pending.append(executor.submit(_probe, *job, protocol, timeout, banner))
        while pending:
            yield pending.popleft().result()
            job = next(jobs, None)
            if job is not None:
                pending.append(executor.submit(_probe, *job, protocol, timeout, banner))
    finally:
        for future in pending:
            future.cancel()
        executor.shutdown(wait=True, cancel_futures=True)
