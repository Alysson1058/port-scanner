"""Validação de parâmetros, sem operações de rede."""
from ipaddress import ip_address
from math import isfinite
import re


def validate_ip(value: str) -> str:
    return str(ip_address(value))


def validate_target(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError('Informe um IP ou domínio válido.')
    value = value.strip()
    try:
        return validate_ip(value)
    except ValueError:
        pass
    if ':' in value or '%' in value or re.fullmatch(r'[0-9.]+', value):
        raise ValueError('Endereço IP inválido.')
    try:
        host = value.rstrip('.').encode('idna').decode('ascii')
    except UnicodeError as exc:
        raise ValueError('Domínio inválido.') from exc
    if len(host) > 253 or any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) for label in host.split('.')):
        raise ValueError('Domínio inválido.')
    return host


def validate_port(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ValueError('A porta deve ser um inteiro entre 1 e 65535.')
    return value


def validate_scan(ip: str, start: int, end: int, timeout: float) -> str:
    target = validate_target(ip)
    validate_port(start)
    validate_port(end)
    if end < start:
        raise ValueError('A porta final deve ser maior ou igual à inicial.')
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 3600 or not isfinite(timeout):
        raise ValueError('O timeout deve ser um número finito entre 0 (exclusivo) e 3600 segundos.')
    return target


def parse_ports(value: str) -> list[int]:
    ports = set()
    try:
        for part in value.split(','):
            bounds = part.strip().split('-')
            if len(bounds) == 1:
                ports.add(validate_port(int(bounds[0])))
            elif len(bounds) == 2:
                start, end = (validate_port(int(v)) for v in bounds)
                if end < start:
                    raise ValueError
                ports.update(range(start, end + 1))
            else:
                raise ValueError
    except ValueError as exc:
        raise ValueError('Use portas entre 1 e 65535, como 22,80,8000-8010.') from exc
    return sorted(ports)
