import io
import json
import socket
import tempfile
import threading
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import MagicMock, patch

from port_scanner import ScanResult, scan_ports
from port_scanner.cli import main
from port_scanner.validation import parse_ports, validate_target

RESOLVED = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 0))]


class ScannerTests(unittest.TestCase):
    def connection(self, failure=None):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.connect.side_effect = failure
        return connection

    def test_states_and_socket_cleanup(self):
        connections = [self.connection(e) for e in [None, ConnectionRefusedError(), socket.timeout(), OSError('offline'), None]]
        with patch('port_scanner.scanner.socket.getaddrinfo', return_value=RESOLVED), patch('port_scanner.scanner.socket.socket', side_effect=connections):
            results = list(scan_ports('localhost', 8000, 8004, workers=1))
        self.assertEqual([r.status for r in results], ['open', 'closed', 'timeout', 'error', 'open'])
        for index, connection in enumerate(connections):
            connection.connect.assert_called_once_with(('127.0.0.1', 8000 + index))
            connection.__exit__.assert_called_once()

    def test_invalid_parameters_never_resolve(self):
        invalid = [dict(ip='127.1'), dict(ip='bad/name'), dict(start=0), dict(end=65536),
                   dict(start=2, end=1), dict(timeout=0), dict(timeout=float('nan')),
                   dict(timeout=float('inf')), dict(timeout=10**1000), dict(workers=0), dict(workers=257),
                   dict(workers=True), dict(protocol='icmp'), dict(family='5'),
                   dict(protocol='udp', banner=True), dict(ports=[]), dict(ports=[False])]
        with patch('port_scanner.scanner.socket.getaddrinfo') as resolver:
            for options in invalid:
                args = dict(ip='127.0.0.1', start=1, end=2)
                args.update(options)
                with self.subTest(options=options), self.assertRaises(ValueError):
                    list(scan_ports(**args))
            resolver.assert_not_called()

    def test_resolution_error(self):
        with patch('port_scanner.scanner.socket.getaddrinfo', side_effect=socket.gaierror('unknown')), self.assertRaisesRegex(ValueError, 'resolver'):
            list(scan_ports('missing.example'))

    def test_ipv6_scope_and_deduplication(self):
        resolved = [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('fe80::1', 0, 0, 2))] * 2
        connection = self.connection()
        with patch('port_scanner.scanner.socket.getaddrinfo', return_value=resolved), patch('port_scanner.scanner.socket.socket', return_value=connection):
            results = list(scan_ports('fe80::1%2', ports=[80, 80], family='6'))
        self.assertEqual(len(results), 1)
        connection.connect.assert_called_once_with(('fe80::1', 80, 0, 2))

    def test_udp_response_and_silence(self):
        for failure, state in [(None, 'open'), (socket.timeout(), 'open|filtered'), (ConnectionRefusedError(), 'closed')]:
            connection = self.connection()
            connection.recv.side_effect = failure
            with self.subTest(state=state), patch('port_scanner.scanner.socket.getaddrinfo', return_value=RESOLVED), patch('port_scanner.scanner.socket.socket', return_value=connection):
                self.assertEqual(next(scan_ports('localhost', 53, 53, protocol='udp')).status, state)
            connection.send.assert_called_once_with(b'\x00')

    def test_banner_timeout_does_not_change_open_state(self):
        for data, failure in [(b'SSH-2.0-test\r\n\x1b', None), (b'', socket.timeout())]:
            connection = self.connection()
            connection.recv.return_value = data
            connection.recv.side_effect = failure
            with patch('port_scanner.scanner.socket.getaddrinfo', return_value=RESOLVED), patch('port_scanner.scanner.socket.socket', return_value=connection):
                result = next(scan_ports('localhost', 22, 22, banner=True))
            self.assertEqual(result.status, 'open')
            if not failure:
                self.assertEqual(result.banner, 'SSH-2.0-test')

    def test_connections_are_concurrent(self):
        barrier = threading.Barrier(3, timeout=3)
        def factory(*args):
            connection = self.connection()
            connection.connect.side_effect = lambda endpoint: barrier.wait()
            return connection
        with patch('port_scanner.scanner.socket.getaddrinfo', return_value=RESOLVED), patch('port_scanner.scanner.socket.socket', side_effect=factory):
            results = list(scan_ports('localhost', 1, 3, workers=3))
        self.assertEqual([r.status for r in results], ['open'] * 3)

    def test_service_lookup_is_serialized_without_mixing_ports(self):
        active = threading.Lock()
        pause = threading.Event()
        def lookup(port, protocol):
            if not active.acquire(blocking=False):
                raise AssertionError('Consulta de serviços concorrente')
            try:
                pause.wait(0.002)  # Libera a execução para outras threads.
                return f'{protocol}-{port}'
            finally:
                active.release()
        with patch('port_scanner.scanner.socket.getaddrinfo', return_value=RESOLVED), patch('port_scanner.scanner.socket.socket', side_effect=lambda *args: self.connection()), patch('port_scanner.scanner.socket.getservbyport', side_effect=lookup):
            results = list(scan_ports('localhost', ports=range(20, 60), workers=32))
        self.assertEqual([(r.port, r.service) for r in results], [(p, f'tcp-{p}') for p in range(20, 60)])

    def test_unknown_service_keeps_scan_result(self):
        with patch('port_scanner.scanner.socket.getaddrinfo', return_value=RESOLVED), patch('port_scanner.scanner.socket.socket', return_value=self.connection()), patch('port_scanner.scanner.socket.getservbyport', side_effect=OSError('unknown service')):
            result = next(scan_ports('localhost', 65535, 65535))
        self.assertEqual(result.status, 'open')
        self.assertIsNone(result.service)

    def test_port_syntax(self):
        self.assertEqual(parse_ports('443,80,80,8000-8002'), [80, 443, 8000, 8001, 8002])
        for invalid in ['', '0', '1,', '2-1', '1-2-3', '65536']:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                parse_ports(invalid)

    def test_targets(self):
        for target in ['localhost', 'example.org', '127.0.0.1', '::1', 'fe80::1%2', 'ação.example']:
            self.assertTrue(validate_target(target))
        for target in ['', '127.1', '999.2.3.4', 'http://example.org', '-bad.org', 'a..org', 'a b']:
            with self.subTest(target=target), self.assertRaises(ValueError):
                validate_target(target)

    def test_bounded_submission_and_generator_close(self):
        executor = MagicMock()
        executor.submit.return_value.result.return_value = ScanResult(1, 'open')
        with patch('port_scanner.scanner.socket.getaddrinfo', return_value=RESOLVED), patch('port_scanner.scanner.ThreadPoolExecutor', return_value=executor):
            results = scan_ports('localhost', 1, 65535, workers=3)
            next(results)
            self.assertEqual(executor.submit.call_count, 3)
            results.close()
        executor.shutdown.assert_called_once_with(wait=True, cancel_futures=True)


class CliTests(unittest.TestCase):
    def invoke(self, args, results):
        def generated():
            yield from results
        with patch('port_scanner.cli.scan_ports', return_value=generated()), redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()):
            status = main(args)
        return status, out.getvalue()

    def test_json_is_valid_and_filtered(self):
        code, output = self.invoke(['localhost', '-p', '80,81', '--format', 'json', '--open-only'], [ScanResult(80, 'open'), ScanResult(81, 'error', 'offline')])
        self.assertEqual(code, 1)
        self.assertEqual([r['port'] for r in json.loads(output)], [80])

    def test_csv(self):
        code, output = self.invoke(['localhost', '--format', 'csv'], [ScanResult(80, 'open', banner='hello,world')])
        self.assertEqual(code, 0)
        self.assertIn('"hello,world"', output)

    def test_csv_escapes_remote_formulas(self):
        _, output = self.invoke(['localhost', '--format', 'csv'], [ScanResult(80, 'open', banner='=1+1')])
        self.assertIn("'=1+1", output)

    def test_interactive_retries(self):
        with patch('builtins.input', side_effect=['bad/name', 'localhost', '0', '80', '79', '80']):
            code, output = self.invoke([], [ScanResult(80, 'open')])
        self.assertEqual(code, 0)
        self.assertIn('inválido', output)
        self.assertIn('Porta 80 aberta', output)

    def test_invalid_cli(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main(['localhost', '-p', '0']), 2)

    def test_output_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'result.json'
            output.write_text('original')
            code, _ = self.invoke(['localhost', '--output', str(output), '--format', 'json'], [ScanResult(80, 'open')])
            self.assertEqual(code, 2)
            self.assertEqual(output.read_text(), 'original')

    def test_interrupted_json_is_closed(self):
        def interrupted():
            yield ScanResult(80, 'open')
            raise KeyboardInterrupt
        code, output = self.invoke(['localhost', '--format', 'json'], interrupted())
        self.assertEqual(code, 130)
        self.assertEqual(len(json.loads(output)), 1)

    def test_interactive_eof(self):
        with patch('builtins.input', side_effect=EOFError), redirect_stderr(io.StringIO()):
            self.assertEqual(main([]), 130)


if __name__ == '__main__':
    unittest.main()
