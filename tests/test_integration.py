"""Conexões reais somente em loopback: RUN_NETWORK_TESTS=1 habilita."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import unittest

from port_scanner import scan_ports


@unittest.skipUnless(os.environ.get('RUN_NETWORK_TESTS') == '1', 'habilite RUN_NETWORK_TESTS=1 para sockets locais')
class LoopbackTests(unittest.TestCase):
    def test_tcp_ipv4_banner_and_entrypoints(self):
        with socket.socket() as server:
            server.bind(('127.0.0.1', 0))
            server.listen(4)
            server.settimeout(5)
            port = server.getsockname()[1]
            def serve():
                for _ in range(3):
                    connection, _ = server.accept()
                    with connection:
                        connection.sendall(b'SSH-2.0-local-test\r\n')
            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            result = next(scan_ports('localhost', port, port, family='4', banner=True))
            self.assertEqual(result.status, 'open')
            self.assertEqual(result.banner, 'SSH-2.0-local-test')
            for entry in [['scanner.py'], ['-m', 'port_scanner']]:
                completed = subprocess.run([sys.executable, *entry, '127.0.0.1', '-p', str(port), '--banner', '--format', 'json'], cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=10)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(json.loads(completed.stdout)[0]['status'], 'open')
            thread.join(5)
            self.assertFalse(thread.is_alive())

    def test_tcp_closed(self):
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            port = reserved.getsockname()[1]
        result = next(scan_ports('127.0.0.1', port, port))
        self.assertEqual(result.status, 'closed')

    def test_ipv6(self):
        try:
            server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            server.bind(('::1', 0))
        except OSError as exc:
            if 'server' in locals():
                server.close()
            self.skipTest(f'IPv6 indisponível: {exc}')
        with server:
            server.listen()
            port = server.getsockname()[1]
            result = next(scan_ports('::1', port, port, family='6'))
            self.assertEqual(result.status, 'open')

    def test_udp_reply_and_silent_listener(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(('127.0.0.1', 0))
            server.settimeout(5)
            port = server.getsockname()[1]
            def reply():
                _, address = server.recvfrom(1024)
                server.sendto(b'local-reply', address)
            thread = threading.Thread(target=reply, daemon=True)
            thread.start()
            self.assertEqual(next(scan_ports('127.0.0.1', port, port, protocol='udp')).status, 'open')
            thread.join(5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(next(scan_ports('127.0.0.1', port, port, protocol='udp', timeout=0.05)).status, 'open|filtered')
"""Conexões reais somente em loopback: RUN_NETWORK_TESTS=1 habilita."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import unittest

from port_scanner import scan_ports


@unittest.skipUnless(os.environ.get('RUN_NETWORK_TESTS') == '1', 'habilite RUN_NETWORK_TESTS=1 para sockets locais')
class LoopbackTests(unittest.TestCase):
    def test_tcp_ipv4_banner_and_entrypoints(self):
        with socket.socket() as server:
            server.bind(('127.0.0.1', 0))
            server.listen(4)
            server.settimeout(5)
            port = server.getsockname()[1]
            def serve():
                for _ in range(3):
                    connection, _ = server.accept()
                    with connection:
                        connection.sendall(b'SSH-2.0-local-test\r\n')
            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            result = next(scan_ports('localhost', port, port, family='4', banner=True))
            self.assertEqual(result.status, 'open')
            self.assertEqual(result.banner, 'SSH-2.0-local-test')
            for entry in [['scanner.py'], ['-m', 'port_scanner']]:
                completed = subprocess.run([sys.executable, *entry, '127.0.0.1', '-p', str(port), '--banner', '--format', 'json'], cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=10)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(json.loads(completed.stdout)[0]['status'], 'open')
            thread.join(5)
            self.assertFalse(thread.is_alive())

    def test_tcp_closed(self):
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            port = reserved.getsockname()[1]
        result = next(scan_ports('127.0.0.1', port, port))
        self.assertEqual(result.status, 'closed')

    def test_ipv6(self):
        try:
            server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            server.bind(('::1', 0))
        except OSError as exc:
            if 'server' in locals():
                server.close()
            self.skipTest(f'IPv6 indisponível: {exc}')
        with server:
            server.listen()
            port = server.getsockname()[1]
            result = next(scan_ports('::1', port, port, family='6'))
            self.assertEqual(result.status, 'open')

    def test_udp_reply_and_silent_listener(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(('127.0.0.1', 0))
            server.settimeout(5)
            port = server.getsockname()[1]
            def reply():
                _, address = server.recvfrom(1024)
                server.sendto(b'local-reply', address)
            thread = threading.Thread(target=reply, daemon=True)
            thread.start()
            self.assertEqual(next(scan_ports('127.0.0.1', port, port, protocol='udp')).status, 'open')
            thread.join(5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(next(scan_ports('127.0.0.1', port, port, protocol='udp', timeout=0.05)).status, 'open|filtered')
"""Conexões reais somente em loopback: RUN_NETWORK_TESTS=1 habilita."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import unittest

from port_scanner import scan_ports


@unittest.skipUnless(os.environ.get('RUN_NETWORK_TESTS') == '1', 'habilite RUN_NETWORK_TESTS=1 para sockets locais')
class LoopbackTests(unittest.TestCase):
    def test_tcp_ipv4_banner_and_entrypoints(self):
        with socket.socket() as server:
            server.bind(('127.0.0.1', 0))
            server.listen(4)
            server.settimeout(5)
            port = server.getsockname()[1]
            def serve():
                for _ in range(3):
                    connection, _ = server.accept()
                    with connection:
                        connection.sendall(b'SSH-2.0-local-test\r\n')
            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            result = next(scan_ports('localhost', port, port, family='4', banner=True))
            self.assertEqual(result.status, 'open')
            self.assertEqual(result.banner, 'SSH-2.0-local-test')
            for entry in [['scanner.py'], ['-m', 'port_scanner']]:
                completed = subprocess.run([sys.executable, *entry, '127.0.0.1', '-p', str(port), '--banner', '--format', 'json'], cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=10)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(json.loads(completed.stdout)[0]['status'], 'open')
            thread.join(5)
            self.assertFalse(thread.is_alive())

    def test_tcp_closed(self):
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            result = next(scan_ports('127.0.0.1', *([reserved.getsockname()[1]] * 2)))
        self.assertEqual(result.status, 'closed')

    def test_ipv6(self):
        try:
            server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            server.bind(('::1', 0))
        except OSError as exc:
            if 'server' in locals():
                server.close()
            self.skipTest(f'IPv6 indisponível: {exc}')
        with server:
            server.listen()
            port = server.getsockname()[1]
            result = next(scan_ports('::1', port, port, family='6'))
            self.assertEqual(result.status, 'open')

    def test_udp_reply_and_silent_listener(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(('127.0.0.1', 0))
            server.settimeout(5)
            port = server.getsockname()[1]
            def reply():
                _, address = server.recvfrom(1024)
                server.sendto(b'local-reply', address)
            thread = threading.Thread(target=reply, daemon=True)
            thread.start()
            self.assertEqual(next(scan_ports('127.0.0.1', port, port, protocol='udp')).status, 'open')
            thread.join(5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(next(scan_ports('127.0.0.1', port, port, protocol='udp', timeout=0.05)).status, 'open|filtered')
