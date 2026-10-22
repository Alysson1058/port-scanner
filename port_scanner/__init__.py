"""API pública do scanner TCP."""
from .scanner import ScanResult, scan_ports

__all__ = ["ScanResult", "scan_ports"]
