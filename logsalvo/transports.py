from __future__ import annotations

import ipaddress
import socket
import ssl

from .models import SenderConfig


class SyslogTransport:
    def __init__(self, config: SenderConfig):
        self.config = config
        self.socket: socket.socket | ssl.SSLSocket | None = None
        self.address: tuple | None = None

    def _bind_address(self, family: socket.AddressFamily) -> tuple | None:
        if not self.config.bind_ip:
            return None
        for info in socket.getaddrinfo(self.config.bind_ip, 0, family, socket.SOCK_DGRAM):
            if info[0] == family:
                return info[4]
        raise OSError(f"source address {self.config.bind_ip!r} does not match destination family")

    def connect(self) -> None:
        self.close()
        socktype = socket.SOCK_DGRAM if self.config.transport == "udp" else socket.SOCK_STREAM
        errors: list[str] = []
        for family, resolved_type, protocol, _, address in socket.getaddrinfo(
            self.config.target, self.config.port, socket.AF_UNSPEC, socktype
        ):
            candidate: socket.socket | ssl.SSLSocket | None = None
            try:
                candidate = socket.socket(family, resolved_type, protocol)
                candidate.settimeout(self.config.timeout)
                bind_address = self._bind_address(family)
                if bind_address:
                    candidate.bind(bind_address)
                if self.config.transport == "tcp":
                    candidate.connect(address)
                    if self.config.tls:
                        context = ssl.create_default_context(
                            cafile=None if self.config.insecure else self.config.cafile
                        )
                        if self.config.insecure:
                            context.check_hostname = False
                            context.verify_mode = ssl.CERT_NONE
                        if self.config.certfile:
                            context.load_cert_chain(self.config.certfile, self.config.keyfile)
                        server_name = self.config.sni
                        if not server_name:
                            try:
                                ipaddress.ip_address(self.config.target)
                            except ValueError:
                                server_name = self.config.target
                        candidate = context.wrap_socket(candidate, server_hostname=server_name)
                self.socket, self.address = candidate, address
                return
            except (OSError, ssl.SSLError) as error:
                errors.append(str(error))
                if candidate:
                    candidate.close()
        raise ConnectionError(
            f"could not connect to {self.config.target}:{self.config.port}: " + "; ".join(errors)
        )

    def send(self, payload: bytes) -> int:
        if self.socket is None or self.address is None:
            self.connect()
        assert self.socket is not None
        if self.config.transport == "udp":
            assert self.address is not None
            return self.socket.sendto(payload, self.address)
        frame = (
            f"{len(payload)} ".encode("ascii") + payload
            if self.config.tcp_framing == "octet"
            else payload + b"\n"
        )
        self.socket.sendall(frame)
        return len(payload)

    def close(self) -> None:
        if self.socket is not None:
            try:
                self.socket.close()
            finally:
                self.socket = None
                self.address = None
