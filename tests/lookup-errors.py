#!/usr/bin/env python3
"""Exercise glibc NSS keyed lookups against a synthetic loopback LDAP peer.

Configure with --with-ldap-conf-file="$PWD/lookup-test.conf", then build and run:
  python3 tests/lookup-errors.py ./nss_ldap.so "$PWD/lookup-test.conf"
No installation, root privileges, real directory, or credentials are needed.
The configuration path must not exist; the test creates and removes it. Use a
dedicated build: the system NSS configuration is not changed. Linux/glibc and
Python 3 are required.
"""

import ctypes as C
import errno
import json
import os
from pathlib import Path
import resource
import socket
import subprocess
import sys
import threading


def tlv(tag, data):
    size = len(data)
    encoded = size.to_bytes(max(1, (size.bit_length() + 7) // 8), "big")
    length = bytes([size]) if size < 128 else bytes([0x80 | len(encoded)]) + encoded
    return bytes([tag]) + length + data


def integer(value):
    encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if encoded[0] & 128:
        encoded = b"\0" + encoded
    return tlv(2, encoded)


def string(value):
    return tlv(4, value.encode("ascii"))


def message(number, operation):
    return tlv(0x30, integer(number) + operation)


def read_value(connection):
    def exact(size):
        result = b""
        while len(result) < size:
            part = connection.recv(size - len(result))
            if not part:
                raise EOFError
            result += part
        return result

    tag, size = exact(2)
    if size & 128:
        size = int.from_bytes(exact(size & 127), "big")
    if size > 65536:
        raise ValueError("unexpectedly large test packet")
    return tag, exact(size)


class Peer:
    def __init__(self, kind, scenario):
        self.kind, self.scenario = kind, scenario
        self.searches = self.binds = 0
        self.errors = []
        self.stop = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with connection:
                connection.settimeout(2)
                try:
                    self.respond(connection)
                except (EOFError, ConnectionResetError, BrokenPipeError, socket.timeout):
                    pass
                except Exception as error:
                    self.errors.append(str(error))

    def respond(self, connection):
        while not self.stop.is_set():
            tag, request = read_value(connection)
            assert tag == 0x30 and request[0] == 2
            # Test message IDs are small, using the short BER length form.
            length = request[1]
            assert 0 < length < 128
            number = int.from_bytes(request[2:2 + length], "big")
            operation = request[2 + length]
            if operation == 0x60:  # BindRequest
                self.binds += 1
                connection.sendall(message(number, tlv(0x61, tlv(10, b"\0") + string("") * 2)))
            elif operation == 0x63:  # SearchRequest
                self.searches += 1
                if self.searches > 1 and (self.scenario.startswith("outage") or
                                         (self.scenario == "recovery" and self.searches == 2)):
                    return
                if self.scenario != "missing":
                    if self.kind == "passwd":
                        attributes = {"objectClass": ["top", "posixAccount"],
                                      "uid": ["testuser"], "uidNumber": ["200001"],
                                      "gidNumber": ["200002"], "cn": ["Test User"],
                                      "homeDirectory": ["/nonexistent"], "loginShell": ["/bin/false"]}
                        dn = "uid=testuser,dc=test"
                    else:
                        attributes = {"objectClass": ["top", "posixGroup"],
                                      "cn": ["testgroup"], "gidNumber": ["200002"],
                                      "memberUid": ["testuser"]}
                        dn = "cn=testgroup,dc=test"
                    fields = b"".join(tlv(0x30, string(key) + tlv(0x31, b"".join(string(v) for v in values)))
                                      for key, values in attributes.items())
                    connection.sendall(message(number, tlv(0x64, string(dn) + tlv(0x30, fields))))
                connection.sendall(message(number, tlv(0x65, tlv(10, b"\0") + string("") * 2)))
            elif operation == 0x42:  # UnbindRequest
                return
            elif operation != 0x50:  # AbandonRequest
                raise ValueError("unexpected LDAP operation: " + hex(operation))

    def close(self):
        self.stop.set()
        self.listener.close()
        self.thread.join(timeout=3)
        assert not self.thread.is_alive(), "test peer did not stop"


class Passwd(C.Structure):
    _fields_ = [("name", C.c_char_p), ("passwd", C.c_void_p), ("uid", C.c_uint),
                ("gid", C.c_uint), ("gecos", C.c_void_p), ("directory", C.c_void_p),
                ("shell", C.c_void_p)]


class Group(C.Structure):
    _fields_ = [("name", C.c_char_p), ("passwd", C.c_void_p), ("gid", C.c_uint),
                ("members", C.POINTER(C.c_char_p))]


APIS = {
    "getpwuid_r": (Passwd, C.c_uint, 200001, "passwd"),
    "getpwnam_r": (Passwd, C.c_char_p, b"testuser", "passwd"),
    "getgrgid_r": (Group, C.c_uint, 200002, "group"),
    "getgrnam_r": (Group, C.c_char_p, b"testgroup", "group"),
}
SCENARIOS = ("success", "missing", "small_buffer", "outage_zero", "outage_sentinel", "recovery")


def probe(library, api, scenario):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    module = C.CDLL(library, use_errno=True)
    structure, key_type, key, kind = APIS[api]
    lookup = getattr(module, "_nss_ldap_" + api)
    lookup.argtypes = [key_type, C.POINTER(structure), C.c_void_p, C.c_size_t, C.POINTER(C.c_int)]
    lookup.restype = C.c_int

    def call(initial=0, size=65536):
        record, buffer, error = structure(), C.create_string_buffer(size), C.c_int(initial)
        status = lookup(key, C.byref(record), buffer, size, C.byref(error))
        if status == 1:
            assert record.gid == 200002
            assert record.name == (b"testuser" if kind == "passwd" else b"testgroup")
            if kind == "passwd":
                assert record.uid == 200001
            else:
                assert record.members[0] == b"testuser"
        return status, error.value

    if scenario.startswith("outage") or scenario == "recovery":
        assert call()[0] == 1, "warm-up lookup failed"
    observed = call(77 if scenario == "outage_sentinel" else 0,
                    1 if scenario == "small_buffer" else 65536)
    expected = ((-1, errno.EIO) if scenario.startswith("outage") else
                (-2, errno.ERANGE) if scenario == "small_buffer" else
                (0, 0) if scenario == "missing" else (1, 0))
    print(json.dumps({"observed": observed, "expected": expected}), flush=True)
    return observed == expected


def main(library, config):
    library = str(Path(library).resolve(strict=True))
    config = Path(config).absolute()
    if os.fsencode(config) + b"\0" not in Path(library).read_bytes():
        raise SystemExit("configuration path must match --with-ldap-conf-file in this build")
    if os.getuid() != os.geteuid() or os.getgid() != os.getegid():
        raise SystemExit("NSS_LDAP_CONFIG_FILE requires matching real/effective IDs")
    failures = 0
    print("Testing 24 cases: 4 keyed APIs x 6 scenarios", flush=True)
    # Exclusive creation prevents overwriting an existing configuration.
    with config.open("x") as config_file:
        try:
            for api, (_, _, _, kind) in APIS.items():
                for scenario in SCENARIOS:
                    peer = Peer(kind, scenario)
                    try:
                        config_file.seek(0)
                        config_file.truncate()
                        config_file.write(f"uri ldap://127.0.0.1:{peer.port}\nbase dc=test\nldap_version 3\n"
                                          "bind_policy soft\nnss_connect_policy persist\n"
                                          "nss_reconnect_tries 1\nnss_reconnect_maxconntries 2\n"
                                          "bind_timelimit 2\ntimelimit 2\n")
                        config_file.flush()
                        child = subprocess.run([sys.executable, "-B", __file__, "--probe", library, api, scenario],
                                               env={**os.environ, "NSS_LDAP_CONFIG_FILE": str(config)},
                                               capture_output=True, text=True, timeout=10)
                    finally:
                        peer.close()
                    recovered = scenario != "recovery" or (peer.searches >= 3 and peer.binds >= 2)
                    passed = child.returncode == 0 and not peer.errors and recovered
                    failures += not passed
                    print(f"{'PASS' if passed else 'FAIL'} {api}/{scenario}: "
                          f"exit={child.returncode} {child.stdout.strip()}", flush=True)
                    if not passed and child.stderr:
                        print(child.stderr, file=sys.stderr)
                    if peer.errors:
                        print("Peer errors: " + repr(peer.errors), file=sys.stderr)
        finally:
            config.unlink()
    print(f"Passed {24 - failures}/24")
    return bool(failures)


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--probe":
        sys.exit(not probe(*sys.argv[2:]))
    if len(sys.argv) != 3:
        raise SystemExit("usage: lookup-errors.py /path/to/nss_ldap.so /path/to/test.conf")
    sys.exit(main(*sys.argv[1:]))
