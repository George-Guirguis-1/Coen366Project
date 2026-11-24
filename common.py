import ipaddress
import logging
import re
import socket
import sys
from pathlib import Path

SERVER_UDP_PORT = 5000
SERVER_TCP_PORT = 6000
BUFFER_SIZE = 65507
TIMEOUT = 2.0
MAX_ATTEMPTS = 3
REPLY_CACHE_TTL = 30

ROLES = ("SUBSCRIBER", "PUBLISHER", "BOTH")
LOCATIONS = ("HALL", "EV", "JMSB", "LOYOLA", "SGW", "ALL")
CATEGORIES = ("FIRE", "SECURITY", "WEATHER", "POWER", "BUILDING", "GENERAL", "ALL")

#Emergency incident severity levels
SEVERITY = ("INFO", "WARNING", "CRITICAL")

#User safety statuses (2.8)
STATUSES = ("SAFE", "NEED_HELP", "LEFT_AREA")


BASE_DIR = Path(__file__).resolve().parent
_TOKEN = re.compile(r"\[[^\]]*\]|\S+")
_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


def tokenize(msg):
    return _TOKEN.findall(msg)


def fmt_list(items):
    return "[" + ", ".join(items) + "]"


def parse_list(token):
    return [x.strip() for x in token.strip("[]").split(",") if x.strip()]


def valid_name(name):
    return bool(_NAME.match(name))


def valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def valid_port(port):
    return port.isdigit() and 0 < int(port) < 65536


def make_udp_socket(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if hasattr(socket, "SIO_UDP_CONNRESET"):
        s.ioctl(socket.SIO_UDP_CONNRESET, False)
    s.bind((host, port))
    return s


def make_tcp_listener(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if sys.platform != "win32":
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen()
    return s


def udp_recv(sock):
    while True:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            return data.decode("utf-8", "replace").strip(), addr
        except ConnectionResetError:
            continue


def recv_line(conn, limit=65536):
    buf = bytearray()
    while len(buf) < limit:
        b = conn.recv(1)
        if not b or b == b"\n":
            break
        buf += b
    return buf.decode("utf-8", "replace").strip()


def local_ip(target="8.8.8.8", port=80):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((target, port))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def make_logger(name, filename):
    (BASE_DIR / "logs").mkdir(exist_ok=True)
    log = logging.getLogger(name)
    log.setLevel(logging.INFO)
    log.propagate = False
    fmt = logging.Formatter("%(asctime)s [%(name)s] %(message)s", "%Y-%m-%d %H:%M:%S")
    for h in (logging.StreamHandler(sys.stdout),
              logging.FileHandler(BASE_DIR / "logs" / filename, encoding="utf-8")):
        h.setFormatter(fmt)
        log.addHandler(h)
    return log

def matches(sub, category, location):
    sub_loc, sub_cat = sub
    return sub_loc in (location, "ALL") and sub_cat in (category, "ALL")