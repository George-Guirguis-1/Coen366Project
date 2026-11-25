import argparse
import hashlib
import json
import re
import shlex
import tempfile
from pathlib import Path
import queue
import random
import socket
import sys
import threading

from common import (MAX_ATTEMPTS, SERVER_TCP_PORT, SERVER_UDP_PORT, TIMEOUT, SEVERITY, local_ip,
                    make_logger, make_tcp_listener, make_udp_socket, parse_list, recv_line,
                    tokenize, udp_recv, encode_field, decode_field, valid_filename, valid_name)

TCP_TIMEOUT = 10.0
CHUNK_SIZE = 65536
MAX_FILE_SIZE = 64 * 1024 * 1024
ATTACHMENT_DIR = Path(__file__).resolve().parent / "attachments"
DOWNLOAD_DIR = Path(__file__).resolve().parent / "downloads"


def display(value):
    return decode_field(value).replace("_", " ")


HELP = """Commands:
  register [name] [role]           role = SUBSCRIBER | PUBLISHER | BOTH
  deregister
  subscribe <location> <category>
  unsubscribe <location> <category>
  publish <category> <location> <severity> <title> <description> <file>
  update <incident_id> <severity> <title> <description>
  close <incident_id> <reason>
  status <incident_id> <status>    status = SAFE | NEED_HELP | LEFT_AREA
  attach <incident_id> <file>       discover attachment source
  download <incident_id> <file>     download attachment using TCP
  sync                             recover active alerts using TCP
  alerts                           display locally stored active alerts
  info                             show this client's state
  help
  quit"""


class Client:
    def __init__(self, args):
        server_ip = socket.gethostbyname(args.server)
        self.server = (server_ip, args.server_port)
        self.server_tcp = (server_ip, args.server_tcp_port)
        self.udp = make_udp_socket("0.0.0.0", args.udp_port)
        self.tcp = make_tcp_listener("0.0.0.0", args.tcp_port)
        self.udp_port = self.udp.getsockname()[1]
        self.tcp_port = self.tcp.getsockname()[1]
        self.ip = args.ip or local_ip(server_ip, args.server_port)
        self.name = args.name
        self.role = args.role.upper() if args.role else None
        self.loss = args.loss
        self.registered = False
        self.locations, self.categories = [], []
        self.subscriptions = set()
        self.rq = 0
        self.rq_lock = threading.Lock()
        self.pending = {}
        self.notify_handlers = {"ALERT": self.on_alert, "ALERT_UPDATE": self.on_alert_update,
                                "ALL_CLEAR": self.on_all_clear}
        self.alerts = {}
        self.alerts_lock = threading.RLock()
        self.latest = {}
        self.revisions = {}
        self.closed = set()
        self.revision = 0
        self.seen = set()
        self.seen_lock = threading.Lock()
        self.tcp_handlers = {"GET_ATTACHMENT": self.on_get_attachment}
        self.log = make_logger(f"CLIENT {self.name or self.udp_port}", f"client_{self.name or self.udp_port}.log")
        self.log.info("Client at %s (UDP %d, TCP %d) -> Emergency Server %s:%d",
                      self.ip, self.udp_port, self.tcp_port, *self.server)

    def next_rq(self):
        with self.rq_lock:
            self.rq += 1
            return f"{self.rq:02d}"

    def send(self, msg, addr, attempt=1):
        self.udp.sendto(msg.encode("utf-8"), addr)
        note = f"  (retransmission {attempt - 1})" if attempt > 1 else ""
        self.log.info("SEND -> %s:%d | %s%s", addr[0], addr[1], msg, note)

    def request(self, cmd, *fields):
        rq = self.next_rq()
        msg = " ".join((cmd, rq) + fields)
        box = queue.Queue(1)
        self.pending[rq] = box
        try:
            for attempt in range(1, MAX_ATTEMPTS + 1):
                self.send(msg, self.server, attempt)
                try:
                    return tokenize(box.get(timeout=TIMEOUT))
                except queue.Empty:
                    self.log.info("No reply to RQ#%s after %.1fs (attempt %d/%d)",
                                  rq, TIMEOUT, attempt, MAX_ATTEMPTS)
            self.log.info("Server unreachable: RQ#%s gave up after %d attempts", rq, MAX_ATTEMPTS)
            return None
        finally:
            self.pending.pop(rq, None)

    def udp_loop(self):
        while True:
            try:
                msg, addr = udp_recv(self.udp)
            except OSError:
                break
            if self.loss and random.random() < self.loss:
                self.log.info("DROP <- %s:%d | %s (simulated loss)", addr[0], addr[1], msg)
                continue
            self.log.info("RECV <- %s:%d | %s", addr[0], addr[1], msg)
            t = tokenize(msg)
            if not t:
                continue
            handler = self.notify_handlers.get(t[0])
            box = self.pending.get(t[1]) if len(t) > 1 and addr == self.server else None
            if handler and addr == self.server:
                with self.alerts_lock:
                    try:
                        handler(t, addr)
                    except (ValueError, OSError):
                        self.log.exception("Invalid UDP notification")
            elif box:
                try:
                    box.put_nowait(msg)
                except queue.Full:
                    pass
            else:
                self.log.info("Unexpected or late message ignored")

    def tcp_loop(self):
        while True:
            try:
                conn, addr = self.tcp.accept()
            except OSError:
                break
            threading.Thread(target=self.handle_tcp, args=(conn, addr), daemon=True).start()

    def handle_tcp(self, conn, addr):
        with conn:
            try:
                conn.settimeout(TCP_TIMEOUT)
                msg = recv_line(conn)
            except (OSError, EOFError, ValueError):
                return
            self.log.info("TCP RECV <- %s:%d | %s", addr[0], addr[1], msg)
            t = tokenize(msg)
            handler = self.tcp_handlers.get(t[0]) if t else None
            if handler:
                handler(t, conn, addr)
            else:
                self.log.info("TCP request not supported yet, connection closed")

    def cmd_register(self, args):
        name = args[0] if args else self.name or input("Name: ").strip()
        role = (args[1] if len(args) > 1 else self.role or
                input("Role (SUBSCRIBER/PUBLISHER/BOTH): ")).strip().upper()
        reply = self.request("REGISTER", name, role, self.ip, str(self.udp_port), str(self.tcp_port))
        if reply and reply[0] == "REGISTERED":
            if self.name != name or self.role != role:
                with self.alerts_lock:
                    self.alerts.clear()
                    self.latest.clear()
                    self.closed.clear()
                    self.revisions.clear()
                    self.seen.clear()
                self.subscriptions.clear()
            self.name, self.role, self.registered = name, role, True
            if len(reply) >= 4:
                self.locations, self.categories = parse_list(reply[2]), parse_list(reply[3])
            self.log.info("Registered as %s (%s). Locations: %s | Categories: %s",
                          name, role, " ".join(self.locations), " ".join(self.categories))
        elif reply:
            self.log.info("Registration denied: %s", " ".join(reply[2:]) or "no reason given")

    def cmd_deregister(self, args):
        if not self.name:
            print("No name known; register first.")
            return
        self.send(f"DE-REGISTER {self.next_rq()} {self.name}", self.server)
        self.registered = False
        self.subscriptions.clear()
        self.log.info("De-registered %s (the server sends no confirmation)", self.name)

    def cmd_subscribe(self, args, unsubscribe=False):
        if len(args) != 2:
            print("Usage: %s <location> <category>" % ("unsubscribe" if unsubscribe else "subscribe"))
            return
        loc, cat = args[0].upper(), args[1].upper()
        reply = self.request("UNSUBSCRIBE" if unsubscribe else "SUBSCRIBE", loc, cat)
        if not reply:
            return
        if reply[0] == "SUBSCRIBED":
            self.subscriptions.add((loc, cat))
            self.log.info("Subscribed to %s/%s", loc, cat)
        elif reply[0] == "UNSUBSCRIBED":
            self.subscriptions.discard((loc, cat))
            self.log.info("Unsubscribed from %s/%s", loc, cat)
        else:
            self.log.info("%s denied: %s", "Unsubscribe" if unsubscribe else "Subscribe",
                          " ".join(reply[2:]) or "no reason given")

    def accept_version(self, incident_id, version):
        number = int(version)
        if number < 1 or incident_id in self.closed or number <= self.latest.get(incident_id, 0):
            return False
        self.latest[incident_id] = number
        self.revision += 1
        self.revisions[incident_id] = self.revision
        self.seen.add((incident_id, version))
        return True

    def on_alert(self, t, addr):
        if addr != self.server or len(t) != 10:
            return
        _, rq, inc_id, version, cat, loc, sev, title, desc, attach = t
        if sev == "CRITICAL":
            self.send(f"ALERT_ACK {rq} {inc_id} {version} {self.name}", self.server)
        if not self.accept_version(inc_id, version):
            self.log.info("Duplicate or stale ALERT %s v%s ignored", inc_id, version)
            return
        self.alerts[inc_id] = dict(version=version, category=cat, location=loc,
                                   severity=sev, title=title, description=desc,
                                   attachment=attach, status="ACTIVE")
        print(f"\n*** {sev} ALERT {inc_id} (v{version}) | {cat} at {loc}\n"
              f"    {display(title)}: {display(desc)}"
              + (f"\n    Attachment: {decode_field(attach)}" if attach != "NONE" else "") + "\n> ", end="")

    def on_alert_update(self, t, addr):
        if addr != self.server or len(t) != 7:
            return
        _, rq, inc_id, version, severity, title, description = t
        if severity == "CRITICAL":
            self.send(f"ALERT_ACK {rq} {inc_id} {version} {self.name}", self.server)
        if not self.accept_version(inc_id, version):
            self.log.info("Duplicate or stale UPDATE %s v%s ignored", inc_id, version)
            return
        if inc_id in self.alerts:
            self.alerts[inc_id].update(version=version, severity=severity, title=title, description=description)
        else:
            self.log.info("Update for unknown incident; use sync for full details")
        print(f"\n*** {severity} UPDATE {inc_id} (v{version})\n"
              f"    {display(title)}: {display(description)}\n> ", end="")

    def on_all_clear(self, t, addr):
        if addr != self.server or len(t) != 5:
            return
        _, rq, inc_id, version, message = t
        self.send(f"ALERT_ACK {rq} {inc_id} {version} {self.name}", self.server)
        if not self.accept_version(inc_id, version):
            self.log.info("Duplicate or stale ALL_CLEAR %s v%s ignored", inc_id, version)
            return
        self.closed.add(inc_id)
        if inc_id in self.alerts:
            self.alerts[inc_id].update(version=version, status="CLOSED")
        print(f"\n*** ALL CLEAR {inc_id} (v{version})\n    {display(message)}\n> ", end="")

    def cmd_publish(self, args):
        if len(args) not in (5,6):
            print("Input all arguments when publishing an alert.")
            return
        category = args[0].upper()
        location = args[1].upper()
        severity = args[2].upper()
        title = encode_field(args[3])
        description = encode_field(args[4])
        attachment = args[5] if len(args) == 6 else "NONE"

        if attachment != "NONE":
            try:
                file_path = ATTACHMENT_DIR / attachment
                if not valid_filename(attachment) or not file_path.is_file() or file_path.is_symlink():
                    print("Invalid or unavailable attachment; place the file in attachments/.")
                    return
                if file_path.stat().st_size > MAX_FILE_SIZE:
                    print("Attachment exceeds the 64 MiB limit.")
                    return
            except OSError as e:
                self.log.info("Attachment unavailable: %s", e)
                return
            attachment = encode_field(attachment)
        reply = self.request("PUBLISH_ALERT", category, location, severity, title, description, attachment)
        if not reply:
            return
        if reply[0] == "ALERT_ACCEPTED":
            self.log.info("Incident %s created", reply[2])
        else:
            self.log.info("Publish denied: %s", " ".join(reply[2:]) or "no reason given")

    #2.6
    def cmd_update(self, args):
        if len(args) != 4:
            print("Usage: update <incident_id> <severity> <title> <description>")
            return
        incident_id = args[0].upper()
        severity = args[1].upper()
        title = encode_field(args[2])
        description = encode_field(args[3])

        reply = self.request("UPDATE_ALERT", incident_id, severity, title, description)
        if not reply:
            return
        if reply[0] == "ALERT_UPDATED":
            self.log.info("Incident %s updated, now version %s", reply[2], reply[3])
        else:
            self.log.info("Update denied: %s", " ".join(reply[2:]) or "no reason given")

    #2.7
    def cmd_close(self, args):
        if len(args) != 2:
            print("Usage: close <incident_id> <reason>")
            return
        incident_id = args[0].upper()
        reason = encode_field(args[1])

        reply = self.request("CLOSE_ALERT", incident_id, reason)
        if not reply:
            return
        if reply[0] == "ALERT_CLOSED":
            self.log.info("Incident %s closed", reply[2])
        else:
            self.log.info("Close denied: %s", " ".join(reply[2:]) or "no reason given")

    #2.8
    def cmd_status(self, args):
        if len(args) != 2:
            print("Usage: status <incident_id> <SAFE|NEED_HELP|LEFT_AREA>")
            return
        if not self.name:
            print("Register first.")
            return
        incident_id = args[0].upper()
        status = args[1].upper()

        reply = self.request("STATUS_REPORT", incident_id, self.name, status)
        if not reply:
            return
        if reply[0] == "STATUS_RECORDED":
            self.log.info("Status %s recorded for %s", status, incident_id)
        else:
            self.log.info("Status rejected: %s", " ".join(reply[2:]) or "no reason given")


    #2.9.A Request attachment source (UDP)
    def cmd_attach(self, args):
        if len(args) != 2:
            print("Usage: attach <incident_id> <file>")
            return
        if not self.registered:
            print("Register first.")
            return
        if self.role not in ("SUBSCRIBER", "BOTH"):
            print("Only subscribers can request attachments.")
            return

        incident_id = args[0].upper()
        file_name = encode_field(args[1])
        reply = self.request("ATTACH_REQ", incident_id, file_name)
        if not reply:
            return

        if reply[0] == "ATTACH_INFO" and len(reply) == 7:
            _, rq, inc_id, publisher, ip, tcp_port, filename = reply
            self.log.info("Attachment source found for %s", inc_id)
            print(f"Publisher: {publisher}")
            print(f"IP address: {ip}")
            print(f"TCP port: {tcp_port}")
            print(f"File: {decode_field(filename)}")
        elif reply[0] == "ATTACH_DENIED":
            self.log.info("Attachment denied: %s",
                          " ".join(reply[3:]) or "no reason given")
        else:
            self.log.info("Unexpected attachment response")

    def tcp_send_message(self, conn, message):
        conn.sendall((message + "\n").encode("utf-8"))
        self.log.info("TCP SEND | %s", message)

    #2.9.B Publisher-side transfer. The persisted server metadata is authoritative.
    def on_get_attachment(self, t, conn, addr):
        rq = t[1] if len(t) > 1 else "UNKNOWN"
        incident_id = t[3] if len(t) > 3 else "UNKNOWN"
        filename = t[4] if len(t) > 4 else "UNKNOWN"
        def deny(reason):
            self.tcp_send_message(conn, f"ATTACH_ERROR {rq} {incident_id} {filename} {reason}")
        try:
            if len(t) != 5:
                deny("Malformed_Request")
                return
            subscriber = t[2]
            if not self.registered or self.role not in ("PUBLISHER", "BOTH"):
                deny("Publisher_Unavailable")
                return
            name = decode_field(filename)
            if not valid_filename(name) or not valid_name(subscriber):
                deny("Invalid_Filename_Or_Name")
                return
            # No file contents are sent to the central server.
            check_rq = self.next_rq()
            try:
                with socket.create_connection(self.server_tcp, timeout=TCP_TIMEOUT) as check:
                    self.tcp_send_message(check, f"CHECK_ATTACHMENT {check_rq} {self.name} {subscriber} {incident_id} {filename}")
                    reply = tokenize(recv_line(check))
            except (OSError, EOFError, ValueError):
                deny("Server_Unavailable")
                return
            if reply != ["CHECK_OK", check_rq]:
                deny(reply[2] if len(reply) == 3 and reply[:2] == ["CHECK_DENIED", check_rq] else "Invalid_Validation_Response")
                return
            path = ATTACHMENT_DIR / name
            try:
                if not path.is_file() or path.is_symlink():
                    raise OSError("File missing")
                with path.open("rb") as f:
                    data = f.read(MAX_FILE_SIZE + 1)
            except OSError:
                deny("File_Unavailable")
                return
            if len(data) > MAX_FILE_SIZE:
                deny("File_Too_Large")
                return
            digest = hashlib.sha256(data).hexdigest()
            self.tcp_send_message(conn, f"ATTACH_DATA {rq} {incident_id} {filename} {len(data)} {digest}")
            self.log.info("Sending %s (%d bytes) to %s", name, len(data), subscriber)
            for offset in range(0, len(data), CHUNK_SIZE):
                conn.sendall(data[offset:offset + CHUNK_SIZE])
            reply = tokenize(recv_line(conn))
            self.log.info("TCP RECV | %s", " ".join(reply))
            if reply == ["ATTACH_OK", rq, incident_id, filename]:
                self.log.info("Transfer verified by %s: %s", subscriber, name)
            elif len(reply) >= 5 and reply[:4] == ["ATTACH_ERROR", rq, incident_id, filename]:
                self.log.info("Transfer rejected: %s", " ".join(reply[4:]))
            else:
                self.log.info("Transfer not confirmed")
        except (OSError, EOFError, ValueError) as e:
            self.log.info("TCP attachment transfer failed: %s", e)

    def cmd_download(self, args):
        if len(args) != 2:
            print('Usage: download <incident_id> "<file>"')
            return
        if not self.registered or self.role not in ("SUBSCRIBER", "BOTH"):
            print("Register as a subscriber first.")
            return
        incident_id, name = args[0].upper(), args[1]
        if not re.fullmatch(r"INC[0-9]+", incident_id) or not valid_filename(name):
            print("Invalid incident ID or filename.")
            return
        filename = encode_field(name)
        reply = self.request("ATTACH_REQ", incident_id, filename)
        if not reply:
            return
        if reply[0] == "ATTACH_DENIED":
            self.log.info("Attachment denied: %s", " ".join(reply[3:]))
            return
        if len(reply) != 7 or reply[0] != "ATTACH_INFO" or reply[2] != incident_id or reply[6] != filename:
            self.log.info("Invalid attachment response")
            return
        try:
            port = int(reply[5])
            if not 1 <= port <= 65535:
                raise ValueError()
        except ValueError:
            self.log.info("Invalid publisher port")
            return
        self.log.info("Publisher located: %s at %s:%d", reply[3], reply[4], port)
        threading.Thread(target=self.download_file, args=(incident_id, filename, reply[4], port, self.name), daemon=True).start()

    def download_file(self, incident_id, filename, ip, port, subscriber):
        rq = self.next_rq()
        temp_path = None
        try:
            name = decode_field(filename)
            if not valid_filename(name) or not valid_name(subscriber) or not re.fullmatch(r"INC[0-9]+", incident_id):
                raise ValueError("Invalid local destination")
            with socket.create_connection((ip, port), timeout=TCP_TIMEOUT) as conn:
                self.tcp_send_message(conn, f"GET_ATTACHMENT {rq} {subscriber} {incident_id} {filename}")
                def report_error(reason):
                    self.log.info("Download failed: %s", reason)
                    try:
                        self.tcp_send_message(conn, f"ATTACH_ERROR {rq} {incident_id} {filename} {reason}")
                    except OSError:
                        pass
                try:
                    header = tokenize(recv_line(conn))
                except (EOFError, ValueError, OSError):
                    report_error("Incomplete_Header")
                    return
                self.log.info("TCP RECV | %s", " ".join(header))
                if len(header) >= 5 and header[:4] == ["ATTACH_ERROR", rq, incident_id, filename]:
                    self.log.info("Publisher rejected transfer: %s", " ".join(header[4:]))
                    return
                if len(header) != 6 or header[:4] != ["ATTACH_DATA", rq, incident_id, filename]:
                    report_error("Invalid_Header")
                    return
                try:
                    size = int(header[4])
                    expected = header[5].lower()
                    if not 0 <= size <= MAX_FILE_SIZE or not re.fullmatch(r"[0-9a-f]{64}", expected):
                        raise ValueError()
                except ValueError:
                    report_error("Invalid_File_Metadata")
                    return
                folder = DOWNLOAD_DIR / subscriber / incident_id
                target = folder / name
                digest = hashlib.sha256()
                remaining = size
                try:
                    folder.mkdir(parents=True, exist_ok=True)
                    with tempfile.NamedTemporaryFile(mode="wb", dir=folder, suffix=".part", delete=False) as f:
                        temp_path = Path(f.name)
                        while remaining:
                            chunk = conn.recv(min(CHUNK_SIZE, remaining))
                            if not chunk:
                                break
                            f.write(chunk)
                            digest.update(chunk)
                            remaining -= len(chunk)
                    if remaining:
                        report_error("Incomplete_Transfer")
                        return
                    actual = digest.hexdigest()
                    if actual != expected:
                        report_error("Checksum_Mismatch")
                        return
                    temp_path.replace(target)
                    temp_path = None
                except TimeoutError:
                    report_error("Transfer_Timeout")
                    return
                except OSError:
                    report_error("Transfer_IO_Error")
                    return
                self.log.info("Received %d bytes", size)
                self.log.info("Expected SHA-256: %s", expected)
                self.log.info("Actual SHA-256:   %s", actual)
                self.log.info("Checksum verification PASSED")
                self.log.info("File saved: %s", target)
                self.tcp_send_message(conn, f"ATTACH_OK {rq} {incident_id} {filename}")
        except (OSError, ValueError) as e:
            self.log.info("TCP download communication failed: %s", e)
        finally:
            if temp_path is not None:
                try:
                    temp_path.unlink(missing_ok=True)
                except OSError as e:
                    self.log.info("Temporary file cleanup failed: %s", e)

    #2.10 Active incident synchronization
    def cmd_sync(self, args):
        if args or not self.registered or self.role not in ("SUBSCRIBER", "BOTH"):
            print("Usage: sync (registered subscribers only)")
            return
        rq = self.next_rq()
        with self.alerts_lock:
            start_revision = self.revision
        recovered = {}
        try:
            with socket.create_connection(self.server_tcp, timeout=TCP_TIMEOUT) as conn:
                self.tcp_send_message(conn, f"GET_ACTIVE_ALERTS {rq} {self.name}")
                header = tokenize(recv_line(conn))
                self.log.info("TCP RECV | %s", " ".join(header))
                if len(header) == 3 and header[:2] == ["ACTIVE_ALERTS_DENIED", rq]:
                    self.log.info("Synchronization denied: %s", header[2])
                    return
                if len(header) != 3 or header[:2] != ["ACTIVE_ALERTS", rq]:
                    raise ValueError("Invalid ACTIVE_ALERTS header")
                count = int(header[2])
                if not 0 <= count <= 10000:
                    raise ValueError("Invalid count")
                fields = ("category", "location", "severity", "status", "title", "description", "attachment")
                for _ in range(count):
                    line = recv_line(conn)
                    self.log.info("TCP RECV | %s", line)
                    record = json.loads(line)
                    if not isinstance(record, dict) or not all(isinstance(record.get(f), str) for f in fields):
                        raise ValueError("Invalid incident record")
                    key, version = record.get("incident_id"), record.get("version")
                    if not isinstance(key, str) or not re.fullmatch(r"INC[0-9]+", key) or key in recovered:
                        raise ValueError("Invalid incident ID")
                    if type(version) is not int or version < 1 or record["status"] != "ACTIVE" or record["severity"] not in SEVERITY:
                        raise ValueError("Invalid incident metadata")
                    recovered[key] = dict(version=str(version), **{f: record[f] for f in fields})
            with self.alerts_lock:
                for key in list(self.alerts):
                    if key not in recovered and self.revisions.get(key, 0) <= start_revision:
                        del self.alerts[key]
                for key, record in recovered.items():
                    version = int(record["version"])
                    if key in self.closed or version < self.latest.get(key, 0):
                        continue
                    self.alerts[key] = record
                    self.latest[key] = version
                    self.seen.add((key, record["version"]))
            self.log.info("Synchronization complete: %d matching active incident(s) received", count)
            self.cmd_alerts([])
        except (OSError, EOFError, ValueError) as e:
            self.log.info("Synchronization failed: %s", e)

    def cmd_alerts(self, args):
        with self.alerts_lock:
            active = {key: dict(value) for key, value in self.alerts.items() if value["status"] == "ACTIVE"}
        print(f"\nActive incidents: {len(active)}")
        if not active:
            print("No active incidents.")
        for key, inc in sorted(active.items()):
            print(f"\n{key} (v{inc['version']}) | {inc['severity']} | {inc['category']} at {inc['location']}")
            print(f"  {display(inc['title'])}: {display(inc['description'])}")
            if inc["attachment"] != "NONE":
                print(f"  Attachment: {decode_field(inc['attachment'])}")

    def cmd_info(self, args):
        subs = ", ".join(f"{l}/{c}" for l, c in sorted(self.subscriptions)) or "-"
        print(f"Name: {self.name or '-'}  Role: {self.role or '-'}  Registered: {self.registered}\n"
              f"Address: {self.ip}  UDP {self.udp_port}  TCP {self.tcp_port}\n"
              f"Server: {self.server[0]}  UDP {self.server[1]}  TCP {self.server_tcp[1]}\n"
              f"Subscriptions confirmed this session: {subs}")

    def run(self):
        threading.Thread(target=self.udp_loop, daemon=True).start()
        threading.Thread(target=self.tcp_loop, daemon=True).start()
        commands = {
            "register": self.cmd_register,
            "deregister": self.cmd_deregister,
            "subscribe": self.cmd_subscribe,
            "unsubscribe": lambda a: self.cmd_subscribe(a, unsubscribe=True),
            "publish": self.cmd_publish,
            "update": self.cmd_update,
            "close": self.cmd_close,
            "status": self.cmd_status,
            "attach": self.cmd_attach,
            "download": self.cmd_download,
            "sync": self.cmd_sync,
            "alerts": self.cmd_alerts,
            "info": self.cmd_info,
            "help": lambda a: print(HELP),
        }
        print(HELP)
        try:
            while True:
                try:
                    line = shlex.split(input("> "))
                except ValueError as e:
                    print(f"Invalid command: {e}")
                    continue
                if not line:
                    continue
                cmd = line[0].lower()
                if cmd in ("quit", "exit"):
                    break
                if cmd in commands:
                    commands[cmd](line[1:])
                else:
                    print("Unknown command. Type 'help'.")
        except (EOFError, KeyboardInterrupt):
            pass
        self.log.info("Client closing")
        self.udp.close()
        self.tcp.close()


def main():
    p = argparse.ArgumentParser(description="CENRS client (peer)")
    p.add_argument("--server", default="127.0.0.1", help="IP or hostname of the Emergency Server")
    p.add_argument("--server-port", type=int, default=SERVER_UDP_PORT)
    p.add_argument("--server-tcp-port", type=int, default=SERVER_TCP_PORT)
    p.add_argument("--name")
    p.add_argument("--role")
    p.add_argument("--ip", help="IP to advertise (default: the interface that reaches the server)")
    p.add_argument("--udp-port", type=int, default=5001)
    p.add_argument("--tcp-port", type=int, default=6001)
    p.add_argument("--loss", type=float, default=0.0, help="simulated UDP loss rate, 0..1")
    try:
        client = Client(p.parse_args())
    except OSError as e:
        sys.exit(f"Startup failed: {e} (port in use? try --udp-port/--tcp-port)")
    client.run()


if __name__ == "__main__":
    main()
