import argparse
import json
import hashlib
import re
import tempfile
from pathlib import Path
import queue
import random
import socket
import sys
import threading

from common import (MAX_ATTEMPTS, SERVER_TCP_PORT, SERVER_UDP_PORT, TIMEOUT, SEVERITY, local_ip,
                    make_logger, make_tcp_listener, make_udp_socket, parse_list, recv_line,
                    tokenize, udp_recv)

TCP_TIMEOUT = 10.0
CHUNK_SIZE = 65536
MAX_FILE_SIZE = 64 * 1024 * 1024
ATTACHMENT_DIR = Path(__file__).resolve().parent / "attachments"
DOWNLOAD_DIR = Path(__file__).resolve().parent / "downloads"


def valid_filename(name):
    return (
        bool(re.fullmatch(r"[A-Za-z0-9_.-]+", name))
        and name not in (".", "..", "NONE")
        and not name.endswith(".")
        and not re.fullmatch(
            r"CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]|CONIN\$|CONOUT\$",
            name.split(".")[0].upper()
        )
    )


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
        self.seen = set()
        self.seen_lock = threading.Lock()
        self.published_files = {}
        self.files_lock = threading.Lock()
        self.tcp_handlers = {
            "GET_ATTACHMENT": self.on_get_attachment
        }
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
            box = self.pending.get(t[1]) if len(t) > 1 and addr[0] == self.server[0] else None
            if handler:
                threading.Thread(target=self.handle_notification, args=(handler, t, addr), daemon=True).start()
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
            except OSError:
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

    def on_alert(self, t, addr):
        if addr[0] != self.server[0]:
            self.log.info("ALERT from unknown source %s ignored", addr[0])
            return
        if len(t) != 10:
            self.log.info("Malformed ALERT ignored")
            return
        _, rq, inc_id, version, cat, loc, sev, title, desc, attach = t
       
        if sev == "CRITICAL":
            self.send(f"ALERT_ACK {rq} {inc_id} {version} {self.name}", self.server)
        with self.seen_lock:
            duplicate = (inc_id, version) in self.seen
            self.seen.add((inc_id, version))
        if duplicate:
            self.log.info("Duplicate ALERT %s v%s: re-ACKed, not displayed", inc_id, version)
            return
        self.alerts[inc_id] = {"version": version, "category": cat, "location": loc,
                           "severity": sev, "title": title, "description": desc,
                           "attachment": attach, "status": "ACTIVE"}
        print(f"\n*** {sev} ALERT {inc_id} (v{version}) | {cat} at {loc}\n"
        f"    {title.replace('_', ' ')}: {desc.replace('_', ' ')}"
        + (f"\n    Attachment: {attach}" if attach != "NONE" else "") + "\n> ", end="")

    #2.6 
    def on_alert_update(self, t, addr):
        if addr[0] != self.server[0]:
            self.log.info("ALERT_UPDATE from unknown source %s ignored", addr[0])
            return
        if len(t) != 7:
            self.log.info("Malformed ALERT_UPDATE ignored")
            return
        rq = t[1]
        incident_id = t[2]
        version = t[3]
        severity = t[4]
        title = t[5]
        description = t[6]

        if severity == "CRITICAL":
            self.send(f"ALERT_ACK {rq} {incident_id} {version} {self.name}", self.server)

        with self.seen_lock:
            duplicate = (incident_id, version) in self.seen
            self.seen.add((incident_id, version))
        if duplicate:
            self.log.info("Duplicate ALERT_UPDATE %s v%s: not displayed", incident_id, version)
            return

        if incident_id in self.alerts:
            self.alerts[incident_id]["version"] = version
            self.alerts[incident_id]["severity"] = severity
            self.alerts[incident_id]["title"] = title
            self.alerts[incident_id]["description"] = description

        print(f"\n*** {severity} UPDATE {incident_id} (v{version})\n"
              f"    {title.replace('_', ' ')}: {description.replace('_', ' ')}\n> ", end="")

    #2.7
    def on_all_clear(self, t, addr):
        # ALL_CLEAR RQ# Incident_ID Version Message
        if addr[0] != self.server[0]:
            self.log.info("ALL_CLEAR from unknown source %s ignored", addr[0])
            return
        if len(t) != 5:
            self.log.info("Malformed ALL_CLEAR ignored")
            return
        rq = t[1]
        incident_id = t[2]
        version = t[3]
        message = t[4]

        # ALL_CLEAR is always acknowledged, even if it is a duplicate
        self.send(f"ALERT_ACK {rq} {incident_id} {version} {self.name}", self.server)

        with self.seen_lock:
            duplicate = (incident_id, version) in self.seen
            self.seen.add((incident_id, version))
        if duplicate:
            self.log.info("Duplicate ALL_CLEAR %s v%s: not displayed", incident_id, version)
            return

        if incident_id in self.alerts:
            self.alerts[incident_id]["version"] = version
            self.alerts[incident_id]["status"] = "CLOSED"

        print(f"\n*** ALL CLEAR {incident_id} (v{version})\n"
              f"    {message.replace('_', ' ')}\n> ", end="")

    def cmd_publish(self, args):
        if len(args) not in (5,6):
            print("Input all arguments when publishing an alert.")
            return
        category = args[0].upper()
        location = args[1].upper()
        severity = args[2].upper()
        title = args[3]
        description = args[4]
        attachment = args[5] if len(args) == 6 else "NONE"

        if attachment != "NONE":
            if not valid_filename(attachment):
                print("Invalid attachment filename.")
                return

            file_path = ATTACHMENT_DIR / attachment

            try:
                if not file_path.is_file() or file_path.is_symlink():
                    print(f"Attachment not found: {file_path}")
                    return

                if file_path.stat().st_size > MAX_FILE_SIZE:
                    print("Attachment exceeds the 64 MiB limit.")
                    return
            except OSError as e:
                self.log.info("Cannot access attachment: %s", e)
                return

        reply = self.request("PUBLISH_ALERT", category, location, severity, title, description, attachment)
        if not reply:
            return
        if reply[0] == "ALERT_ACCEPTED":
            if attachment != "NONE":
                with self.files_lock:
                    self.published_files[reply[2]] = (self.name, attachment)

                self.log.info("Attachment %s available for %s",
                              attachment, reply[2])

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
        title = args[2]
        description = args[3]

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
        reason = args[1]

        reply = self.request("CLOSE_ALERT", incident_id, reason)
        if not reply:
            return
        if reply[0] == "ALERT_CLOSED":
            with self.files_lock:
                self.published_files.pop(incident_id, None)

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
        file_name = args[1]
        reply = self.request("ATTACH_REQ", incident_id, file_name)
        if not reply:
            return

        if reply[0] == "ATTACH_INFO" and len(reply) == 7:
            _, rq, inc_id, publisher, ip, tcp_port, filename = reply
            self.log.info("Attachment source found for %s", inc_id)
            print(f"Publisher: {publisher}")
            print(f"IP address: {ip}")
            print(f"TCP port: {tcp_port}")
            print(f"File: {filename}")
        elif reply[0] == "ATTACH_DENIED":
            self.log.info("Attachment denied: %s",
                          " ".join(reply[3:]) or "no reason given")
        else:
            self.log.info("Unexpected attachment response")


    #2.9.B Direct publisher-to-subscriber TCP transfer

    def tcp_send_message(self, conn, msg):
        conn.sendall((msg + "\n").encode("utf-8"))
        self.log.info("TCP SEND | %s", msg)

    def on_get_attachment(self, t, conn, addr):
        rq = t[1] if len(t) > 1 else "UNKNOWN"
        incident_id = t[3] if len(t) > 3 else "UNKNOWN"
        file_name = t[4] if len(t) > 4 else "UNKNOWN"

        def deny(reason):
            self.tcp_send_message(
                conn,
                f"ATTACH_ERROR {rq} {incident_id} {file_name} {reason}"
            )

        try:
            if len(t) != 5:
                deny("Malformed_Request")
                return

            subscriber = t[2]

            if not self.registered or self.role not in ("PUBLISHER", "BOTH"):
                deny("Publisher_Unavailable")
                return

            if not valid_filename(file_name):
                deny("Invalid_Filename")
                return

            # Only serve files belonging to published incidents
            with self.files_lock:
                published_file = self.published_files.get(incident_id)

            if published_file != (self.name, file_name):
                deny("Unknown_Incident_Or_Attachment")
                return

            file_path = ATTACHMENT_DIR / file_name

            if not file_path.is_file() or file_path.is_symlink():
                deny("File_Unavailable")
                return

            # Read a bounded snapshot so checksum and data match
            try:
                with open(file_path, "rb") as f:
                    data = f.read(MAX_FILE_SIZE + 1)
            except OSError:
                deny("File_Unavailable")
                return

            if len(data) > MAX_FILE_SIZE:
                deny("File_Too_Large")
                return

            file_size = len(data)
            checksum = hashlib.sha256(data).hexdigest()

            header = (
                f"ATTACH_DATA {rq} {incident_id} "
                f"{file_name} {file_size} {checksum}"
            )

            self.tcp_send_message(conn, header)

            self.log.info("Sending %s (%d bytes) to %s",
                          file_name, file_size, subscriber)

            # Send binary data in chunks
            for offset in range(0, file_size, CHUNK_SIZE):
                conn.sendall(data[offset:offset + CHUNK_SIZE])

            # Wait for application-level confirmation
            reply = tokenize(recv_line(conn))

            self.log.info("TCP RECV | %s", " ".join(reply))

            expected = [rq, incident_id, file_name]

            if reply == ["ATTACH_OK"] + expected:
                self.log.info("Transfer verified by %s: %s",
                              subscriber, file_name)

            elif (len(reply) >= 5
                  and reply[0] == "ATTACH_ERROR"
                  and reply[1:4] == expected):
                self.log.info("Transfer rejected by %s: %s",
                              subscriber, " ".join(reply[4:]))

            else:
                self.log.info("Transfer not confirmed by %s", subscriber)

        except OSError as e:
            self.log.info("TCP attachment transfer failed: %s", e)

    def cmd_download(self, args):
        if len(args) != 2:
            print("Usage: download <incident_id> <file>")
            return

        if not self.registered:
            print("Register first.")
            return

        if self.role not in ("SUBSCRIBER", "BOTH"):
            print("Only subscribers can download attachments.")
            return

        incident_id = args[0].upper()
        file_name = args[1]

        if not valid_filename(file_name):
            print("Invalid attachment filename.")
            return

        if not re.fullmatch(r"INC[0-9]+", incident_id):
            print("Invalid incident ID.")
            return

        # First discover the publisher using UDP
        reply = self.request("ATTACH_REQ", incident_id, file_name)

        if not reply:
            return

        if reply[0] == "ATTACH_DENIED":
            self.log.info("Attachment denied: %s",
                          " ".join(reply[3:]))
            return

        if reply[0] != "ATTACH_INFO" or len(reply) != 7:
            self.log.info("Unexpected attachment response")
            return

        _, _, inc_id, publisher, ip, tcp_port, filename = reply

        if inc_id != incident_id or filename != file_name:
            self.log.info("Attachment information mismatch")
            return

        try:
            port = int(tcp_port)

            if not 1 <= port <= 65535:
                raise ValueError("Invalid TCP port")

        except ValueError:
            self.log.info("Invalid publisher TCP port")
            return

        self.log.info("Publisher located: %s at %s:%d",
                      publisher, ip, port)

        # Keep UDP notifications and terminal input responsive
        threading.Thread(
            target=self.download_file,
            args=(incident_id, file_name, ip, port, self.name),
            daemon=True
        ).start()

    def download_file(self, incident_id, file_name, ip, port, subscriber):
        rq = self.next_rq()
        temp_path = None

        try:
            # Connect directly to the publisher
            with socket.create_connection(
                (ip, port), timeout=TCP_TIMEOUT
            ) as conn:

                conn.settimeout(TCP_TIMEOUT)

                request = (
                    f"GET_ATTACHMENT {rq} {subscriber} "
                    f"{incident_id} {file_name}"
                )

                self.tcp_send_message(conn, request)

                header = tokenize(recv_line(conn))

                self.log.info("TCP RECV | %s", " ".join(header))

                def report_error(reason):
                    self.log.info("Download failed: %s", reason)

                    try:
                        self.tcp_send_message(
                            conn,
                            f"ATTACH_ERROR {rq} {incident_id} "
                            f"{file_name} {reason}"
                        )
                    except OSError:
                        pass

                if (len(header) >= 5
                    and header[0] == "ATTACH_ERROR"
                    and header[1:4] == [rq, incident_id, file_name]):
                    self.log.info("Publisher rejected transfer: %s",
                                  " ".join(header[4:]))
                    return

                if (len(header) != 6
                    or header[0] != "ATTACH_DATA"
                    or header[1:4] != [rq, incident_id, file_name]):
                    report_error("Invalid_Header")
                    return

                try:
                    file_size = int(header[4])

                    if not 0 <= file_size <= MAX_FILE_SIZE:
                        raise ValueError()

                    expected_checksum = header[5].lower()

                    if not re.fullmatch(r"[0-9a-f]{64}", expected_checksum):
                        raise ValueError()

                except ValueError:
                    report_error("Invalid_File_Metadata")
                    return

                target_dir = DOWNLOAD_DIR / subscriber / incident_id
                target_path = target_dir / file_name

                checksum = hashlib.sha256()
                remaining = file_size

                try:
                    target_dir.mkdir(parents=True, exist_ok=True)

                    # Use a temporary file until verification succeeds
                    with tempfile.NamedTemporaryFile(
                        mode="wb",
                        dir=target_dir,
                        suffix=".part",
                        delete=False
                    ) as f:

                        temp_path = Path(f.name)

                        while remaining > 0:
                            chunk = conn.recv(
                                min(CHUNK_SIZE, remaining)
                            )

                            if not chunk:
                                break

                            f.write(chunk)
                            checksum.update(chunk)
                            remaining -= len(chunk)

                    if remaining != 0:
                        report_error("Incomplete_Transfer")
                        return

                    actual_checksum = checksum.hexdigest()

                    if actual_checksum != expected_checksum:
                        report_error("Checksum_Mismatch")
                        return

                    # Only keep a successfully verified file
                    temp_path.replace(target_path)
                    temp_path = None

                except TimeoutError:
                    report_error("Transfer_Timeout")
                    return

                except OSError:
                    report_error("Transfer_IO_Error")
                    return

                self.log.info("Received %d bytes", file_size)
                self.log.info("Expected SHA-256: %s", expected_checksum)
                self.log.info("Actual SHA-256:   %s", actual_checksum)
                self.log.info("Checksum verification PASSED")
                self.log.info("File saved: %s", target_path)

                self.tcp_send_message(
                    conn,
                    f"ATTACH_OK {rq} {incident_id} {file_name}"
                )

        except OSError as e:
            self.log.info("TCP download communication failed: %s", e)

        finally:
            if temp_path is not None:
                try:
                    temp_path.unlink(missing_ok=True)
                except OSError as e:
                    self.log.info("Temporary file cleanup failed: %s", e)



    def handle_notification(self, handler, t, addr):
        with self.alerts_lock:
            handler(t, addr)

    # Read a complete newline-terminated TCP message.
    # Reject incomplete or oversized messages.

    def recv_sync_line(self, conn, limit=65536):
        data = bytearray()

        while len(data) < limit:
            byte = conn.recv(1)

            if not byte:
                raise EOFError("Incomplete TCP message")

            if byte == b"\n":
                return data.decode("utf-8")

            data.extend(byte)

        raise ValueError("TCP message exceeds size limit")

    #2.10 Recover active incidents using TCP

    def cmd_sync(self, args):
        if args:
            print("Usage: sync")
            return

        if not self.registered:
            print("Register first.")
            return

        if self.role not in ("SUBSCRIBER", "BOTH"):
            print("Only subscribers can synchronize alerts.")
            return

        rq = self.next_rq()

        # Remember local state before synchronization
        with self.alerts_lock:
            previous_alerts = {
                key: dict(value)
                for key, value in self.alerts.items()
            }

            previous_seen = set(self.seen)

        recovered = {}

        try:
            with socket.create_connection(
                self.server_tcp, timeout=TCP_TIMEOUT
            ) as conn:

                conn.settimeout(TCP_TIMEOUT)

                self.tcp_send_message(
                    conn,
                    f"GET_ACTIVE_ALERTS {rq} {self.name}"
                )

                header = tokenize(self.recv_sync_line(conn))

                self.log.info("TCP RECV | %s", " ".join(header))

                if (len(header) >= 3
                    and header[0] == "ACTIVE_ALERTS_DENIED"
                    and header[1] == rq):

                    self.log.info(
                        "Synchronization denied: %s",
                        " ".join(header[2:])
                    )
                    return

                if (len(header) != 3
                    or header[0] != "ACTIVE_ALERTS"
                    or header[1] != rq):

                    raise ValueError("Invalid ACTIVE_ALERTS header")

                count = int(header[2])

                if not 0 <= count <= 10000:
                    raise ValueError("Invalid incident count")

                required_fields = {
                    "incident_id", "version", "category",
                    "location", "severity", "status",
                    "title", "description", "attachment"
                }

                # Read exactly the announced number of records
                for _ in range(count):
                    line = self.recv_sync_line(conn)

                    self.log.info("TCP RECV | %s", line)

                    record = json.loads(line)

                    if not isinstance(record, dict):
                        raise ValueError("Invalid incident record")

                    if not required_fields.issubset(record):
                        raise ValueError("Incomplete incident record")

                    if record["status"] != "ACTIVE":
                        raise ValueError("Unexpected incident status")

                    if type(record["version"]) is not int or record["version"] < 1:
                        raise ValueError("Invalid incident version")

                    incident_id = record["incident_id"]

                    if not isinstance(incident_id, str) or not re.fullmatch(
                        r"INC[0-9]+", incident_id
                    ):
                        raise ValueError("Invalid incident ID")

                    if incident_id in recovered:
                        raise ValueError("Duplicate incident record")

                    for field in required_fields - {"version"}:
                        if not isinstance(record[field], str):
                            raise ValueError("Invalid incident field")

                    if record["severity"] not in SEVERITY:
                        raise ValueError("Invalid incident severity")

                    recovered[incident_id] = {
                        field: record[field]
                        for field in required_fields
                        if field != "incident_id"
                    }

                    # Match existing UDP version representation
                    recovered[incident_id]["version"] = str(
                        record["version"]
                    )

            # Update local state only after the complete TCP
            # response has been received and validated.
            with self.alerts_lock:

                # Identify UDP notifications processed during sync.
                new_seen = self.seen - previous_seen
                changed_ids = {key for key, version in new_seen}

                # Remove stale active incidents, except those
                # changed by UDP while synchronization was running.
                for incident_id in list(self.alerts):

                    if incident_id in changed_ids:
                        continue

                    if (
                        incident_id in previous_alerts
                        and incident_id not in recovered
                        and self.alerts[incident_id]["status"] == "ACTIVE"
                    ):
                        del self.alerts[incident_id]

                for incident_id, record in recovered.items():

                    local = self.alerts.get(incident_id)
                    incoming_version = int(record["version"])

                    known_versions = [
                        int(version)
                        for key, version in self.seen
                        if key == incident_id
                        and str(version).isdigit()
                    ]

                    # Never replace a newer notification with an
                    # older TCP snapshot.
                    if known_versions and max(known_versions) > incoming_version:
                        self.log.info(
                            "Skipped older snapshot for %s; "
                            "run sync again if needed",
                            incident_id
                        )
                        continue

                    if local and int(local["version"]) > incoming_version:
                        continue

                    if (
                        local
                        and local["status"] == "CLOSED"
                        and int(local["version"]) >= incoming_version
                    ):
                        continue

                    self.alerts[incident_id] = record

                    with self.seen_lock:
                        self.seen.add(
                            (incident_id, record["version"])
                        )

            self.log.info(
                "Synchronization complete: %d matching active incident(s) received",
                count
            )

            self.cmd_alerts([])

        except (OSError, EOFError, ValueError) as e:
            self.log.info("Synchronization failed: %s", e)

    def cmd_alerts(self, args):
        if args:
            print("Usage: alerts")
            return

        with self.alerts_lock:
            active = {
                key: dict(value)
                for key, value in self.alerts.items()
                if value["status"] == "ACTIVE"
            }

        print(f"\nActive incidents: {len(active)}")

        if not active:
            print("No active incidents.")
            return

        for incident_id, incident in sorted(active.items()):
            print(
                f"\n{incident_id} (v{incident['version']})"
                f" | {incident['severity']}"
                f" | {incident['category']}"
                f" at {incident['location']}"
            )

            print(
                f"  {incident['title'].replace('_', ' ')}:"
                f" {incident['description'].replace('_', ' ')}"
            )

            if incident["attachment"] != "NONE":
                print(f"  Attachment: {incident['attachment']}")

        print()


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
                line = input("> ").split()
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
