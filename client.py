import argparse
import queue
import random
import socket
import sys
import threading

from common import (MAX_ATTEMPTS, SERVER_TCP_PORT, SERVER_UDP_PORT, TIMEOUT, SEVERITY, local_ip,
                    make_logger, make_tcp_listener, make_udp_socket, parse_list, recv_line,
                    tokenize, udp_recv)

HELP = """Commands:
  register [name] [role]           role = SUBSCRIBER | PUBLISHER | BOTH
  deregister
  subscribe <location> <category>
  unsubscribe <location> <category>
  publish <category> <location> <severity> <title> <description> <file>  
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
        self.notify_handlers = {"ALERT": self.on_alert}
        self.alerts = {}
        self.seen = set()
        self.seen_lock = threading.Lock()
        self.tcp_handlers = {}
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
                threading.Thread(target=handler, args=(t, addr), daemon=True).start()
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

        reply = self.request("PUBLISH_ALERT", category, location, severity, title, description, attachment)
        if not reply:
            return
        if reply[0] == "ALERT_ACCEPTED":
            self.log.info("Incident %s created", reply[2])
        else:
            self.log.info("Publish denied: %s", " ".join(reply[2:]) or "no reason given")


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
