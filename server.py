import argparse
import json
import os
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from common import (BASE_DIR, CATEGORIES, LOCATIONS, REPLY_CACHE_TTL, ROLES, SERVER_TCP_PORT,
                    SERVER_UDP_PORT, SEVERITY, STATUSES, TIMEOUT, MAX_ATTEMPTS, fmt_list, local_ip, make_logger, make_tcp_listener,
                    make_udp_socket, recv_line, tokenize, udp_recv, valid_ip, valid_name,
                    valid_port, matches)


class Store:
    def __init__(self, path, log):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.data = {"users": {}}
        if self.path.exists():
            try:
                with open(self.path, encoding="utf-8") as f:
                    self.data.update(json.load(f))
            except (OSError, json.JSONDecodeError) as e:
                bad = self.path.with_suffix(".corrupt")
                os.replace(self.path, bad)
                log.info("State file unreadable (%s), moved to %s and starting empty", e, bad.name)

    def save(self):
        with self.lock:
            tmp = self.path.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2)
            os.replace(tmp, self.path)


class EmergencyServer:
    def __init__(self, args):
        self.log = make_logger("SERVER", "server.log")
        self.store = Store(args.state, self.log)
        self.users = self.store.data["users"]
        self.store.data.setdefault("incidents", {})
        self.store.data.setdefault("next_incident", 101)
        self.store.data.setdefault("next_rq", 1)
        self.incidents = self.store.data["incidents"]
        self.loss = args.loss
        self.udp = make_udp_socket(args.host, args.udp_port)
        self.tcp = make_tcp_listener(args.host, args.tcp_port)
        self.pool = ThreadPoolExecutor(max_workers=args.workers)
        self.replies = {}
        self.udp_handlers = {
            "REGISTER": self.on_register,
            "DE-REGISTER": self.on_deregister,
            "SUBSCRIBE": self.on_subscribe,
            "UNSUBSCRIBE": self.on_unsubscribe,
            "PUBLISH_ALERT": self.on_publish_alert,
            "UPDATE_ALERT": self.on_update_alert,
            "CLOSE_ALERT": self.on_close_alert,
            "STATUS_REPORT": self.on_status_report,
            "ALERT_ACK": self.on_alert_ack,
            "ATTACH_REQ": self.on_attach_req,
        }
        self.tcp_handlers = {"GET_ACTIVE_ALERTS": self.on_get_active_alerts,
                             "CHECK_ATTACHMENT": self.on_check_attachment}
        self.ack_timeout = args.ack_timeout
        self.awaiting = {}                   
        self.store.data.setdefault("deliveries", {})
        self.store.data.setdefault("status_reports", {})
        # Timers are process-local; interrupted deliveries are not assumed successful.
        for versions in self.store.data["deliveries"].values():
            for recipients in versions.values():
                for name, status in recipients.items():
                    if status == "PENDING":
                        recipients[name] = "UNCONFIRMED"
        self.store.save()
        self.log.info("Emergency Server listening on UDP %s:%d and TCP %s:%d",
                      args.host, args.udp_port, args.host, args.tcp_port)
        self.log.info("Clients on other computers connect with: --server %s", local_ip())
        self.log.info("Recovered %d user(s) from %s", len(self.users), self.store.path.name)
        if self.users:
            self.print_users()

    def next_rq(self):
        n = self.store.data["next_rq"]
        self.store.data["next_rq"] += 1
        return f"{n:02d}"

    def send(self, msg, addr):
        self.udp.sendto(msg.encode("utf-8"), addr)
        self.log.info("SEND -> %s:%d | %s", addr[0], addr[1], msg)

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
            self.pool.submit(self.handle_datagram, msg, addr)

    def handle_datagram(self, msg, addr) :
        t = tokenize(msg)
        if not t:
            return
        handler = self.udp_handlers.get(t[0].upper())
        if handler is None:
            self.log.info("Unknown command '%s' from %s:%d ignored", t[0], *addr)
            return
        if len(t) < 2:
            self.log.info("Malformed message (missing RQ#) from %s:%d ignored", *addr)
            return
        with self.store.lock:
            reply = None if t[0] == "ATTACH_REQ" else self.cached_reply(addr, msg)
            if reply:
                self.log.info("Duplicate request RQ#%s from %s:%d, resending previous reply", t[1], *addr)
            else:
                try:
                    reply = handler(t, addr)
                except Exception:
                    self.log.exception("Error while handling: %s", msg)
                    return
                if reply and t[0] != "ATTACH_REQ":
                    self.replies[(addr, msg)] = (reply, time.time())
        if reply:
            self.send(reply, addr)

    def cached_reply(self, addr, msg):
        now = time.time()
        for k in [k for k, (_, ts) in self.replies.items() if now - ts > REPLY_CACHE_TTL]:
            del self.replies[k]
        hit = self.replies.get((addr, msg))
        return hit[0] if hit else None

    def forget_replies(self, addr):
        for k in [k for k in self.replies if k[0] == addr]:
            del self.replies[k]

    def owns(self, user, addr):
        return tuple(user["seen"]) == addr or (user["ip"], user["udp_port"]) == addr

    def user_by_addr(self, addr):
        for name, user in self.users.items():
            if self.owns(user, addr):
                return name, user
        return None, None


    #2.4 helper methods
    def find_recipients(self, incident):
        recipients = []
        for name, user in self.users.items():
            if user["role"] == "PUBLISHER":
                continue
            if any(matches(s, incident["category"], incident["location"]) for s in user["subscriptions"]):
                recipients.append((name, tuple(user["seen"])))
        return recipients

    def distribute(self, inc_id):
        try:
            with self.store.lock:
                inc = self.incidents.get(inc_id)
                if inc is None:
                    return
                inc = dict(inc)
                inc["recipients"] = self.incidents[inc_id].setdefault("recipients", [])
                outgoing = []
                for name, addr in self.find_recipients(inc):
                    if name not in inc.setdefault("recipients", []):
                        inc["recipients"].append(name)
                    msg = (f"ALERT {self.next_rq()} {inc_id} {inc['version']} {inc['category']} "
                           f"{inc['location']} {inc['severity']} {inc['title']} "
                           f"{inc['description']} {inc['attachment']}")
                    outgoing.append((name, addr, msg))
                    if inc["severity"] == "CRITICAL":
                        self.set_delivery(inc_id, inc["version"], name, "PENDING")
                self.store.save()
            if not outgoing:
                self.log.info("%s: no matching subscribers", inc_id)
            for name, addr, msg in outgoing:
                if inc["severity"] == "CRITICAL":
                    rq = msg.split()[1]
                    self.send_reliable(rq, name, addr, msg, inc_id, inc["version"])
                else:
                    self.send(msg, addr)
        except Exception:
            self.log.exception("Distribution of %s failed", inc_id)


    #2.5 helper methods

    def set_delivery(self, inc_id, version, name, status):

        d = self.store.data["deliveries"].setdefault(inc_id, {}). setdefault(str(version), {})
        d[name] = status

    def send_reliable(self, rq, name, addr, msg, inc_id, version):
        with self.store.lock:
            self.awaiting[rq] = {"name": name, "addr": addr, "msg": msg, "inc_id": inc_id, "version": version, "attempt": 1}
        self.send(msg, addr)
        self.start_timer(rq)

    def start_timer(self, rq):
        timer = threading.Timer(self.ack_timeout, self.on_ack_timeout, args=(rq,))
        timer.daemon = True
        with self.store.lock:
            entry = self.awaiting.get(rq)
            if entry is None:
                return
            entry["timer"] = timer
            timer.start()

    def on_ack_timeout(self, rq):
       
        with self.store.lock:
            entry = self.awaiting.get(rq)
            if entry is None:  # the ACK arrived meanwhile
                return
            if entry["attempt"] >= MAX_ATTEMPTS:
                del self.awaiting[rq]
                self.set_delivery(entry["inc_id"], entry["version"], entry["name"], "UNCONFIRMED")
                self.store.save()
                self.log.info("No ALERT_ACK from %s for %s v%s after %d attempts: UNCONFIRMED",
                              entry["name"], entry["inc_id"], entry["version"], MAX_ATTEMPTS)
                return
            entry["attempt"] += 1
            attempt = entry["attempt"]
        self.log.info("No ALERT_ACK for RQ#%s, retransmitting (attempt %d/%d)", rq, attempt, MAX_ATTEMPTS)
        self.send(entry["msg"], entry["addr"])
        self.start_timer(rq)

    def on_alert_ack(self, t, addr):
       
        if len(t) != 5:
            self.log.info("Malformed ALERT_ACK ignored")
            return None
        rq, inc_id, name = t[1], t[2], t[-1]
        entry = self.awaiting.get(rq)
        if (entry is None or entry["inc_id"] != inc_id or entry["name"] != name or
                str(entry["version"]) != t[3] or entry["addr"] != addr):
            self.log.info("Duplicate or unexpected ALERT_ACK RQ#%s from %s ignored", rq, name)
            return None
        del self.awaiting[rq]
        if entry.get("timer"):
            entry["timer"].cancel()
        self.set_delivery(inc_id, entry["version"], name, "ACKED")
        self.store.save()
        self.log.info("%s acknowledged %s v%s (attempt %d)", name, inc_id, entry["version"], entry["attempt"])
        return None

    def on_register(self, t, addr):
        rq = t[1]
        deny = f"REGISTER-DENIED {rq} "
        if len(t) != 7:
            return deny + "Malformed_Request"
        _, _, name, role, ip, udp, tcp = t
        role = role.upper()
        if not valid_name(name):
            return deny + "Invalid_Name"
        if role not in ROLES:
            return deny + "Invalid_Role"
        if not valid_ip(ip):
            return deny + "Invalid_IP_Address"
        if not (valid_port(udp) and valid_port(tcp)):
            return deny + "Invalid_Port"
        udp, tcp = int(udp), int(tcp)
        old = self.users.get(name)
        same_peer = old and (tuple(old["seen"]) == addr or
                             (old["ip"], old["udp_port"], old["tcp_port"]) == (ip, udp, tcp))
        if old and not same_peer:
            return deny + "Name_Already_Exists"
        owner, _ = self.user_by_addr(addr)
        if owner and owner != name:
            return deny + "Endpoint_Already_Registered"
        subs = old["subscriptions"] if old and role != "PUBLISHER" else []
        self.users[name] = {"role": role, "ip": ip, "udp_port": udp, "tcp_port": tcp,
                            "seen": list(addr), "subscriptions": subs,
                            "registered_at": time.strftime("%Y-%m-%d %H:%M:%S")}
        self.store.save()
        self.log.info("%s %s as %s", "Re-registered" if old else "Registered", name, role)
        if ip != addr[0]:
            self.log.info("Note: %s declared IP %s but its packets come from %s (NAT/other interface)",
                          name, ip, addr[0])
        self.print_users()
        return f"REGISTERED {rq} {fmt_list(LOCATIONS)} {fmt_list(CATEGORIES)}"

    def on_deregister(self, t, addr):
        if len(t) != 3:
            self.log.info("Malformed DE-REGISTER ignored")
            return None
        name = t[2]
        user = self.users.get(name)
        if user is None:
            self.log.info("DE-REGISTER for unknown user '%s' ignored", name)
        elif not self.owns(user, addr):
            self.log.info("DE-REGISTER for '%s' from %s:%d (not its endpoint) ignored", name, *addr)
        else:
            del self.users[name]
            self.store.save()
            self.forget_replies(addr)
            self.log.info("De-registered %s", name)
            self.print_users()
        return None

    def check_subscription(self, t, addr, deny):
        if len(t) != 4:
            return None, None, deny + "Malformed_Request"
        name, user = self.user_by_addr(addr)
        if user is None:
            return None, None, deny + "Not_Registered"
        if user["role"] == "PUBLISHER":
            return None, None, deny + "Unauthorized_Role"
        loc, cat = t[2].upper(), t[3].upper()
        if loc not in LOCATIONS:
            return None, None, deny + "Invalid_Location"
        if cat not in CATEGORIES:
            return None, None, deny + "Invalid_Category"
        return name, [loc, cat], None

    def on_subscribe(self, t, addr):
        rq = t[1]
        name, sub, denied = self.check_subscription(t, addr, f"SUBSCRIPTION-DENIED {rq} ")
        if denied:
            return denied
        subs = self.users[name]["subscriptions"]
        if sub not in subs:
            subs.append(sub)
            self.store.save()
        self.log.info("%s subscribed to %s/%s", name, *sub)
        self.print_users()
        return f"SUBSCRIBED {rq}"

    def on_unsubscribe(self, t, addr):
        rq = t[1]
        name, sub, denied = self.check_subscription(t, addr, f"UNSUBSCRIPTION-DENIED {rq} ")
        if denied:
            return denied
        subs = self.users[name]["subscriptions"]
        if sub not in subs:
            return f"UNSUBSCRIPTION-DENIED {rq} Not_Subscribed"
        subs.remove(sub)
        self.store.save()
        self.log.info("%s unsubscribed from %s/%s", name, *sub)
        self.print_users()
        return f"UNSUBSCRIBED {rq}"

    def on_publish_alert(self, t, addr):
        rq = t[1]
        deny = f"ALERT_DENIED {rq} "

        if len(t) != 8:
            return deny + "Malformed_Request"
        _, _, category, location, severity, title, description, attachment = t
        category = category.upper()
        location = location.upper()
        severity = severity.upper()

        name, user = self.user_by_addr(addr)

        if user is None:
            return deny + "Not_Registered"
        if user["role"] not in ("PUBLISHER", "BOTH"):
            return deny + "Unauthorized_Role"

        if category not in CATEGORIES:
            return deny + "Invalid_Category"
        if location not in LOCATIONS:
            return deny + "Invalid_Location"
        if severity not in SEVERITY:
            return deny + "Invalid_Severity"
        
        inc_id = f"INC{self.store.data['next_incident']}"
        self.store.data["next_incident"] += 1
        self.incidents[inc_id] = {
            "publisher": name,
            "category": category,
            "location": location,
            "severity": severity,
            "title": title,
            "description": description,
            "attachment": attachment,
            "version": 1,
            "status": "ACTIVE",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        
        self.store.save()

        self.log.info("%s published %s: %s at %s, %s, %s", name, inc_id,
                  category, location, severity, title)
        self.pool.submit(self.distribute, inc_id)

        return f"ALERT_ACCEPTED {rq} {inc_id}"

    #2.6 Updating an existing incident
    def on_update_alert(self, t, addr):
        # UPDATE_ALERT RQ# Incident_ID Severity Title Description
        rq = t[1]
        deny = f"UPDATE_DENIED {rq} "

        if len(t) != 6:
            return deny + "Malformed_Message"
        incident_id = t[2].upper()
        severity = t[3].upper()
        title = t[4]
        description = t[5]

        name, user = self.user_by_addr(addr)
        if user is None:
            return deny + "Not_Registered"

        incident = self.incidents.get(incident_id)
        if incident is None:
            return deny + "Unknown_Incident"
        if incident["status"] != "ACTIVE":
            return deny + "Incident_Closed"
        if incident["publisher"] != name:
            return deny + "Not_Incident_Owner"
        if severity not in SEVERITY:
            return deny + "Invalid_Severity"

        incident["severity"] = severity
        incident["title"] = title
        incident["description"] = description
        incident["version"] = incident["version"] + 1
        self.store.save()

        self.log.info("%s updated %s, new version %d (%s)", name, incident_id,
                      incident["version"], severity)

        # send ALERT_UPDATE in its own thread so the reply is not delayed
        threading.Thread(target=self.send_update, args=(incident_id,), daemon=True).start()

        return f"ALERT_UPDATED {rq} {incident_id} {incident['version']}"

    def send_update(self, incident_id):
        # ALERT_UPDATE RQ# Incident_ID Version Severity Title Description
        with self.store.lock:
            incident = self.incidents[incident_id]
            version = incident["version"]
            severity = incident["severity"]
            recipients = self.find_recipients(incident)
            messages = []
            for name, addr in recipients:
                if name not in incident.setdefault("recipients", []):
                    incident["recipients"].append(name)
                rq = self.next_rq()
                msg = (f"ALERT_UPDATE {rq} {incident_id} {version} {severity} "
                       f"{incident['title']} {incident['description']}")
                messages.append((rq, name, addr, msg))
                if severity == "CRITICAL":
                    self.set_delivery(incident_id, version, name, "PENDING")
            self.store.save()

        if len(messages) == 0:
            self.log.info("%s: no matching subscribers for the update", incident_id)

        for rq, name, addr, msg in messages:
            if severity == "CRITICAL":
                # same ACK + retransmission as a CRITICAL ALERT (section 2.5)
                self.send_reliable(rq, name, addr, msg, incident_id, version)
            else:
                self.send(msg, addr)

    #2.7 Closing an incident and ALL_CLEAR
    def on_close_alert(self, t, addr):
        # CLOSE_ALERT RQ# Incident_ID Reason
        rq = t[1]
        deny = f"CLOSE_DENIED {rq} "

        if len(t) != 4:
            return deny + "Malformed_Message"
        incident_id = t[2].upper()
        reason = t[3]

        name, user = self.user_by_addr(addr)
        if user is None:
            return deny + "Not_Registered"

        incident = self.incidents.get(incident_id)
        if incident is None:
            return deny + "Unknown_Incident"
        if incident["status"] != "ACTIVE":
            return deny + "Incident_Closed"
        if incident["publisher"] != name:
            return deny + "Not_Incident_Owner"

        incident["status"] = "CLOSED"
        incident["version"] = incident["version"] + 1
        incident["close_reason"] = reason
        self.store.save()

        self.log.info("%s closed %s, new version %d (%s)", name, incident_id,
                      incident["version"], reason)

        threading.Thread(target=self.send_all_clear, args=(incident_id,), daemon=True).start()

        return f"ALERT_CLOSED {rq} {incident_id}"

    def send_all_clear(self, incident_id):
        # ALL_CLEAR RQ# Incident_ID Version Message
        with self.store.lock:
            incident = self.incidents[incident_id]
            version = incident["version"]
            recipients = dict(self.find_recipients(incident))
            prior = set(incident.get("recipients", []))
            for deliveries in self.store.data["deliveries"].get(incident_id, {}).values():
                prior.update(deliveries)
            for name in prior:
                user = self.users.get(name)
                if user and user["role"] != "PUBLISHER":
                    recipients[name] = tuple(user["seen"])
            recipients = list(recipients.items())
            messages = []
            for name, addr in recipients:
                rq = self.next_rq()
                msg = f"ALL_CLEAR {rq} {incident_id} {version} {incident['close_reason']}"
                messages.append((rq, name, addr, msg))
                self.set_delivery(incident_id, version, name, "PENDING")
            self.store.save()

        if len(messages) == 0:
            self.log.info("%s: no matching subscribers for ALL_CLEAR", incident_id)

        # ALL_CLEAR always needs an ALERT_ACK, so always use retransmission (section 2.5)
        for rq, name, addr, msg in messages:
            self.send_reliable(rq, name, addr, msg, incident_id, version)

    #2.8 User safety / response status
    def on_status_report(self, t, addr):
        # STATUS_REPORT RQ# Incident_ID Name Status
        rq = t[1]
        reject = f"STATUS_REJECTED {rq} "

        if len(t) != 5:
            return reject + "Malformed_Message"
        incident_id = t[2].upper()
        name = t[3]
        status = t[4].upper()

        sender_name, user = self.user_by_addr(addr)
        if user is None or sender_name != name:
            return reject + "Not_Registered"
        if user["role"] == "PUBLISHER":
            return reject + "Unauthorized_Role"

        incident = self.incidents.get(incident_id)
        if incident is None:
            return reject + "Unknown_Incident"
        if incident["status"] != "ACTIVE":
            return reject + "Incident_Closed"
        if status not in STATUSES:
            return reject + "Invalid_Status"

        # keep only the most recent status for this user and incident
        key = incident_id + "|" + name
        self.store.data["status_reports"][key] = status
        self.store.save()

        self.log.info("%s reported %s for %s", name, status, incident_id)
        return f"STATUS_RECORDED {rq}"


    #2.9.A Attachment source discovery (UDP)
    def on_attach_req(self, t, addr):
        rq = t[1]
        incident_id = t[2].upper() if len(t) > 2 else "UNKNOWN"
        deny = f"ATTACH_DENIED {rq} {incident_id} "

        if len(t) != 4:
            return deny + "Malformed_Request"
        file_name = t[3]

        name, user = self.user_by_addr(addr)
        if user is None:
            return deny + "Not_Registered"
        if user["role"] not in ("SUBSCRIBER", "BOTH"):
            return deny + "Unauthorized_Role"

        incident = self.incidents.get(incident_id)
        if incident is None:
            return deny + "Unknown_Incident"
        if incident["status"] != "ACTIVE":
            return deny + "Incident_Closed"
        if incident["attachment"] == "NONE":
            return deny + "No_Attachment"
        if incident["attachment"] != file_name:
            return deny + "Attachment_Mismatch"

        publisher_name = incident["publisher"]
        publisher = self.users.get(publisher_name)
        if publisher is None or publisher["role"] not in ("PUBLISHER", "BOTH"):
            return deny + "Publisher_Unavailable"

        self.log.info("%s requested %s for %s from %s",
                      name, file_name, incident_id, publisher_name)
        return (f"ATTACH_INFO {rq} {incident_id} {publisher_name} "
                f"{publisher['ip']} {publisher['tcp_port']} {file_name}")

    def tcp_send(self, conn, message):
        conn.sendall((message + "\n").encode("utf-8"))
        self.log.info("TCP SEND | %s", message)

    #2.10 Active incident synchronization
    def on_get_active_alerts(self, t, conn, addr):
        rq = t[1] if len(t) > 1 else "UNKNOWN"
        try:
            with self.store.lock:
                user = self.users.get(t[2]) if len(t) == 3 else None
                reason = ("Malformed_Request" if len(t) != 3 else
                          "Not_Registered" if user is None else
                          "Unauthorized_Role" if user["role"] == "PUBLISHER" else None)
                records = []
                if not reason:
                    fields = ("version", "category", "location", "severity", "status",
                              "title", "description", "attachment")
                    for key, inc in self.incidents.items():
                        if inc["status"] == "ACTIVE" and any(matches(sub, inc["category"], inc["location"]) for sub in user["subscriptions"]):
                            records.append(dict(incident_id=key, **{f: inc[f] for f in fields}))
            if reason:
                self.tcp_send(conn, f"ACTIVE_ALERTS_DENIED {rq} {reason}")
                return
            self.tcp_send(conn, f"ACTIVE_ALERTS {rq} {len(records)}")
            for record in records:
                self.tcp_send(conn, json.dumps(record, ensure_ascii=True))
        except OSError as e:
            self.log.info("Sync failed: %s", e)

    # Extension: publisher checks persisted ownership before serving a file.
    # This avoids a second, potentially inconsistent publisher-side database.
    def on_check_attachment(self, t, conn, addr):
        rq = t[1] if len(t) > 1 else "UNKNOWN"
        reason = "Malformed_Request"
        if len(t) == 6:
            _, _, publisher, subscriber, incident_id, filename = t
            with self.store.lock:
                owner = self.users.get(publisher)
                peer = self.users.get(subscriber)
                inc = self.incidents.get(incident_id)
                if not owner or owner["role"] not in ("PUBLISHER", "BOTH"):
                    reason = "Publisher_Unavailable"
                elif not peer or peer["role"] not in ("SUBSCRIBER", "BOTH"):
                    reason = "Subscriber_Not_Registered"
                elif not inc or inc["publisher"] != publisher:
                    reason = "Unknown_Incident_Or_Attachment"
                elif inc["status"] != "ACTIVE":
                    reason = "Incident_Closed"
                elif filename == "NONE" or inc["attachment"] != filename:
                    reason = "Attachment_Mismatch"
                else:
                    reason = None
        try:
            self.tcp_send(conn, f"CHECK_DENIED {rq} {reason}" if reason else f"CHECK_OK {rq}")
        except OSError as e:
            self.log.info("Attachment validation failed: %s", e)

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
                conn.settimeout(10)
                msg = recv_line(conn)
            except (OSError, EOFError, ValueError):
                return
            self.log.info("TCP RECV <- %s:%d | %s", addr[0], addr[1], msg)
            t = tokenize(msg)
            handler = self.tcp_handlers.get(t[0].upper()) if t else None
            if handler:
                handler(t, conn, addr)
            else:
                self.log.info("TCP request not supported yet, connection closed")

    def print_users(self):
        with self.store.lock:
            lines = [f"Registered users ({len(self.users)}):"]
            for name, u in sorted(self.users.items()):
                subs = ", ".join(f"{l}/{c}" for l, c in u["subscriptions"]) or "-"
                lines.append(f"    {name:<14} {u['role']:<10} {u['ip']}:{u['udp_port']}/{u['tcp_port']:<6}"
                             f" seen {u['seen'][0]}:{u['seen'][1]:<6} subs: {subs}")
        self.log.info("\n".join(lines))

    def run(self):
        threading.Thread(target=self.udp_loop, daemon=True).start()
        threading.Thread(target=self.tcp_loop, daemon=True).start()
        try:
            while True:
                try:
                    cmd = input().strip().lower()
                except EOFError:
                    while True:
                        time.sleep(1)
                if cmd == "users":
                    self.print_users()
                elif cmd in ("quit", "exit"):
                    break
                elif cmd:
                    print("Commands: users, quit")
        except KeyboardInterrupt:
            pass
        self.log.info("Server shutting down")
        self.udp.close()
        self.tcp.close()


def main():
    p = argparse.ArgumentParser(description="CENRS Emergency Server")
    p.add_argument("--host", default="0.0.0.0", help="interface to bind (0.0.0.0 = all)")
    p.add_argument("--udp-port", type=int, default=SERVER_UDP_PORT)
    p.add_argument("--tcp-port", type=int, default=SERVER_TCP_PORT)
    p.add_argument("--state", default=str(BASE_DIR / "data" / "server_state.json"))
    p.add_argument("--loss", type=float, default=0.0, help="simulated UDP loss rate, 0..1")
    p.add_argument("--workers", type=int, default=16)
    p.add_argument("--ack-timeout", type=float, default=TIMEOUT, help="seconds to wait for ALERT_ACK")
    EmergencyServer(p.parse_args()).run()


if __name__ == "__main__":
    main()
