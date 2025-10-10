import subprocess
import sys
import argparse
from collections import defaultdict, deque
import time
import joblib
import pandas as pd
from colorama import Fore, Style
from datetime import datetime
import threading
import queue
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import ipaddress
import argparse

try:
    from routeros_api import RouterOsApiPool
except Exception:
    RouterOsApiPool = None

class HybridDDoSDetector:
    def __init__(self, interface='any', model_path='model/ddos_model.pkl',
                 iptables_enabled=True, blackhole_enabled=True,
                 mikrotik_enabled=False, mt_host=None, mt_user=None, mt_pass=None, mt_port=8728):
        self.interface = interface

        try:
            self.model = joblib.load(model_path)
            self.label_encoder = joblib.load('model/label_encoder.pkl')
        except Exception as e:
            print(Fore.RED + f"# Gagal load model/encoder: {e}" + Style.RESET_ALL)
            self.model = None
            self.label_encoder = None

        self.thresholds = {'ICMP': 10, 'UDP': 100, 'TCP': 200, 'OTHER': 100}
        self.packet_queue = queue.Queue(maxsize=200000)
        self.state_memory = defaultdict(lambda: deque(maxlen=5))
        self.last_attack_time = defaultdict(float)
        self.attack_hold_time = 5
        self.blacklist = set()
        self.whitelist = {"10.10.18.1"}
        self.last_ttl = {}
        self.iptables_enabled = bool(iptables_enabled)
        self.blackhole_enabled = bool(blackhole_enabled)

        self.mikrotik_enabled = bool(mikrotik_enabled) and RouterOsApiPool is not None
        self.mt_host = mt_host
        self.mt_user = mt_user
        self.mt_pass = mt_pass
        self.mt_port = int(mt_port) if mt_port else 8728
        self._mt_pool = None
        self._mt_api = None

        if self.mikrotik_enabled:
            if not (self.mt_host and self.mt_user and self.mt_pass):
                print(Fore.YELLOW + "# Mikrotik enabled but credentials/host not provided -> disabling mikrotik mode" + Style.RESET_ALL)
                self.mikrotik_enabled = False
            else:
                try:
                    self._mt_pool = RouterOsApiPool(self.mt_host,
                                                    username=self.mt_user,
                                                    password=self.mt_pass,
                                                    port=self.mt_port,
                                                    plaintext_login=True,
                                                    use_ssl=False)
                    self._mt_api = self._mt_pool.get_api()
                    print(Fore.CYAN + f"# Connected to MikroTik API {self.mt_host}:{self.mt_port}" + Style.RESET_ALL)
                except Exception as e:
                    print(Fore.RED + f"# Gagal konek ke MikroTik API: {e} -> mikrotik mode disabled" + Style.RESET_ALL)
                    self.mikrotik_enabled = False
                    self._mt_pool = None
                    self._mt_api = None

        threading.Thread(target=self._analyzer_worker, daemon=True).start()
        threading.Thread(target=self._sync_blacklist_worker, daemon=True).start()
        threading.Thread(target=self._cleanup_old_ips_worker, daemon=True).start()

    def _choose_ip_from_field(self, ip_field: str) -> str:
        if not ip_field:
            return ''
        parts = [p.strip() for p in ip_field.split(',') if p.strip()]

        for p in parts:
            if p.startswith("192.168.64."):
                return p

        for p in reversed(parts):
            try:
                ip = ipaddress.ip_address(p)
                if ip.version == 4:
                    return p
            except Exception:
                continue

        return parts[-1] if parts else ''


    def _choose_proto_from_field(self, proto_field: str):
        if not proto_field:
            return ('OTHER', 0)
        parts = [p.strip() for p in proto_field.split(',') if p.strip()]
        nums = []
        for p in parts:
            try:
                nums.append(int(p))
            except:
                txt = p.upper()
                if 'ICMP' in txt:
                    return ('ICMP', 1)
                if 'TCP' in txt:
                    return ('TCP', 6)
                if 'UDP' in txt:
                    return ('UDP', 17)
        for n in reversed(nums):
            if n in (1, 6, 17):
                return ({1:'ICMP',6:'TCP',17:'UDP'}[n], n)
        if nums:
            n = nums[-1]
            return ({1:'ICMP',6:'TCP',17:'UDP'}.get(n, f'PROTO_{n}'), n)
        return ('OTHER', 0)

    def _choose_int_from_field(self, field: str, default=0):
        if not field:
            return default
        for part in field.split(','):
            part = part.strip()
            try:
                return int(part)
            except:
                continue
        return default

    def _parse_tshark_line(self, packet_data: str):
        fields = packet_data.split('|')
        raw_time = fields[0] if len(fields) > 0 else ''
        raw_ip_src = fields[1] if len(fields) > 1 else ''
        raw_protocol = fields[2] if len(fields) > 2 else ''
        raw_len = fields[3] if len(fields) > 3 else ''
        raw_proto_num = fields[4] if len(fields) > 4 else ''
        raw_ttl = fields[5] if len(fields) > 5 else ''

        src_ip = self._choose_ip_from_field(raw_ip_src)
        protocol_name, proto_num = self._choose_proto_from_field(raw_proto_num if raw_proto_num else raw_protocol)

        pkt_len = 0
        if raw_len:
            try:
                pkt_len = int(raw_len.split(',')[-1])
            except:
                try:
                    pkt_len = int(raw_len.split(',')[0])
                except:
                    pkt_len = 0

        ttl = self._choose_int_from_field(raw_ttl, default=0)

        return {
            'time_epoch': float(raw_time) if raw_time else 0.0,
            'src_ip': src_ip,
            'protocol': protocol_name,
            'pkt_len': pkt_len,
            'pkt_proto': proto_num,
            'ip_ttl': ttl,
            'raw': packet_data
        }

    def enable_iptables(self, enabled: bool):
        self.iptables_enabled = bool(enabled)
        print(Fore.CYAN + f"# iptables_enabled = {self.iptables_enabled}" + Style.RESET_ALL)

    def enable_blackhole(self, enabled: bool):
        self.blackhole_enabled = bool(enabled)
        print(Fore.CYAN + f"# blackhole_enabled = {self.blackhole_enabled}" + Style.RESET_ALL)

    def run(self):
        print(f"{Fore.CYAN}# Starting hybrid DDoS detection (TZSP) on {self.interface}{Style.RESET_ALL}\n")
        print(Fore.CYAN + f"# iptables_enabled={self.iptables_enabled}, blackhole_enabled={self.blackhole_enabled}, mikrotik_enabled={self.mikrotik_enabled}" + Style.RESET_ALL)
        header = (
            f"{'Datetime':<20} | {'Source IP':<15} | {'Protocol':<9} | "
            f"{'PktLen':>8} | {'PktRate':>8} | {'PktCount':>9} | {'IP TTL':>6} | {'Status':<12}"
        )
        print(Fore.YELLOW + header + Style.RESET_ALL)
        print(Fore.YELLOW + "-" * len(header) + Style.RESET_ALL)

        tshark_cmd = [
            'sudo', 'tshark', '-i', self.interface, '-f', 'udp port 37008',
            '-d', 'udp.port==37008,tzsp',
            '-l', '-Y', 'ip',
            '-T', 'fields',
            '-e', 'frame.time_epoch', '-e', 'ip.src', '-e', '_ws.col.Protocol',
            '-e', 'frame.len', '-e', 'ip.proto', '-e', 'ip.ttl',
            '-E', 'header=n', '-E', 'separator=|'
        ]
        proc = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

        try:
            for line in iter(proc.stdout.readline, b''):
                line = line.decode(errors='ignore').strip()
                if line:
                    try:
                        self.packet_queue.put_nowait(line)
                    except queue.Full:
                        pass
        except KeyboardInterrupt:
            print(Fore.CYAN + "\n# Detection stopped" + Style.RESET_ALL)
            proc.terminate()

    def _sync_blacklist_worker(self, interval=5):
        while True:
            try:
                if self.mikrotik_enabled and self._mt_api:
                    try:
                        al = self._mt_api.get_resource('/ip/firewall/address-list')
                        items = al.get()
                        current_blocks = set()
                        for it in items:
                            if it.get('list') == 'blacklist' and 'address' in it:
                                current_blocks.add(it['address'])
                        removed_ips = self.blacklist - current_blocks
                        for ip in removed_ips:
                            if ip in self.blacklist:
                                self.blacklist.remove(ip)
                            self.clear_ip_state(ip)
                            keys_to_delete = [k for k in list(self.state_memory.keys()) if k[0] == ip]
                            for k in keys_to_delete:
                                del self.state_memory[k]
                            keys_to_reset = [k for k in list(self.last_attack_time.keys()) if k[0] == ip]
                            for k in keys_to_reset:
                                del self.last_attack_time[k]
                        self.blacklist.update(current_blocks)
                    except Exception as e:
                        print(Fore.RED + f"# Error syncing from MikroTik: {e}" + Style.RESET_ALL)
                else:
                    if not self.iptables_enabled:
                        if self.blacklist:
                            print(Fore.YELLOW + "# iptables disabled -> membersihkan blacklist internal" + Style.RESET_ALL)
                        self.blacklist.clear()
                        time.sleep(interval)
                        continue

                    result = subprocess.run(
                        ["sudo", "iptables", "-L", "INPUT", "-n"],
                        capture_output=True, text=True
                    )
                    current_blocks = set()
                    for line in result.stdout.splitlines():
                        if "DROP" in line:
                            parts = line.split()
                            for tok in parts:
                                if self._looks_like_ip(tok):
                                    current_blocks.add(tok)
                    removed_ips = self.blacklist - current_blocks
                    for ip in removed_ips:
                        if ip in self.blacklist:
                            self.blacklist.remove(ip)
                        keys_to_delete = [k for k in list(self.state_memory.keys()) if k[0] == ip]
                        for k in keys_to_delete:
                            del self.state_memory[k]
                        keys_to_reset = [k for k in list(self.last_attack_time.keys()) if k[0] == ip]
                        for k in keys_to_reset:
                            del self.last_attack_time[k]
                    self.blacklist.update(current_blocks)

            except Exception as e:
                print(Fore.RED + f"# Error syncing blacklist: {e}" + Style.RESET_ALL)
            time.sleep(interval)

    def _looks_like_ip(self, s):
        parts = s.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    def _block_ip(self, ip):
        if ip not in self.blacklist:
            self.blacklist.add(ip)
            try:
                    al = self._mt_api.get_resource('/ip/firewall/address-list')
                    exists = False
                    for it in al.get():
                        if it.get('list') == 'blacklist' and it.get('address') == ip:
                            exists = True
                            break
                    if not exists:
                        al.add(list='blacklist', address=ip, comment='Auto-blocked by detector')

                    fw = self._mt_api.get_resource('/ip/firewall/filter')
                    rules = fw.get()
                    def has_rule(match):
                        for r in rules:
                            if r.get('chain') == match.get('chain') and r.get('action') == match.get('action'):
                                if match.get('src-address') and r.get('src-address') == match.get('src-address'):
                                    return True
                                if match.get('dst-address') and r.get('dst-address') == match.get('dst-address'):
                                    return True
                        return False

                    input_rule = {'chain':'input', 'src-address':ip, 'action':'drop', 'comment':'auto-block-input'}
                    forward_rule = {'chain':'forward', 'src-address':ip, 'action':'drop', 'comment':'auto-block-forward'}

                    if not has_rule(input_rule): 
                        fw.add(**input_rule)
                    if not has_rule(forward_rule):
                        fw.add(**forward_rule)

                    print(Fore.MAGENTA + f"# IP {ip} diblokir via MikroTik." + Style.RESET_ALL)
            except Exception as e:
                    print(Fore.RED + f"# Gagal block via MikroTik: {e}" + Style.RESET_ALL)

    def _analyzer_worker(self):
        window_data = []
        last_flush = time.time()
        while True:
            try:
                line = self.packet_queue.get(timeout=0.1)
                window_data.append(line)
            except queue.Empty:
                pass

            now = time.time()
            if now - last_flush >= 1.0:
                if window_data:
                    self._process_window(window_data, last_flush)
                    window_data = []
                last_flush = now

    def _process_window(self, packets, window_time):
        counters = defaultdict(int)
        pkt_len_sum = defaultdict(int)

        for packet_data in packets:
            try:
                parsed = self._parse_tshark_line(packet_data)
                src_ip = parsed['src_ip']
                protocol = parsed['protocol']
                pkt_len = parsed['pkt_len']
                proto_num = parsed['pkt_proto']
                ttl = parsed['ip_ttl']

                if (
                    not src_ip
                    or src_ip in self.blacklist
                    or src_ip in self.whitelist
                    or src_ip.startswith("10.10.18.")
                ):
                    continue

                counters[(src_ip, protocol)] += 1
                pkt_len_sum[(src_ip, protocol)] += pkt_len
                self.last_ttl[(src_ip, protocol)] = ttl
            except Exception:
                continue

        for (src_ip, protocol), count in counters.items():
            rate = count
            threshold = self.thresholds.get(protocol, self.thresholds['OTHER'])
            avg_len = pkt_len_sum[(src_ip, protocol)] // count if count > 0 else 0
            ttl = self.last_ttl.get((src_ip, protocol), 0)

            data = {
                'protocol_ICMP': 1 if protocol == 'ICMP' else 0,
                'protocol_TCP': 1 if protocol == 'TCP' else 0,
                'protocol_UDP': 1 if protocol == 'UDP' else 0,
                'pkt_len': avg_len,
                'pkt_rate': min(rate, 1000000),
                'pkt_count': count,
                'ip_ttl': ttl
            }

            if self.model is None or self.label_encoder is None:
                ml_label = "Normal"
                ml_prob = 1.0
            else:
                try:
                    df = pd.DataFrame([data])[self.model.feature_names_in_]
                    ml_pred = self.model.predict(df)
                    ml_label_raw = self.label_encoder.inverse_transform(ml_pred)[0]
                    ml_prob = self.model.predict_proba(df).max()
                    label_map = {
                        "DDOS-Attack": "DDOS-Attack",
                        "DDoS Attack": "DDOS-Attack",
                        "ddos_attack": "DDOS-Attack",
                        "Attack": "DDOS-Attack",
                        "Normal": "Normal",
                        "normal": "Normal",
                        "1": "Normal",
                        "0": "DDOS-Attack"
                    }
                    ml_label = label_map.get(ml_label_raw, "Normal")
                except Exception as e:
                    print(Fore.RED + f"# Feature/mode error: {e}" + Style.RESET_ALL)
                    ml_label = "Normal"
                    ml_prob = 1.0

            threshold_label = "Normal"
            if count > threshold or (protocol == "ICMP" and rate > 1000) or (protocol == "UDP" and rate > 500):
                threshold_label = "DDOS-Attack"

            final_label = ml_label
            if ml_label == "DDOS-Attack" and threshold_label == "Normal":
                if ml_prob < 0.7:
                    final_label = "Normal"
            elif threshold_label == "DDOS-Attack" and ml_label == "Normal":
                final_label = "DDOS-Attack"

            key = (src_ip, protocol)
            self.state_memory[key].append(final_label)
            if list(self.state_memory[key]).count("DDOS-Attack") >= 3:
                self._block_ip(src_ip)
                final_label = "DDOS-Attack"

            now = time.time()
            if final_label == "DDOS-Attack":
                self.last_attack_time[key] = now
            else:
                if now - self.last_attack_time[key] < self.attack_hold_time:
                    final_label = "DDOS-Attack"

            label_color = Fore.GREEN if final_label == "Normal" else Fore.RED
            dt_str = datetime.fromtimestamp(window_time).strftime("%Y-%m-%d %H:%M:%S")

            print(
                f"{dt_str:<20} | {src_ip:<15} | {protocol:<9} | {avg_len:>8} | "
                f"{rate:>8} | {count:>9} | {ttl:>6} | {label_color}{final_label:<12}{Style.RESET_ALL}"
            )
            sys.stdout.flush()

    def _get_proto_name(self, proto_num):
        proto_map = {1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP", 88: "EIGRP"}
        return proto_map.get(proto_num, f"PROTO_{proto_num}")
    
    def clear_ip_state(self, ip):
        """Clear all internal state for a specific IP"""
        keys_to_delete = [k for k in list(self.state_memory.keys()) if k[0] == ip]
        for k in keys_to_delete:
            if k in self.state_memory:
                del self.state_memory[k]
        
        keys_to_reset = [k for k in list(self.last_attack_time.keys()) if k[0] == ip]
        for k in keys_to_reset:
            if k in self.last_attack_time:
                del self.last_attack_time[k]
        
        keys_ttl = [k for k in list(self.last_ttl.keys()) if k[0] == ip]
        for k in keys_ttl:
            if k in self.last_ttl:
                del self.last_ttl[k]
        
        print(Fore.CYAN + f"# State cleared for IP: {ip}" + Style.RESET_ALL)
    
    def _cleanup_old_ips_worker(self, max_age=300):
        """Clean up state for IPs that haven't been seen for a while"""
        while True:
            try:
                current_time = time.time()
                for key in list(self.state_memory.keys()):
                    if current_time - self._get_last_seen_time(key[0]) > max_age:
                        del self.state_memory[key]
                
                # Clean last_attack_time
                for key in list(self.last_attack_time.keys()):
                    if current_time - self.last_attack_time[key] > max_age:
                        del self.last_attack_time[key]
                        
            except Exception as e:
                print(Fore.RED + f"# Error cleaning old IPs: {e}" + Style.RESET_ALL)
            time.sleep(60)

    def _get_last_seen_time(self, ip):
        """Get last time an IP was seen in any state"""
        for key in self.state_memory.keys():
            if key[0] == ip:
                return time.time()
        return 0

class UnblockHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/unblock":
            length = int(self.headers.get('content-length', 0))
            body = self.rfile.read(length)
            try:
                data = json.loads(body.decode())
            except Exception:
                self._send_response(400, {"status": "error", "message": "invalid json"})
                return

            ip = data.get("src_ip")
            if ip:
                try:
                    if detector.mikrotik_enabled and detector._mt_api:
                        try:
                            al = detector._mt_api.get_resource('/ip/firewall/address-list')
                            items = al.get()
                            for it in items:
                                if it.get('list') == 'blacklist' and it.get('address') == ip:
                                    al.remove(id=it['.id'])
                            fw = detector._mt_api.get_resource('/ip/firewall/filter')
                            rules = fw.get()
                            for r in rules:
                                if r.get('comment','').startswith('auto-block') and (r.get('src-address') == ip or r.get('dst-address') == ip):
                                    fw.remove(id=r['.id'])
                            rt = detector._mt_api.get_resource('/ip/route')
                            routes = rt.get()
                            for r in routes:
                                if r.get('dst-address') == f"{ip}/32" and r.get('type') == 'blackhole':
                                    rt.remove(id=r['.id'])
                            try:
                                conn = detector._mt_api.get_resource('/ip/firewall/connection')
                                conns = conn.get()
                                for c in conns:
                                    if c.get('src-address') == ip or c.get('dst-address') == ip:
                                        try:
                                            conn.remove(id=c['.id'])
                                        except Exception:
                                            continue
                            except Exception:
                                pass

                            if ip in detector.blacklist:
                                detector.blacklist.remove(ip)
                            keys_to_delete = [k for k in list(detector.state_memory.keys()) if k[0] == ip]
                            for k in keys_to_delete:
                                del detector.state_memory[k]
                            keys_to_reset = [k for k in list(detector.last_attack_time.keys()) if k[0] == ip]
                            for k in keys_to_reset:
                                del detector.last_attack_time[k]

                            self._send_response(200, {"status": "success", "message": f"{ip} unblocked (mikrotik)"})
                            print(Fore.GREEN + f"# IP {ip} berhasil di-unblock dari MikroTik." + Style.RESET_ALL)
                            return
                        except Exception as e:
                            print(Fore.RED + f"# Gagal unblock via MikroTik API: {e}" + Style.RESET_ALL)
                            
                    if detector.iptables_enabled:
                        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=False)
                        subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"], check=False)
                    else:
                        print(Fore.YELLOW + f"# iptables disabled -> tidak menghapus rule iptables untuk {ip}" + Style.RESET_ALL)

                    if detector.blackhole_enabled:
                        subprocess.run(["sudo", "ip", "route", "del", "blackhole", f"{ip}/32"], check=False)
                    else:
                        print(Fore.YELLOW + f"# blackhole disabled -> tidak menghapus blackhole route untuk {ip}" + Style.RESET_ALL)

                    if ip in detector.blacklist:
                        detector.blacklist.remove(ip)
                    keys_to_delete = [k for k in list(detector.state_memory.keys()) if k[0] == ip]
                    for k in keys_to_delete:
                        del detector.state_memory[k]
                    keys_to_reset = [k for k in list(detector.last_attack_time.keys()) if k[0] == ip]
                    for k in keys_to_reset:
                        del detector.last_attack_time[k]
                    detector.clear_ip_state(ip)
                    self._send_response(200, {"status": "success", "message": f"{ip} unblocked"})
                    print(Fore.GREEN + f"# IP {ip} berhasil di-unblock dari server (fitur sesuai setting)." + Style.RESET_ALL)
                except Exception as e:
                    self._send_response(500, {"status": "error", "message": str(e)})
            else:
                self._send_response(400, {"status": "error", "message": "src_ip required"})

    def _send_response(self, code, data):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

def start_unblock_server(port=6000):
    server = HTTPServer(("0.0.0.0", port), UnblockHandler)
    print(Fore.CYAN + f"# Unblock server running on port {port}" + Style.RESET_ALL)
    threading.Thread(target=server.serve_forever, daemon=True).start()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Hybrid DDoS Detector (TZSP-ready)")
    parser.add_argument('--interface', '-i', default='any', help='Interface for tshark (default any)')
    parser.add_argument('--model', '-m', default='model/ddos_model.pkl', help='Path to ML model')
    parser.add_argument('--no-iptables', action='store_true', help='Disable iptables blocking')
    parser.add_argument('--no-blackhole', action='store_true', help='Disable blackhole route')
    
    parser.add_argument('--host', dest='mt_host', default=None, help='MikroTik host/IP')
    parser.add_argument('--user', dest='mt_user', default=None, help='MikroTik API username')
    parser.add_argument('--pass', dest='mt_pass', default=None, help='MikroTik API password')
    parser.add_argument('--mt-port', dest='mt_port', default=8728, help='MikroTik API port (default 8728)')
    parser.add_argument('--port', '-p', type=int, default=6000, help='Unblock server port')

    args = parser.parse_args()

    interface = args.interface
    model_path = args.model
    iptables_enabled = not args.no_iptables
    blackhole_enabled = not args.no_blackhole

    mikrotik_enabled = all([args.mt_host, args.mt_user, args.mt_pass])

    detector = HybridDDoSDetector(
        interface=interface,
        model_path=model_path,
        iptables_enabled=iptables_enabled,
        blackhole_enabled=blackhole_enabled,
        mikrotik_enabled=mikrotik_enabled,
        mt_host=args.mt_host,
        mt_user=args.mt_user,
        mt_pass=args.mt_pass,
        mt_port=args.mt_port
    )
    
    detector.whitelist.add("192.168.64.1")

    start_unblock_server(port=args.port)
    detector.run()
