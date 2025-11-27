import sys
sys.path.append("model")

from nb import NaiveBayesGaussian

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
from messages.message import Message
from datetime import datetime

class HybridDDoSDetector:
    def __init__(self, interface='enp0s8', model_path='model/result/model/ddos_model.pkl',
                 iptables_enabled=True, blackhole_enabled=True):
        self.interface = interface
        self.model = joblib.load(model_path)
        self.label_encoder = joblib.load('model/result/model/label_encoder.pkl')
        self.thresholds = {'ICMP': 10, 'UDP': 100, 'TCP': 200, 'OTHER': 100}
        self.packet_queue = queue.Queue(maxsize=200000)
        self.state_memory = defaultdict(lambda: deque(maxlen=5))
        self.last_attack_time = defaultdict(float)
        self.attack_hold_time = 1
        self.blacklist = set()
        self.whitelist = {"10.10.18.1"}

        self.iptables_enabled = bool(iptables_enabled)
        self.blackhole_enabled = bool(blackhole_enabled)

        threading.Thread(target=self._analyzer_worker, daemon=True).start()
        threading.Thread(target=self._sync_blacklist_worker, daemon=True).start()

    def enable_iptables(self, enabled: bool):
        self.iptables_enabled = bool(enabled)
        print(Fore.CYAN + f"# iptables_enabled = {self.iptables_enabled}" + Style.RESET_ALL)

    def enable_blackhole(self, enabled: bool):
        self.blackhole_enabled = bool(enabled)
        print(Fore.CYAN + f"# blackhole_enabled = {self.blackhole_enabled}" + Style.RESET_ALL)

    def run(self):
        print(f"{Fore.CYAN}# Starting DDoS detection on host {self.interface}{Style.RESET_ALL}\n")
        if self.iptables_enabled == False and self.blackhole_enabled == False:
            print(Fore.CYAN + f"# Block user access is turned off" + Style.RESET_ALL)
            
        header = (
            f"{'Datetime':<20} | {'Source IP':<15} | {'Protocol':<9} | "
            f"{'Packet Length':>14} | {'Packet Rate':>12} | {'Packet Count':>13} | {'IP TTL':>6} | {'Status':<12} | {'Probability':>12}"
        )

        print(Fore.YELLOW + header + Style.RESET_ALL)
        print(Fore.YELLOW + "-" * len(header) + Style.RESET_ALL)

        tshark_cmd = [
            'sudo', 'tshark', '-i', self.interface, '-l', '-T', 'fields',
            '-e', 'frame.time_epoch', '-e', 'ip.src', '-e', '_ws.col.Protocol',
            '-e', 'frame.len', '-e', 'ip.proto', '-e', 'ip.ttl',
            '-E', 'header=n', '-E', 'separator=|'
        ]
        
        proc = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

        try:
            for line in iter(proc.stdout.readline, b''):
                line = line.decode().strip()
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
                if not self.iptables_enabled:
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

            if self.iptables_enabled:
                try:
                    subprocess.run(["sudo", "iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"], check=False)
                    subprocess.run(["sudo", "iptables", "-I", "FORWARD", "1", "-s", ip, "-j", "DROP"], check=False)
                    print(Fore.MAGENTA + f"# IP {ip} diblokir" + Style.RESET_ALL)
                except Exception as e:
                    print(Fore.RED + f"# Gagal menambahkan rule iptables untuk {ip}: {e}" + Style.RESET_ALL)

            if self.blackhole_enabled:
                try:
                    subprocess.run(["sudo", "ip", "route", "add", "blackhole", f"{ip}/32"], check=False)
                    # print(Fore.MAGENTA + f"# Blackhole route ditambahkan untuk {ip}/32." + Style.RESET_ALL)
                except Exception as e:
                    print(Fore.RED + f"# Gagal tambah blackhole route untuk {ip}: {e}" + Style.RESET_ALL)

    def _analyzer_worker(self):
        window_data = []
        last_flush = time.time()
        WINDOW_SECONDS = 3.0

        while True:
            try:
                line = self.packet_queue.get(timeout=0.1)
                window_data.append(line)
            except queue.Empty:
                pass

            now = time.time()
            if now - last_flush >= WINDOW_SECONDS:
                if window_data:
                    self._process_window(window_data, last_flush, now)
                    window_data = []
                last_flush = now

    def _process_window(self, packets, window_start, window_end):
        counters = defaultdict(int)
        pkt_len_sum = defaultdict(int)

        for packet_data in packets:
            try:
                fields = packet_data.split('|')
                src_ip = fields[1] if len(fields) > 1 else ''
                
                if not src_ip.startswith('10.10.18.') or src_ip == '10.10.18.1':
                    continue
                
                protocol = fields[2].split()[0] if len(fields) > 2 and fields[2] else 'OTHER'
                
                if protocol not in ['ICMP', 'TCP', 'UDP']:
                    continue
                
                if not src_ip or src_ip in self.blacklist or src_ip in self.whitelist:
                    continue
                pkt_len = int(fields[3]) if len(fields) > 3 and fields[3] else 0
                ip_proto = int(fields[4]) if len(fields) > 4 and fields[4] else 0
                ttl = int(fields[5]) if len(fields) > 5 and fields[5] else 0

                if protocol == '':
                    protocol = self._get_proto_name(ip_proto)

                counters[(src_ip, protocol)] += 1
                pkt_len_sum[(src_ip, protocol)] += pkt_len
            except Exception:
                continue
        
        window_duration = max(window_end - window_start, 1e-6)

        for (src_ip, protocol), count in counters.items():
            pkt_rate = count / window_duration
            avg_len = pkt_len_sum[(src_ip, protocol)] // count if count > 0 else 0
            protocol_mapping = {'ICMP': 0, 'TCP': 1, 'UDP': 2}
    
            data = {
                'protocol': protocol_mapping.get(protocol, 3),
                'pkt_length': avg_len,
                'pkt_rate': pkt_rate,
                'pkt_count': count,
                'ip_ttl': ttl
            }

            try:
                df = pd.DataFrame([data]).reindex(columns=self.model.feature_names_in_, fill_value=0)
            except Exception as e:
                print(Fore.RED + f"# Feature mismatch saat reindex: {e}" + Style.RESET_ALL)
                print(Fore.RED + f"# model.features: {list(self.model.feature_names_in_)}" + Style.RESET_ALL)
                print(Fore.RED + f"# data.keys: {list(data.keys())}" + Style.RESET_ALL)
                continue

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
                1: "Normal",
                0: "DDOS-Attack"
            }
            ml_label = label_map.get(ml_label_raw, "Normal")

            final_label = ml_label 
            if final_label == "DDOS-Attack":
                is_low_traffic = pkt_rate < 500 and count < 25005
                
                if is_low_traffic:
                    final_label = "Normal"

            key = (src_ip, protocol)
            self.state_memory[key].append(final_label)
            if list(self.state_memory[key]).count("DDOS-Attack") >= 3:
                waktu_serangan = datetime.now().strftime("%d %B %Y %H:%M:%S")
                
                try:
                    wa_targets = [
                        "6285835524290",
                    ]

                    email_receivers = [
                        "liando1804@gmail.com",
                    ] 

                    wa_message = (
                        f"🚨 *PERINGATAN SERANGAN DDOS TERDETEKSI* 🚨\n\n"
                        f"📍 *Server Rumah Sakit Umum Daerah Tapan*\n"
                        f"🕒 *Waktu Serangan:* {waktu_serangan}\n"
                        f"🌐 *IP Penyerang:* {src_ip}\n"
                        f"📡 *Protokol:* {protocol}\n"
                        f"📦 *Rata-rata Paket:* {avg_len}\n"
                        f"⚙️ *Tingkat Lalu Lintas:* {pkt_rate}\n"
                        f"📊 *Jumlah Paket:* {count}\n"
                        f"🔁 *IP TTL:* {ttl}\n\n"
                        f"— Sistem Hybrid AI Detector"
                    )

                    for target in wa_targets:
                        Message(target, wa_message).send_via_whatsapp()
                        print(Fore.GREEN + f"# Pesan WhatsApp Dikirim" + Style.RESET_ALL)

                    subject = "🚨 Peringatan Serangan DDoS di Server RSUD Tapan"
                    email_body = f"""
                    <html>
                    <body style="font-family: 'Segoe UI', Arial, sans-serif; background-color: #f4f6f8; padding: 30px;">

                        <div style="max-width: 600px; margin: auto; background-color: #ffffff; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); padding: 30px;">
                            <div style="text-align: center; margin-bottom: 20px;">
                                <div style="background-color: #d9534f; color: white; display: inline-block; padding: 10px 20px; border-radius: 8px; font-size: 18px; font-weight: bold;">
                                    🚨 Peringatan Serangan DDoS
                                </div>
                            </div>

                            <p style="font-size: 15px; color: #333333; text-align: justify;">
                                Telah terdeteksi aktivitas mencurigakan pada sistem jaringan 
                                <b>Rumah Sakit Umum Daerah Tapan</b>. Berikut detail hasil analisis otomatis sistem:
                            </p>

                            <div style="background-color: #f9f9f9; border-left: 5px solid #d9534f; padding: 15px 20px; border-radius: 8px; margin-top: 15px;">
                                <p style="margin: 6px 0;"><b>🕒 Waktu Deteksi:</b> {waktu_serangan}</p>
                                <p style="margin: 6px 0;"><b>🌐 IP Penyerang:</b> {src_ip}</p>
                                <p style="margin: 6px 0;"><b>📡 Protokol:</b> {protocol}</p>
                                <p style="margin: 6px 0;"><b>📦 Rata-rata Panjang Paket:</b> {avg_len}</p>
                                <p style="margin: 6px 0;"><b>⚙️ Tingkat Lalu Lintas:</b> {pkt_rate:.0f}</p>
                                <p style="margin: 6px 0;"><b>📊 Jumlah Paket:</b> {count}</p>
                                <p style="margin: 6px 0;"><b>🔁 IP TTL:</b> {ttl}</p>
                            </div>

                            <div style="margin-top: 30px; text-align: center; color: #555555; font-size: 14px;">
                                <p style="margin: 0;"><i>— Sistem Hybrid AI Detector</i></p>
                                <p style="margin: 0;"><i>Rumah Sakit Umum Daerah Tapan</i></p>
                            </div>
                        </div>

                    </body>
                    </html>
                    """

                    for receiver in email_receivers:
                        Message(receiver, email_body, subject).send_via_email()
                        print(Fore.YELLOW + f"# Pesan Email Dikirim" + Style.RESET_ALL)

                    print(Fore.CYAN + f"# Notifikasi berhasil dikirim ke WhatsApp & Email." + Style.RESET_ALL)

                except Exception as e:
                    print(Fore.RED + f"# Gagal mengirim notifikasi: {e}" + Style.RESET_ALL)

                try:
                    wa_block_message = (
                        f"🔒 *NOTIFIKASI PEMBLOKIRAN AKSES PENGGUNA* 🔒\n\n"
                        f"📍 *Server Rumah Sakit Umum Daerah Tapan*\n"
                        f"🕒 *Waktu Pemblokiran:* {waktu_serangan}\n"
                        f"🌐 *IP yang Diblokir:* {src_ip}\n"
                        f"📡 *Protokol Serangan:* {protocol}\n\n"
                        f"✅ *Status:* Akses telah berhasil diblokir\n\n"
                        f"ℹ️ *Informasi Tambahan:*\n"
                        f"• Metode Blocking: iptables & Blackhole Route\n"
                        f"• Alasan: Serangan DDoS terdeteksi dan dikonfirmasi (3x deteksi)\n"
                        f"• Paket Serangan: {count} paket\n"
                        f"• Tingkat Lalu Lintas: {pkt_rate:.0f} pps\n\n"
                        f"Sistem akan terus memantau jaringan untuk keamanan maksimal.\n\n"
                        f"— Sistem Hybrid AI Detector"
                    )

                    block_email_body = f"""
                    <html>
                    <body style="font-family: 'Segoe UI', Arial, sans-serif; background-color: #f4f6f8; padding: 30px;">

                        <div style="max-width: 600px; margin: auto; background-color: #ffffff; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); padding: 30px;">
                            <div style="text-align: center; margin-bottom: 20px;">
                                <div style="background-color: #5cb85c; color: white; display: inline-block; padding: 10px 20px; border-radius: 8px; font-size: 18px; font-weight: bold;">
                                    🔒 Notifikasi Pemblokiran Akses
                                </div>
                            </div>

                            <p style="font-size: 15px; color: #333333; text-align: justify;">
                                Sistem telah berhasil memblokir akses dari IP yang melakukan serangan DDoS. 
                                Berikut ringkasan aksi keamanan yang telah dilakukan:
                            </p>

                            <div style="background-color: #f0f8f0; border-left: 5px solid #5cb85c; padding: 15px 20px; border-radius: 8px; margin-top: 15px;">
                                <p style="margin: 6px 0;"><b>🕒 Waktu Pemblokiran:</b> {waktu_serangan}</p>
                                <p style="margin: 6px 0;"><b>🌐 IP yang Diblokir:</b> <span style="font-family: monospace; background-color: #f0f0f0; padding: 2px 6px;">{src_ip}</span></p>
                                <p style="margin: 6px 0;"><b>📡 Protokol Serangan:</b> {protocol}</p>
                                <p style="margin: 6px 0;"><b>📊 Total Paket Serangan:</b> {count} paket</p>
                                <p style="margin: 6px 0;"><b>⚙️ Laju Paket:</b> {pkt_rate:.0f} pps (paket per detik)</p>
                            </div>

                            <div style="margin-top: 20px; background-color: #f9f9f9; border: 1px solid #ddd; padding: 15px 20px; border-radius: 8px;">
                                <p style="margin: 0; font-size: 14px; color: #555;"><b>📌 Metode Pemblokiran yang Digunakan:</b></p>
                                <ul style="margin: 10px 0; padding-left: 20px;">
                                    <li>iptables DROP rule (INPUT & FORWARD)</li>
                                    <li>Blackhole Routing</li>
                                </ul>
                            </div>

                            <div style="margin-top: 25px; background-color: #e8f5e9; border: 1px solid #c8e6c9; padding: 15px 20px; border-radius: 8px;">
                                <p style="margin: 0; font-size: 15px; color: #2e7d32;">
                                    ✅ Akses telah <b>berhasil diblokir</b> dan jaringan RSUD Tapan terlindungi dari ancaman ini.
                                </p>
                            </div>

                            <div style="margin-top: 30px; text-align: center; color: #555555; font-size: 14px;">
                                <p style="margin: 0;"><i>— Sistem Hybrid AI Detector</i></p>
                                <p style="margin: 0;"><i>Rumah Sakit Umum Daerah Tapan</i></p>
                            </div>
                        </div>

                    </body>
                    </html>
                    """

                    for target in wa_targets:
                        Message(target, wa_block_message).send_via_whatsapp()
                        print(Fore.GREEN + f"# Notifikasi Pemblokiran WhatsApp Dikirim" + Style.RESET_ALL)

                    for receiver in email_receivers:
                        Message(receiver, block_email_body, "🔒 Notifikasi Pemblokiran Akses Pengguna - RSUD Tapan").send_via_email()
                        print(Fore.YELLOW + f"# Notifikasi Pemblokiran Email Dikirim" + Style.RESET_ALL)

                    print(Fore.CYAN + f"# Notifikasi pemblokiran berhasil dikirim." + Style.RESET_ALL)

                except Exception as e:
                    print(Fore.RED + f"# Gagal mengirim notifikasi pemblokiran: {e}" + Style.RESET_ALL)

                self._block_ip(src_ip)
                final_label = "DDOS-Attack"

            now = time.time()
            if final_label == "DDOS-Attack":
                self.last_attack_time[key] = now
            else:
                if now - self.last_attack_time[key] < self.attack_hold_time:
                    final_label = "DDOS-Attack"

            label_color = Fore.GREEN if final_label == "Normal" else Fore.RED
            dt_str = datetime.fromtimestamp(window_end).strftime("%Y-%m-%d %H:%M:%S")

            prob_percent = ml_prob * 100

            if prob_percent.is_integer():
                prob_str = f"{int(prob_percent)}%"
            else:
                prob_str = f"{prob_percent:.2f}%"

            print(
                f"{dt_str:<20} | {src_ip:<15} | {protocol:<9} | {avg_len:>14} | "
                f"{pkt_rate:>12.0f} | {count:>13} | {ttl:>6} | {label_color}{final_label:<12}{Style.RESET_ALL} | {prob_str:>12}"
            )
            
            sys.stdout.flush()

    def _get_proto_name(self, proto_num):
        proto_map = {1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP", 88: "EIGRP"}
        return proto_map.get(proto_num, f"PROTO_{proto_num}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Hybrid DDoS Detector")
    parser.add_argument('--interface', '-i', default='enp0s8', help='Network interface to listen on')
    parser.add_argument('--model', '-m', default='model/result/model/ddos_model.pkl', help='Path to ML model')
    parser.add_argument('--no-iptables', action='store_true', help='Disable iptables blocking')
    parser.add_argument('--no-blackhole', action='store_true', help='Disable blackhole route')
    parser.add_argument('--port', '-p', type=int, default=6001, help='Unblock server port')
    args = parser.parse_args()

    interface = args.interface
    model_path = args.model
    iptables_enabled = not args.no_iptables
    blackhole_enabled = not args.no_blackhole

    detector = HybridDDoSDetector(interface=interface, model_path=model_path,
                                  iptables_enabled=iptables_enabled, blackhole_enabled=blackhole_enabled)
    detector.run()