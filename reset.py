import subprocess
from routeros_api import RouterOsApiPool

MIKROTIK_ENABLED = True
MT_HOST = "10.10.18.2"
MT_USER = "apiuser"
MT_PASS = "apiuser"
MT_PORT = 8728

def clear_iptables():
    print("\n=== Membersihkan iptables ===")
    try:
        subprocess.run(["sudo", "iptables", "-F"], check=True)
        subprocess.run(["sudo", "iptables", "-X"], check=True)
        print("[OK] Semua aturan iptables berhasil dihapus.")
    except Exception as e:
        print("[ERROR] Gagal menghapus iptables:", e)

def clear_blackhole():
    print("\n=== Membersihkan blackhole route ===")
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True)

        for line in result.stdout.splitlines():
            if "blackhole" in line:
                ip_block = line.split()[1]
                subprocess.run(["sudo", "ip", "route", "del", "blackhole", ip_block], check=False)
                print(f"[DEL] Blackhole {ip_block}")

        print("[OK] Semua blackhole IP dibersihkan.")
    except Exception as e:
        print("[ERROR] Gagal menghapus blackhole:", e)

def clear_mikrotik():
    if not MIKROTIK_ENABLED:
        print("\n[MikroTik OFF] Skip")
        return
    
    print("\n=== Membersihkan blokir di MikroTik ===")
    try:
        pool = RouterOsApiPool(
            MT_HOST, username=MT_USER, password=MT_PASS,
            port=MT_PORT, plaintext_login=True
        )
        api = pool.get_api()

        al = api.get_resource("/ip/firewall/address-list")
        for item in al.get():
            if item.get("list") == "blacklist":
                al.remove(id=item["id"])
                print(f"[DEL] Address-list {item.get('address')}")

        fw = api.get_resource("/ip/firewall/filter")
        for rule in fw.get():
            rule_id = rule.get(".id")
            comment = rule.get("comment", "")

            if rule_id == "*0":
                continue
            
            if "auto-block" in comment or "blacklist" in comment:
                fw.remove(id=rule["id"])
                print(f"[DEL] Rule DROP {comment}")


        print("[OK] Semua blokir MikroTik berhasil dihapus.")

        pool.disconnect()

    except Exception as e:
        print("[ERROR] Gagal konek ke MikroTik:", e)

if __name__ == "__main__":
    print("\n============================================")
    print("   SCRIPT PEMBERSIH BLOKIR JARINGAN")
    print("   IPTABLES + BLACKHOLE + MIKROTIK")
    print("============================================\n")

    clear_iptables()
    clear_blackhole()
    clear_mikrotik()

    print("\n=== SELESAI - SEMUA BLOKIR TELAH DIBUKA ===\n")

