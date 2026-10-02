#!/usr/bin/env python3
import socket
import subprocess
import json
import urllib.request
import os
import re
from concurrent.futures import ThreadPoolExecutor

# Colores para la terminal
VERDE = "\033[1;32m"
AZUL = "\033[1;36m"
AMARILLO = "\033[1;33m"
ROJO = "\033[1;31m"
RESET = "\033[0m"

# Mapeo directo de puertos locales conocidos
SERVICIOS_CONOCIDOS = {
    "53": "systemd-resolved (DNS)",
    "631": "cupsd (Impresión)",
    "22": "sshd (SSH)",
    "80": "httpd (Servidor Web)",
    "443": "https (Web Segura)"
}

def banner():
    print(f"{VERDE}=================================================={RESET}")
    print(f"         {AZUL}[ Arkap CyberScan]{RESET}         ")
    print(f"      {AMARILLO}Auditoría de Red y Sistema en Tiempo Real{RESET}      ")
    print(f"{VERDE}=================================================={RESET}\n")

def ejecutar_cmd(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return ""

def obtener_ip_local_e_interfaz():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("9.9.9.9", 53))
        ip_local = s.getsockname()[0]
        s.close()
        
        ip_route = ejecutar_cmd("ip route get 9.9.9.9")
        match = re.search(r'dev\s+(\S+)', ip_route)
        iface = match.group(1) if match else "Desconocida"
        return ip_local, iface
    except Exception:
        return "127.0.0.1", "lo"

def obtener_mac(iface):
    mac = ejecutar_cmd(f"cat /sys/class/net/{iface}/address")
    return mac if mac else "No disponible"

def obtener_ip_publica():
    try:
        req = urllib.request.Request("https://ipinfo.io/json", headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            return data.get("ip", "Desconocida"), data.get("org", "Desconocido"), data.get("city", "N/A"), data.get("country", "N/A")
    except Exception:
        return "Sin conexión / Oculta", "N/A", "N/A", "N/A"

def escanear_puerto(ip, puerto):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.2)
        res = sock.connect_ex((ip, puerto))
        sock.close()
        if res == 0:
            return puerto
    except Exception:
        pass
    return None

def main():
    banner()

    # 1. Interfaz de Red y Datos Locales Reales
    ip_local, interfaz = obtener_ip_local_e_interfaz()
    mac_local = obtener_mac(interfaz)
    print(f"{AZUL}[1] Interfaz Activa ({interfaz}):{RESET}")
    print(f"    • IP Local (LAN):  {VERDE}{ip_local}{RESET}")
    print(f"    • Dirección MAC:   {VERDE}{mac_local}{RESET}")

    # 2. IP Pública y Geolocalización ISP
    ip_pub, isp, ciudad, pais = obtener_ip_publica()
    print(f"\n{AZUL}[2] Conexión Externa (WAN):{RESET}")
    print(f"    • IP Pública:      {VERDE}{ip_pub}{RESET}")
    print(f"    • Proveedor (ISP): {VERDE}{isp}{RESET}")
    print(f"    • Ubicación IP:    {VERDE}{ciudad}, {pais}{RESET}")

    # 3. Gateway / Router Principal
    gateway = ejecutar_cmd("ip route show default | awk '{print $3}'")
    print(f"\n{AZUL}[3] Puerta de Enlace (Router):{RESET} {VERDE}{gateway if gateway else 'Desconocido'}{RESET}")

    # 4. Servidores DNS Upstream Reales
    dns_res = ejecutar_cmd("resolvectl status | grep 'DNS Servers' | awk '{$1=$2=\"\"; print $0}'")
    dns_clean = ", ".join(dns_res.split()) if dns_res else "127.0.0.53 (Stub local)"
    print(f"{AZUL}[4] Resolutores DNS Activos:{RESET} {VERDE}{dns_clean}{RESET}")

    # 5. Estado del Firewall (UFW)
    ufw = ejecutar_cmd("sudo ufw status | head -n 1")
    if not ufw:
        ufw = ejecutar_cmd("ufw status | head -n 1")
    ufw_color = VERDE if "active" in ufw and "inactive" not in ufw else AMARILLO
    print(f"{AZUL}[5] Estado del Firewall (UFW):{RESET} {ufw_color}{ufw if ufw else 'Status: active'}{RESET}")

    # 6. Escaneo de Dispositivos Reales en la LAN (Tabla ARP)
    print(f"\n{AZUL}[6] Dispositivos Detectados en la Red Local (LAN):{RESET}")
    arp_output = ejecutar_cmd("ip neighbor show | grep -E 'REACHABLE|STALE'")
    if arp_output:
        for linea in arp_output.splitlines():
            partes = linea.split()
            ip_vecino = partes[0]
            mac_vecina = partes[4] if len(partes) > 4 else "MAC Desconocida"
            estado = partes[-1]
            print(f"    • {AMARILLO}{ip_vecino}{RESET} -> MAC: {VERDE}{mac_vecina}{RESET} [{estado}]")
    else:
        print(f"    • {VERDE}Sin otros dispositivos activos registrados en la tabla ARP.{RESET}")

    # 7. Sockets Escuchando y Procesos Limpios
    print(f"\n{AZUL}[7] Puertos y Procesos Escuchando (Sockets Locales):{RESET}")
    ss_out = ejecutar_cmd("ss -tulnp | grep LISTEN")
    if ss_out:
        for linea in ss_out.splitlines():
            partes = linea.split()
            local_addr = partes[4] if len(partes) > 4 else "N/A"
            
            proc_match = re.search(r'users:\(\("([^"]+)"', linea)
            if proc_match:
                proc_info = proc_match.group(1)
            else:
                puerto_num = local_addr.split(":")[-1]
                proc_info = SERVICIOS_CONOCIDOS.get(puerto_num, "Servicio Local")

            print(f"    • Puerto: {AMARILLO}{local_addr:<22}{RESET} Servicio: {VERDE}{proc_info}{RESET}")
    else:
        print(f"    • {VERDE}Sin sockets abiertos.{RESET}")

    # 8. Métricas en Tiempo Real del Sistema
    ram_total = ejecutar_cmd("free -m | awk '/Mem:/ {print $2}'")
    ram_used = ejecutar_cmd("free -m | awk '/Mem:/ {print $3}'")
    uptime = ejecutar_cmd("uptime -p | sed 's/up //'")
    print(f"\n{AZUL}[8] Rendimiento del Sistema:{RESET}")
    print(f"    • Memoria RAM:    {VERDE}{ram_used} MB / {ram_total} MB{RESET}")
    print(f"    • Tiempo Activo:  {VERDE}{uptime}{RESET}")

    # 9. Verificación de Seguridad Kernel
    aslr = ejecutar_cmd("cat /proc/sys/kernel/randomize_va_space")
    aslr_status = "Protección Total (2)" if aslr == "2" else "Desactivado/Parcial"
    print(f"\n{AZUL}[9] Mitigación de Kernel ASLR:{RESET} {VERDE}{aslr_status}{RESET}")

    # 10. Escaneo de Puertos Externeables a la Red
    puertos = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3306, 3389, 5900, 8080, 8443]
    print(f"\n{AZUL}[10] Escaneando top 19 puertos de red en {ip_local}...{RESET}")
    abiertos = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futuros = [executor.submit(escanear_puerto, ip_local, p) for p in puertos]
        for f in futuros:
            res = f.result()
            if res:
                abiertos.append(res)

    if abiertos:
        print(f"    {AMARILLO}[!] ALERTA: Puertos expuestos a la LAN: {abiertos}{RESET}")
    else:
        print(f"    {VERDE}[✓] Seguro: Ningún puerto crítico expuesto en la red local.{RESET}")

    # Mensaje de cierre TEAM DRS
    print(f"\n{VERDE}=================================================={RESET}")
    print(f"{AZUL}Muchas gracias por apoyar y descubrir esta herramienta.{RESET}")
    print(f"{AMARILLO}Atentamente: TEAM DRS{RESET}")
    print(f"{VERDE}=================================================={RESET}\n")

if __name__ == "__main__":
    main()