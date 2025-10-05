import netifaces
import ipaddress
from scapy.all import ARP, Ether, srp, sr1, IP, ICMP
from colorama import init, Fore, Style
import logging

# Ignorar mensajes de advertencia de Scapy en IPv6
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Inicializar colorama para que funcione en todas las terminales
init(autoreset=True)

def enacabezado():
    """Imprime el encabezado del programa."""
    print(Fore.CYAN + Style.BRIGHT + "========================================")
    print(Fore.CYAN + Style.BRIGHT + "   PYLAN - Network Scanner @nachouc     ")
    print(Fore.CYAN + Style.BRIGHT + "========================================")
    print()

def obtener_interfaz_activa():
    """
    Detecta automáticamente la primera interfaz de red activa (que no sea loopback)
    y devuelve su dirección IP y máscara de red.
    """
    interfaces = netifaces.interfaces()
    for interfaz in interfaces:
        # Ignorar la interfaz de loopback
        if interfaz == 'lo':
            continue
        try:
            direcciones = netifaces.ifaddresses(interfaz)
            if netifaces.AF_INET in direcciones:
                info = direcciones[netifaces.AF_INET][0]
                direccion_ip = info.get('addr')
                mascara_red = info.get('netmask')
                if direccion_ip and mascara_red:
                    print(Fore.GREEN + f"[+] Interfaz activa detectada: {interfaz}")
                    print(Fore.GREEN + f"[+] Dirección IP: {direccion_ip}/{mascara_red}")
                    return direccion_ip, mascara_red
        except Exception as e:
            print(Fore.RED + f"[-] Error al procesar la interfaz {interfaz}: {e}")
    return None, None

def identificar_so(ip):
    """
    Intenta identificar el sistema operativo de un host mediante el TTL de un paquete ICMP.
    """
    try:
        paquete_icmp = IP(dst=ip) / ICMP()
        respuesta = sr1(paquete_icmp, timeout=1, verbose=0)

        if respuesta is None:
            return "SO Desconocido (no responde a ping)"
        
        ttl = respuesta.ttl
        if 60 <= ttl <= 70:
            return "Linux/Unix/macOS"
        elif 120 <= ttl <= 130:
            return "Windows"
        else:
            return f"Otro (TTL: {ttl})"
            
    except Exception:
        return "SO Desconocido (error en ping)"

def escanear_red(rango_ip):
    """
    Escanea el rango de red especificado usando ARP para encontrar hosts activos
    e intenta identificar su sistema operativo.
    """
    print(Fore.YELLOW + f"\n[*] Escaneando la red {rango_ip}...")
    
    # Paquete ARP para descubrir hosts en la red
    arp = ARP(pdst=rango_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff") # Broadcast
    paquete_arp = ether / arp

    # Enviar el paquete y recibir respuestas
    resultado = srp(paquete_arp, timeout=3, verbose=0)[0]

    hosts_activos = []
    for enviado, recibido in resultado:
        hosts_activos.append({'ip': recibido.psrc, 'mac': recibido.hwsrc})

    if not hosts_activos:
        print(Fore.RED + "[-] No se encontraron hosts activos en la red.")
        return

    print(Fore.GREEN + f"\n[+] Se encontraron {len(hosts_activos)} hosts activos. Identificando SO...")
    print(Fore.CYAN + Style.BRIGHT + f"{'IP':<18} {'MAC':<20} {'Sistema Operativo (Estimado)':<30}")
    print(Fore.CYAN + Style.BRIGHT + "-"*68)

    # Identificar SO para cada host y mostrar resultados
    for host in sorted(hosts_activos, key=lambda x: ipaddress.IPv4Address(x['ip'])):
        so_estimado = identificar_so(host['ip'])
        print(f"{host['ip']:<18} {host['mac']:<20} {so_estimado:<30}")

if __name__ == "__main__":
    enacabezado()
    
    # 1. Obtener la IP y máscara de la interfaz activa
    direccion_ip_local, mascara_red = obtener_interfaz_activa()
    if not direccion_ip_local:
        print(Fore.RED + "[-] No se pudo encontrar una interfaz de red activa con dirección IP.")
        exit(1)

    # 2. Calcular el rango de la red a partir de la IP y la máscara
    try:
        interfaz_red = ipaddress.IPv4Interface(f'{direccion_ip_local}/{mascara_red}')
        red = interfaz_red.network
        rango_a_escanear = str(red.with_prefixlen)
    except Exception as e:
        print(Fore.RED + f"[-] Error al calcular el rango de la red: {e}")
        exit(1)

    # 3. Escanear la red calculada
    escanear_red(rango_a_escanear)