import os
import signal
import sys
from scapy.all import *

# Função para lidar com o sinal SIGINT (Ctrl+C)
def signal_handler(sig, frame):
    print('\nCaptura de redes interrompida. Salvando informações em log...')
    # Escrever informações em log
    with open('rede.log', 'a') as log_file:
        for ssid, bssid, signal_strength in ssid_list:
            log_file.write(f"SSID: {ssid}, BSSID: {bssid}, Força do sinal: {signal_strength}\n")
    print('Informações salvas em log. Saindo...')
    sys.exit(0)

# Função para filtrar pacotes de Beacon
def handle_packet(pkt):
    if pkt.haslayer(Dot11Beacon):
        ssid = pkt[Dot11Elt].info.decode()
        bssid = pkt[Dot11].addr3
        signal_strength = -(256 - ord(pkt.notdecoded[-4:-3]))
        ssid_list.append((ssid, bssid, signal_strength))
        print(f"SSID: {ssid}, BSSID: {bssid}, Força do sinal: {signal_strength} dBm")

# Inicializar lista para armazenar informações de rede
ssid_list = []

# Registrar o manipulador de sinal SIGINT (Ctrl+C)
signal.signal(signal.SIGINT, signal_handler)

# Detectar a interface de rede disponível
interfaces = os.listdir('/sys/class/net/')
interface = None
for iface in interfaces:
    if iface != 'lo' and not iface.startswith('docker'):
        interface = iface
        break

if interface:
    print(f"Interface de rede detectada: {interface}")
else:
    print("Nenhuma interface de rede disponível. Usando periféricos do dispositivo.")

# Configurar interface de rede para monitoramento
if interface:
    os.system(f"ifconfig {interface} promisc")
else:
    print("Não foi possível detectar uma interface de rede. Usando periféricos do dispositivo.")

# Iniciar a captura de pacotes
print("Capturando redes ao redor... Pressione Ctrl+C para interromper.")
sniff(iface=interface, prn=handle_packet)
