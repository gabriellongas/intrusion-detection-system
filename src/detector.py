import socket
import os
import struct
import time
from collections import defaultdict

# Configuração do limite de pacotes SYN por segundo
SYN_THRESHOLD = 10
BLOCK_DURATION = 60  # duração do bloqueio em segundos
LOG_FILE = "syn_flood_log.txt"

# Dicionário para rastrear os IPs e a contagem de pacotes SYN
syn_counts = defaultdict(list)
blocked_ips = {}

# Função para logar eventos
def log_event(event):
    with open(LOG_FILE, "a") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {event}\n")
    print(event)

# Função para bloquear um IP
def block_ip(ip):
    os.system(f"iptables -A INPUT -s {ip} -j DROP")
    blocked_ips[ip] = time.time()
    log_event(f"IP {ip} bloqueado devido a ataque SYN flood.")

# Função para verificar e desbloquear IPs após a duração do bloqueio
def unblock_ips():
    current_time = time.time()
    for ip in list(blocked_ips.keys()):
        if current_time - blocked_ips[ip] > BLOCK_DURATION:
            os.system(f"iptables -D INPUT -s {ip} -j DROP")
            del blocked_ips[ip]
            log_event(f"IP {ip} desbloqueado.")

# Função principal de captura de pacotes
def packet_sniffer():
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sniffer.bind(("0.0.0.0", 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Captura de pacotes
    while True:
        # Verificar IPs bloqueados periodicamente
        unblock_ips()

        # Receber pacote
        raw_packet = sniffer.recvfrom(65565)[0]
        ip_header = raw_packet[0:20]
        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
        
        # Verificar se é IPv4
        version_ihl = iph[0]
        version = version_ihl >> 4
        if version != 4:
            continue
        
        # Extrair IP de origem
        src_ip = socket.inet_ntoa(iph[8])
        
        # Verificar protocolo TCP
        protocol = iph[6]
        if protocol == 6:  # TCP
            tcp_header = raw_packet[20:40]
            tcph = struct.unpack("!HHLLBBHHH", tcp_header)
            flags = tcph[5]

            # Verificar flag SYN
            syn_flag = flags & 0x02
            if syn_flag:
                current_time = time.time()
                syn_counts[src_ip].append(current_time)

                # Limpar registros antigos
                syn_counts[src_ip] = [
                    t for t in syn_counts[src_ip] if current_time - t <= 1
                ]

                # Verificar se excedeu o limite
                if len(syn_counts[src_ip]) > SYN_THRESHOLD:
                    if src_ip not in blocked_ips:
                        block_ip(src_ip)

if __name__ == "__main__":
    log_event("Iniciando monitoramento de SYN flood.")
    try:
        packet_sniffer()
    except KeyboardInterrupt:
        log_event("Encerrando monitoramento de SYN flood.")
