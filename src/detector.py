import socket
import os
import struct
import time
from collections import defaultdict

# Configuração do limite de pacotes SYN por segundo
SYN_THRESHOLD = 10  # Número de pacotes SYN por segundo para caracterizar um ataque
BLOCK_DURATION = 60  # Duração do bloqueio em segundos para IPs maliciosos
LOG_FILE = "syn_flood_log.txt"  # Arquivo de log para registrar eventos de ataque

# Dicionário para rastrear IPs e contagem de pacotes SYN
syn_counts = defaultdict(list)  # Guarda o tempo dos pacotes SYN por IP
blocked_ips = {}  # Guarda os IPs bloqueados e o tempo de bloqueio

# Função para registrar eventos no log
def log_event(event):
    # Escreve o evento com data e hora no arquivo de log
    with open(LOG_FILE, "a") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {event}\n")
    print(event)  # Também imprime o evento no console

# Função para bloquear um IP utilizando iptables
def block_ip(ip):
    # Comando para adicionar uma regra de bloqueio ao IP
    os.system(f"iptables -A INPUT -s {ip} -j DROP")
    blocked_ips[ip] = time.time()  # Armazena o tempo em que o IP foi bloqueado
    log_event(f"IP {ip} bloqueado devido a ataque SYN flood.")  # Registra no log

# Função para verificar e desbloquear IPs após o tempo de bloqueio
def unblock_ips():
    current_time = time.time()
    # Itera sobre os IPs bloqueados
    for ip in list(blocked_ips.keys()):
        # Desbloqueia o IP se o tempo de bloqueio expirou
        if current_time - blocked_ips[ip] > BLOCK_DURATION:
            os.system(f"iptables -D INPUT -s {ip} -j DROP")
            del blocked_ips[ip]  # Remove o IP da lista de bloqueio
            log_event(f"IP {ip} desbloqueado.")  # Registra no log

# Função principal de captura de pacotes
def packet_sniffer():
    # Cria um socket raw para capturar pacotes TCP (IPPROTO_TCP)
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sniffer.bind(("0.0.0.0", 0))  # Liga o socket a todos os endereços disponíveis
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)  # Inclui cabeçalho IP

    # Loop para capturar pacotes de rede continuamente
    while True:
        unblock_ips()  # Verifica e desbloqueia IPs se necessário

        # Recebe um pacote da rede
        raw_packet = sniffer.recvfrom(65565)[0]
        
        # Processa o cabeçalho IP do pacote
        ip_header = raw_packet[0:20]
        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
        
        # Verifica se o pacote é IPv4
        version_ihl = iph[0]
        version = version_ihl >> 4
        if version != 4:
            continue  # Ignora pacotes que não sejam IPv4
        
        # Extrai o IP de origem do cabeçalho IP
        src_ip = socket.inet_ntoa(iph[8])
        
        # Verifica se o pacote é TCP
        protocol = iph[6]
        if protocol == 6:  # Protocolo TCP
            # Processa o cabeçalho TCP
            tcp_header = raw_packet[20:40]
            tcph = struct.unpack("!HHLLBBHHH", tcp_header)
            flags = tcph[5]

            # Verifica se o pacote tem a flag SYN ativada
            syn_flag = flags & 0x02
            if syn_flag:
                current_time = time.time()
                # Armazena o tempo de recebimento do pacote SYN para o IP de origem
                syn_counts[src_ip].append(current_time)

                # Remove pacotes antigos da contagem para o cálculo de taxa
                syn_counts[src_ip] = [
                    t for t in syn_counts[src_ip] if current_time - t <= 1
                ]

                # Verifica se o número de pacotes SYN por segundo ultrapassa o limite
                if len(syn_counts[src_ip]) > SYN_THRESHOLD:
                    # Bloqueia o IP se ele ainda não estiver bloqueado
                    if src_ip not in blocked_ips:
                        block_ip(src_ip)

# Inicializa o sniffer e começa a monitorar SYN floods
if __name__ == "__main__":
    log_event("Iniciando monitoramento de SYN flood.")  # Log de início
    try:
        packet_sniffer()  # Executa a função principal
    except KeyboardInterrupt:
        log_event("Encerrando monitoramento de SYN flood.")  # Log de encerramento