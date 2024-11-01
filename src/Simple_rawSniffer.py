import socket
import struct

# Crie um socket raw Ethernet para capturar pacotes
raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

print("Aguardando pacotes Ethernet...")

while True:
    # Capture um pacote Ethernet
    packet, addr = raw_socket.recvfrom(65535)

    # Analise o cabeçalho Ethernet
    eth_header = packet[:14]
    eth_payload = packet[14:]

    eth_dest_mac, eth_src_mac, eth_type = struct.unpack("!6s6sH", eth_header)

    print("Cabeçalho Ethernet:")
    print(f"MAC de destino: {':'.join('%02x' % b for b in eth_dest_mac)}")
    print(f"MAC de origem: {':'.join('%02x' % b for b in eth_src_mac)}")
    print(f"Tipo: {hex(eth_type)}")
    print("--------------------")

    # Verificar se o pacote é IPv4 (EtherType 0x0800)
    if eth_type == 0x0800:
        ip_header = eth_payload[:20]
        ip_version, ip_tos, ip_length, ip_id, ip_flags, ip_ttl, ip_protocol, ip_checksum, ip_src, ip_dest = struct.unpack("!BBHHHBBH4s4s", ip_header)

        print("Cabeçalho IP:")
        print(f"Endereço de origem: {socket.inet_ntoa(ip_src)}")
        print(f"Endereço de destino: {socket.inet_ntoa(ip_dest)}")
        print(f"Protocolo: {ip_protocol}")
        print("--------------------")

        # Verificar se o protocolo é TCP (protocolo 6) ou UDP (protocolo 17)
        if ip_protocol == 6 or ip_protocol == 17:
            if ip_protocol == 6:
                tcp_header = eth_payload[20:40]
                src_port, dest_port, sequence, ack_num, offset_flags = struct.unpack("!HHIIB", tcp_header)
                offset = (offset_flags >> 4) * 4

                print("Cabeçalho TCP:")
                print(f"Porta de origem: {src_port}")
                print(f"Porta de destino: {dest_port}")
                print(f"Número de Sequência: {sequence}")
                print(f"Número de Ack: {ack_num}")
                print("--------------------")

    print("====================")