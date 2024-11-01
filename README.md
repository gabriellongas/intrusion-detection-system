
# Detecção de Ataques SYN Flood com Python

Este projeto implementa uma ferramenta de detecção e mitigação de ataques SYN flood usando Python. Ele captura pacotes de rede, identifica padrões de ataque por meio da frequência de pacotes SYN e bloqueia automaticamente IPs suspeitos, registrando todos os eventos em um arquivo de log.

## Requisitos

- Python 3.x
- Permissões de superusuário (necessário para capturar pacotes e manipular `iptables`)
- Bibliotecas padrão do Python (`socket`, `os`, `struct`, `time`, `collections`)

## Funcionalidades

1. **Captura de Pacotes de Rede**:
   - Utiliza um *socket raw* para capturar pacotes IPv4.
   - Filtra pacotes TCP e verifica a flag SYN para identificar tentativas de conexão.

2. **Detecção de SYN Flood**:
   - Monitora a frequência de pacotes SYN recebidos de um mesmo IP em um intervalo de tempo.
   - Define um limiar de pacotes SYN por segundo (`SYN_THRESHOLD`) para caracterizar um ataque.

3. **Bloqueio de IP e Registro em Log**:
   - Utiliza o comando `iptables` para bloquear o IP de origem que exceder o limiar de pacotes SYN.
   - Registra em um arquivo de log a detecção do ataque e a ação de bloqueio realizada.
   - Desbloqueia automaticamente os IPs após um período (`BLOCK_DURATION`).

## Instalação

1. Clone o repositório:

   ```bash
   git clone https://github.com/seu-usuario/detector-syn-flood.git
   cd detector-syn-flood
   ```

2. Execute o script como superusuário:

   ```bash
   sudo python3 detector.py
   ```

> **Nota:** Esse script exige permissões de superusuário para criar o socket raw e manipular `iptables`.

## Parâmetros Configuráveis

No início do código, você pode ajustar as seguintes variáveis para adaptar o comportamento do detector:

- `SYN_THRESHOLD`: Número de pacotes SYN por segundo para caracterizar um ataque. O padrão é `10`.
- `BLOCK_DURATION`: Duração do bloqueio (em segundos) para IPs que excedem o limite de pacotes SYN. O padrão é `60` segundos.
- `LOG_FILE`: Caminho e nome do arquivo de log para registrar eventos.

## Arquivo de Log

O arquivo de log (`syn_flood_log.txt` por padrão) registra cada evento de ataque e bloqueio, incluindo:

- IP de origem do ataque
- Ação realizada (bloqueio ou desbloqueio do IP)
- Data e hora de cada evento

## Estrutura do Código

- `log_event(event)`: Função para registrar eventos no log.
- `block_ip(ip)`: Bloqueia um IP utilizando `iptables`.
- `unblock_ips()`: Desbloqueia IPs bloqueados após `BLOCK_DURATION`.
- `packet_sniffer()`: Função principal que captura e analisa pacotes de rede para detectar ataques SYN flood.

## Como Funciona

1. O script captura todos os pacotes IPv4 e verifica se são pacotes TCP com a flag SYN.
2. Se um IP exceder o limite de pacotes SYN (`SYN_THRESHOLD`), ele é bloqueado temporariamente usando `iptables`.
3. O script registra todas as ações no arquivo de log e desbloqueia IPs após `BLOCK_DURATION`.

## Exemplo de Uso

Ao iniciar o script, ele irá monitorar a rede para pacotes SYN e, ao detectar um ataque, o IP ofensivo será bloqueado e o evento registrado em log.

```plaintext
2024-10-31 10:45:12 - IP 192.168.1.15 bloqueado devido a ataque SYN flood.
2024-10-31 10:46:12 - IP 192.168.1.15 desbloqueado.
```

## Contribuição

Contribuições são bem-vindas! Sinta-se à vontade para abrir *issues* ou enviar *pull requests* com melhorias, correções de bugs ou novos recursos.

## Aviso Legal

Este código é um exemplo educacional e deve ser usado com responsabilidade. Não execute scripts de bloqueio de IP em redes que você não possui permissão para monitorar ou modificar.
