import socket
from concurrent.futures import ThreadPoolExecutor
import argparse
import sys # Importado para sys.exit

# Dicionário de portas comuns (pode adicionar mais se desejar)
COMMON_PORTS = {
    20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    135: "RPC", 139: "NetBIOS Session Service", 445: "Microsoft-DS (SMB)",
    1433: "MS SQL Server", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 8080: "HTTP Alt", 8443: "HTTPS Alt"
    # Outras que podem ser úteis: 1521 (Oracle), 27017 (MongoDB), 5000, 8000 (Dev Servers)
}

# Lista de portas altas comuns a serem adicionadas ao scan padrão
EXTRA_COMMON_PORTS = [1433, 3306, 3389, 5432, 5900, 8080, 8443]

def scan_port(host, port, timeout=0.5):
    """ Tenta conectar a uma porta específica. Retorna (porta, serviço) se aberta, None se fechada/erro. """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                return port, service
    except socket.timeout:
        pass
    except OSError: # Ignora erros como "Host unreachable" ou "Network unreachable" silenciosamente
        pass
    except Exception as e:
        # Log de erros inesperados pode ser útil, mas evitado aqui para não poluir a saída padrão
        # print(f"[-] Erro desconhecido na porta {port} para {host}: {e}")
        pass
    return None

def scan_ports(host="127.0.0.1", start_port=1, end_port=1024, extra_ports=None, max_threads=100, timeout=0.5):
    """
    Escaneia um range de portas e portas extras em um host usando threads.

    Retorna:
        list: Lista de tuplas (porta, serviço) para portas abertas.
    """
    if extra_ports is None:
        extra_ports = EXTRA_COMMON_PORTS # Usa a lista padrão

    # Cria a lista completa de portas a escanear
    ports_to_scan_set = set(range(start_port, end_port + 1))
    ports_to_scan_set.update(p for p in extra_ports if 0 < p <= 65535)
    ports_to_scan = sorted(list(ports_to_scan_set)) # Ordena a lista final

    total_ports_count = len(ports_to_scan)
    port_range_str = f"{start_port}-{end_port}" if start_port<=end_port else "N/A"
    extra_count = len(ports_to_scan_set.intersection(extra_ports))
    print(f"🔍 Escaneando {host} ({total_ports_count} portas: range {port_range_str} + {extra_count} extras definidas)...")

    open_ports = []
    ports_scanned = 0

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(scan_port, host, port, timeout): port
            for port in ports_to_scan
        }

        for future in futures:
            result = future.result()
            ports_scanned += 1
            if result:
                open_ports.append(result)
                port, service = result
                print(f"[+] Porta aberta encontrada: {port:<5} ({service})")

            # Barra de progresso simples (opcional, pode deixar mais lento)
            # progress = int(50 * ports_scanned / total_ports_count)
            # print(f"\r   Progresso: [{'=' * progress}{' ' * (50 - progress)}] {ports_scanned}/{total_ports_count}", end="")

    # print("\r" + " " * 70 + "\r", end="") # Limpa a linha de progresso

    if not open_ports:
        print("\nNenhuma porta aberta comum encontrada nos ranges escaneados.")
    else:
        open_ports.sort(key=lambda x: x[0])
        print(f"\n✅ Scan concluído. Total de portas abertas encontradas: {len(open_ports)}")

    return open_ports

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Escaneador de Portas TCP Simples.")
    parser.add_argument("--host", default="127.0.0.1", help="Host a ser escaneado (padrão: 127.0.0.1)")
    parser.add_argument("-s", "--start", type=int, default=1, help="Porta inicial (padrão: 1)")
    parser.add_argument("-e", "--end", type=int, default=1024, help="Porta final (padrão: 1024)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Número máximo de threads (padrão: 100)")
    parser.add_argument("-T", "--timeout", type=float, default=0.5, help="Timeout de conexão por porta em segundos (padrão: 0.5)")
    # Poderia adicionar argumento para passar portas extras: --extra-ports 8080,3306 ...

    args = parser.parse_args()

    if not (0 < args.start <= 65535 and 0 < args.end <= 65535 and args.start <= args.end):
        print("Erro: Range de portas inválido (1-65535).")
        sys.exit(1)
    if args.threads <= 0:
        print("Erro: Número de threads deve ser positivo.")
        sys.exit(1)
    if args.timeout <= 0:
        print("Erro: Timeout deve ser positivo.")
        sys.exit(1)

    # Usa a lista padrão EXTRA_COMMON_PORTS definida no início
    found_ports = scan_ports(args.host, args.start, args.end, max_threads=args.threads, timeout=args.timeout)