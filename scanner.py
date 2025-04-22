import sys
import platform
import argparse
import time
import os
import ctypes # Para verificar admin no windows

# Importa as funções dos outros módulos
from scan_ports import scan_ports
from check_firewall import check_firewall_status
from check_updates import check_pending_updates
from check_antivirus import check_antivirus_status
from check_users import check_local_users
from check_encryption import check_disk_encryption, is_admin # Adicionado is_admin daqui também
from report_generator import generate_pdf_report

def main():
    start_time = time.time()
    # Verifica se é admin logo no início (importante para Bitlocker e talvez usuários)
    admin_privileges = is_admin() if platform.system() == "Windows" else False

    print("\n==============================================")
    print("🛡️   ZenithScan - Scanner de Segurança Local  🛡️")
    print("==============================================")
    if platform.system() == "Windows":
        print(f"[INFO] Executando como Administrador: {'Sim' if admin_privileges else 'Não'}")
        if not admin_privileges:
             print("[AVISO] Algumas verificações (ex: BitLocker, detalhes de usuários) podem requerer execução como Administrador.")


    # --- Argumentos ---
    parser = argparse.ArgumentParser(description="Realiza verificações de segurança locais e gera um relatório.")
    parser.add_argument("--host", default="127.0.0.1", help="Host para escanear portas (padrão: 127.0.0.1)")
    parser.add_argument("--start-port", type=int, default=1, help="Porta inicial para scan (padrão: 1)")
    parser.add_argument("--end-port", type=int, default=1024, help="Porta final para scan (padrão: 1024)")
    parser.add_argument("--threads", type=int, default=100, help="Threads para scan de portas (padrão: 100)")
    parser.add_argument("--timeout", type=float, default=0.5, help="Timeout de conexão por porta em segundos (padrão: 0.5)")
    parser.add_argument("--output", default="relatorio_zenithscan.pdf", help="Nome do arquivo PDF de saída (padrão: relatorio_zenithscan.pdf)")
    parser.add_argument("--skip-updates", action="store_true", help="Pular verificação de atualizações")
    parser.add_argument("--skip-antivirus", action="store_true", help="Pular verificação de antivírus")
    parser.add_argument("--skip-users", action="store_true", help="Pular verificação de contas de usuário")
    parser.add_argument("--skip-encryption", action="store_true", help="Pular verificação de criptografia de disco")

    args = parser.parse_args()

    # --- Validações e Infos Iniciais ---
    if not (0 < args.start_port <= 65535 and 0 < args.end_port <= 65535 and args.start_port <= args.end_port): print("Erro: Range de portas inválido."); sys.exit(1)
    if args.threads <= 0: print("Erro: Número de threads deve ser positivo."); sys.exit(1)
    if args.timeout <= 0: print("Erro: Timeout deve ser positivo."); sys.exit(1)

    print(f"\nIniciando varredura em {time.strftime('%d/%m/%Y %H:%M:%S')}")
    print(f"Sistema Operacional: {platform.system()} {platform.release()}")
    if platform.system() == "Linux" and os.geteuid() != 0: print("[AVISO] No Linux, 'sudo' pode ser necessário para updates.")
    elif platform.system() == "Windows":
         try: import win32com.client; print("[INFO] Módulo 'pywin32' encontrado.")
         except ImportError: print("[AVISO] Módulo 'pywin32' não encontrado (necessário para updates). Instale: pip install pywin32")
    print("-" * 46)


    # --- 1. Scan de Portas ---
    print("\n1. 🔓 Escaneando portas abertas...")
    open_ports = []
    try:
        open_ports = scan_ports(args.host, args.start_port, args.end_port, max_threads=args.threads, timeout=args.timeout)
    except Exception as e:
        print(f"\n❌ Erro inesperado durante o scan de portas: {e}")
    print("-" * 46)


    # --- 2. Verificação de Firewall ---
    print("\n2. 🔥 Verificando status do firewall...")
    firewall_data = {}
    try:
        firewall_data = check_firewall_status()
        print(f"   Resultado: OS={firewall_data.get('os', 'N/A')}, Status={firewall_data.get('status', 'N/A')}")
        if firewall_data.get('error'): print(f"   ⚠️ Aviso/Erro: {firewall_data['error']}")
    except Exception as e:
        print(f"\n❌ Erro inesperado durante a verificação do firewall: {e}")
        firewall_data = {"os": platform.system(), "status": "Error", "error": f"Falha na chamada: {e}"}
    print("-" * 46)


    # --- 3. Verificação de Atualizações ---
    update_data = {}
    if not args.skip_updates:
        print("\n3. 🕒 Verificando atualizações pendentes...")
        try:
            update_data = check_pending_updates()
            print(f"   Resultado: OS={update_data.get('os', 'N/A')}, Status={update_data.get('status', 'N/A')}, Contagem={update_data.get('count', 0)}")
            if update_data.get('error'): print(f"   ⚠️ Aviso/Erro: {update_data['error']}")
        except Exception as e:
            print(f"\n❌ Erro inesperado durante a verificação de atualizações: {e}")
            update_data = {"os": platform.system(), "status": "Error", "error": f"Falha na chamada: {e}"}
    else:
        print("\n3. 🕒 Verificação de atualizações pulada (--skip-updates).")
        update_data = {"os": platform.system(), "status": "Skipped", "error": "Verificação pulada pelo usuário."}
    print("-" * 46)

    # --- 4. Verificação de Antivírus ---
    av_data = {}
    if not args.skip_antivirus:
        print("\n4. 🛡️ Verificando status do antivírus...")
        try:
            av_data = check_antivirus_status()
            print(f"   Resultado: Status={av_data.get('status', 'N/A')}")
            if av_data.get('error'): print(f"   ⚠️ Aviso/Erro: {av_data['error']}")
            if av_data.get('products'):
                 for p in av_data['products']:
                     status_str = f"Ativo={format_bool(p.get('enabled'))}"
                     if p.get('enabled'): status_str += f", Atualizado={format_bool(p.get('updated'))}"
                     print(f"     - Produto: {p.get('name', 'N/A')} ({status_str})")
        except Exception as e:
            print(f"\n❌ Erro inesperado durante a verificação de antivírus: {e}")
            av_data = {"os": platform.system(), "status": "Error", "error": f"Falha na chamada: {e}"}
    else:
        print("\n4. 🛡️ Verificação de antivírus pulada (--skip-antivirus).")
        av_data = {"os": platform.system(), "status": "Skipped", "error": "Verificação pulada pelo usuário."}
    print("-" * 46)


    # --- 5. Verificação de Contas de Usuário ---
    users_data = {}
    if not args.skip_users:
        print("\n5. 👤 Verificando contas de usuário locais...")
        try:
            users_data = check_local_users()
            print(f"   Resultado: Status={users_data.get('status', 'N/A')}, Usuários Analisados={len(users_data.get('users', []))}") # Mudado texto
            if users_data.get('error'): print(f"   ⚠️ Aviso/Erro: {users_data['error']}")
            if users_data.get('users'):
                for u in users_data['users'][:5]: # Mostra resumo dos 5 primeiros
                     status_parts = []
                     if u.get('active') is not None: status_parts.append(f"Ativo={format_bool(u.get('active'))}")
                     if u.get('password_expires') is not None: status_parts.append(f"Senha Expira={format_bool(u.get('password_expires'))}")
                     if u.get('is_admin') is not None: status_parts.append(f"Admin(SID)?={format_bool(u.get('is_admin'))}")
                     error_str = f", Erro='{u.get('error')}'" if u.get('error') else ""
                     print(f"     - {u.get('username','?')} ({', '.join(status_parts)}{error_str})")
                if len(users_data['users']) > 5: print("       ...")
        except Exception as e:
            print(f"\n❌ Erro inesperado durante a verificação de usuários: {e}")
            users_data = {"os": platform.system(), "status": "Error", "error": f"Falha na chamada: {e}"}
    else:
        print("\n5. 👤 Verificação de contas de usuário pulada (--skip-users).")
        users_data = {"os": platform.system(), "status": "Skipped", "error": "Verificação pulada pelo usuário."}
    print("-" * 46)


    # --- 6. Verificação de Criptografia de Disco ---
    encryption_data = {}
    if not args.skip_encryption:
        print("\n6. 💿 Verificando criptografia de disco (BitLocker)...")
        if platform.system() == "Windows" and not admin_privileges:
             print("   [ERRO] Necessário executar como Administrador para esta verificação.")
             encryption_data = {"os": "Windows", "drive":"C", "status": "Error", "protection":"Unknown", "error": "Requer privilégios de Administrador."}
        else:
             try:
                 encryption_data = check_disk_encryption()
                 print(f"   Resultado (Drive {encryption_data.get('drive', '?')}): Status={encryption_data.get('status', 'N/A')}, Proteção={encryption_data.get('protection', 'N/A')}")
                 if encryption_data.get('error'): print(f"   ⚠️ Aviso/Erro: {encryption_data['error']}")
             except Exception as e:
                 print(f"\n❌ Erro inesperado durante a verificação de criptografia: {e}")
                 encryption_data = {"os": platform.system(), "drive":"C", "status": "Error", "protection":"Unknown", "error": f"Falha na chamada: {e}"}
    else:
        print("\n6. 💿 Verificação de criptografia pulada (--skip-encryption).")
        encryption_data = {"os": platform.system(), "drive":"C", "status": "Skipped", "protection":"Unknown", "error": "Verificação pulada pelo usuário."}
    print("-" * 46)


    # --- 7. Geração do Relatório --- (Número muda para 7)
    print("\n7. 📝 Gerando relatório em PDF...")
    try:
        # Passa todos os dados coletados
        generate_pdf_report(open_ports, firewall_data, update_data, av_data, users_data, encryption_data, args.output)
    except Exception as e:
         print(f"\n❌ Erro inesperado durante a chamada da geração do relatório: {e}")


    # --- Finalização ---
    end_time = time.time()
    print("-" * 46)
    print(f"\n✅ Verificação concluída em {end_time - start_time:.2f} segundos.")
    print("-" * 46)

    try: input("\nPressione ENTER para sair...")
    except EOFError: pass

# Adiciona a função format_bool que agora também é usada aqui no scanner
def format_bool(value):
    if value is True: return "Sim"
    if value is False: return "Não"
    return "?"

if __name__ == "__main__":
    main()