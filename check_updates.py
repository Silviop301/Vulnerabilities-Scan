import subprocess
import platform
import sys

def check_pending_updates_windows():
    """ Tenta verificar atualizações pendentes no Windows usando COM API. """
    try:
        import win32com.client
        update_session = win32com.client.Dispatch("Microsoft.Update.Session")
        update_searcher = update_session.CreateUpdateSearcher()
        # Procura por atualizações de software não instaladas
        search_result = update_searcher.Search("IsInstalled=0 and Type='Software'")

        count = search_result.Updates.Count
        if count == 0:
            return {"status": "No Updates", "count": 0, "details": "Nenhuma atualização de software pendente encontrada.", "error": None}
        else:
            updates_list = [f"- {update.Title}" for update in search_result.Updates]
            details = f"{count} atualização(ões) pendente(s) encontrada(s):\n" + "\n".join(updates_list[:10]) # Lista as 10 primeiras
            if count > 10:
                details += f"\n... e mais {count - 10}."
            return {"status": "Updates Pending", "count": count, "details": details, "error": None}

    except ImportError:
        return {"status": "Error", "count": 0, "details": "", "error": "Módulo 'pywin32' não instalado. Execute: pip install pywin32"}
    except Exception as e:
        # Tenta fallback para o PowerShell (menos ideal, requer PSWindowsUpdate)
        # Nota: Este comando AINDA pode ser arriscado ou não funcionar sem o módulo
        print("⚠️ Falha ao usar API COM do Windows Update. Tentando fallback com PowerShell (requer módulo PSWindowsUpdate)...")
        try:
            # Comando para LISTAR, não instalar. Precisa do módulo PSWindowsUpdate.
            command = "powershell -Command \"Import-Module PSWindowsUpdate; Get-WUList -MicrosoftUpdate | Format-Table -AutoSize\""
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=120)

            if result.returncode == 0 and result.stdout and "ComputerName" in result.stdout: # Verifica se a saída parece válida
                 output_lines = result.stdout.strip().split('\n')
                 # Conta linhas que não são cabeçalho ou vazias (estimativa)
                 update_count = sum(1 for line in output_lines if line.strip() and not line.startswith("ComputerName") and not line.startswith("------------"))
                 if update_count > 0:
                      status = "Updates Pending"
                      details = f"Verificação via PowerShell indica atualizações pendentes ({update_count} estimadas):\n{result.stdout}"
                 else:
                      status = "No Updates"
                      details = "Verificação via PowerShell não encontrou atualizações pendentes."
                 return {"status": status, "count": update_count, "details": details, "error": "Usado método PowerShell como fallback."}
            else:
                error_msg = f"Falha no fallback PowerShell. Código: {result.returncode}. Erro: {result.stderr}"
                return {"status": "Error", "count": 0, "details": result.stdout, "error": error_msg}

        except Exception as ps_e:
            return {"status": "Error", "count": 0, "details": "", "error": f"Falha ao usar API COM e erro no fallback PowerShell: {ps_e}"}


def check_pending_updates_linux():
    """ Verifica atualizações pendentes no Linux usando 'apt'. """
    try:
        # Roda 'apt update' silenciosamente primeiro para atualizar a lista de pacotes
        subprocess.run(["sudo", "apt", "update", "-qq"], check=True, capture_output=True)

        # Agora lista os pacotes atualizáveis
        result = subprocess.run(
            ["apt", "list", "--upgradable"],
            capture_output=True,
            text=True,
            check=True,
            encoding='utf-8',
            errors='ignore'
        )
        output = result.stdout.strip()
        if output and "Listing..." in output:
             lines = output.split('\n')
             # Remove a linha "Listing..." e conta o restante
             upgradable_packages = [line for line in lines if not line.startswith("Listing...")]
             count = len(upgradable_packages)
             if count > 0:
                 details = f"{count} pacote(s) atualizável(is) encontrado(s):\n" + "\n".join(upgradable_packages[:10]) # Lista os 10 primeiros
                 if count > 10:
                    details += f"\n... e mais {count - 10}."
                 return {"status": "Updates Pending", "count": count, "details": details, "error": None}
             else:
                 # Se 'apt list --upgradable' rodou mas não listou pacotes
                 return {"status": "No Updates", "count": 0, "details": "Nenhum pacote atualizável encontrado após 'apt update'.", "error": None}
        else:
             # Saída inesperada ou vazia
             return {"status": "No Updates", "count": 0, "details": "Nenhum pacote atualizável encontrado.", "error": None}

    except FileNotFoundError:
        return {"status": "Error", "count": 0, "details": "", "error": "'apt' command not found. This check is for Debian/Ubuntu based systems."}
    except subprocess.CalledProcessError as e:
        # 'apt update' pode requerer 'sudo' e falhar se não tiver permissão
        error_msg = f"Erro ao executar apt. Verifique permissões (sudo) ou erro do apt: {e}"
        if e.stderr:
            error_msg += f"\nStderr: {e.stderr.strip()}"
        return {"status": "Error", "count": 0, "details": e.stdout if e.stdout else "", "error": error_msg}
    except Exception as e:
        return {"status": "Error", "count": 0, "details": "", "error": f"Erro inesperado: {e}"}


def check_pending_updates():
    """
    Verifica atualizações pendentes no sistema operacional atual.

    Retorna:
        dict: Um dicionário contendo:
            'os' (str): Sistema operacional detectado.
            'status' (str): 'Updates Pending', 'No Updates', 'Error', 'Unsupported OS'.
            'count' (int): Número de atualizações encontradas (0 se nenhuma ou erro).
            'details' (str): Lista de atualizações ou mensagem de status.
            'error' (str | None): Mensagem de erro, se houver.
    """
    system = platform.system()
    result_data = {"os": system, "status": "Unknown", "count": 0, "details": "", "error": None}

    if system == "Windows":
        # Verifica se estamos rodando como Admin, necessário para COM/PowerShell avançado
        # try:
        #    is_admin = (os.getuid() == 0) # Linux/Mac
        # except AttributeError:
        #    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0 # Windows
        # if not is_admin:
        #    result_data.update({"status": "Error", "error": "Requer privilégios de administrador para verificar atualizações no Windows."})
        #    return result_data
        # Comentado acima - verificar admin pode ser complexo/indesejado. Deixa tentar e falhar.

        print("🕒 Verificando atualizações pendentes no Windows (pode levar um momento)...")
        win_result = check_pending_updates_windows()
        result_data.update(win_result) # Mescla o resultado da função específica do Windows

    elif system == "Linux":
        print("🕒 Verificando atualizações pendentes no Linux (Debian/Ubuntu)...")
        # Verifica se está rodando como root, pois 'apt update' geralmente precisa
        # import os
        # if os.geteuid() != 0:
        #    print("⚠️ Aviso: 'apt update' pode precisar de 'sudo'. Tentando mesmo assim...")
        # Comentado - melhor deixar o erro do subprocesso indicar falta de permissão

        linux_result = check_pending_updates_linux()
        result_data.update(linux_result) # Mescla o resultado da função específica do Linux
    else:
        result_data["status"] = "Unsupported OS"
        result_data["os"] = "Unsupported"

    return result_data

if __name__ == "__main__":
    update_info = check_pending_updates()
    print("\n--- Verificação de Atualizações ---")
    print(f"Sistema Operacional: {update_info['os']}")
    print(f"Status: {update_info['status']}")
    print(f"Contagem: {update_info['count']}")
    if update_info['error']:
        print(f"Erro/Aviso: {update_info['error']}")
    print("\nDetalhes:")
    print(update_info['details'] if update_info['details'] else "Nenhum detalhe disponível.")

    # Adiciona dependência pywin32 se estiver no Windows
    if platform.system() == "Windows":
        print("\nNota: A verificação no Windows requer 'pywin32'. Instale com: pip install pywin32")