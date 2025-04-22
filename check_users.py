# check_users.py
import subprocess
import platform
import json # Para analisar JSON do PowerShell
import os
import re # Ainda pode ser útil para analisar grupos depois

# Função parse_net_user_output_ptbr não é mais necessária se Get-LocalUser funcionar

def check_local_users_windows_powershell():
    """Obtém usuários locais e detalhes básicos via PowerShell Get-LocalUser."""
    users_data = {"os": "Windows", "status": "Unknown", "users": [], "error": None}
    try:
        # Comando PowerShell para obter usuários locais e detalhes chave em formato JSON
        # Inclui Name, Enabled, PasswordExpires, SID (para referência futura)
        # O parâmetro -Compress tenta criar um JSON mais compacto
        command = "powershell -NoProfile -ExecutionPolicy Bypass -Command \"Get-LocalUser | Where-Object {$_.Name -ne 'Guest' -and $_.Name -ne 'DefaultAccount' -and $_.Name -ne 'WDAGUtilityAccount'} | Select-Object Name, SID, Enabled, PasswordExpires, PasswordLastSet | ConvertTo-Json -Compress\""

        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, check=True,
            encoding='utf-8', errors='ignore', timeout=20 # Timeout maior para PowerShell
        )
        output = result.stdout.strip()

        # Se a saída for vazia, ou não for JSON válido, retorna erro
        if not output or (not output.startswith('[') and not output.startswith('{')):
             users_data['status'] = "Not Found"
             users_data['error'] = "Get-LocalUser não retornou dados válidos (saída vazia ou não JSON)."
             users_data['details'] = output # Guarda saída para depuração
             return users_data

        users_json = json.loads(output)

        # Garante que temos uma lista
        if not isinstance(users_json, list):
            users_json = [users_json]

        detailed_users = []
        for u_data in users_json:
            username = u_data.get('Name')
            if not username: continue # Pula se não tiver nome

            # Detalhes diretos do Get-LocalUser
            is_active = u_data.get('Enabled', '?') # True/False/?
            # PasswordExpires é uma data ou None. Se for None, nunca expira.
            password_never_expires = u_data.get('PasswordExpires') is None

            # Verificação de Admin ainda é um desafio sem 'net localgroup'
            # Vamos tentar uma verificação básica pelo SID (SID S-1-5-*-500 é o admin padrão)
            # Ou poderíamos tentar rodar 'net localgroup administrators' separadamente se tiver permissão
            is_admin_check = False # Assume não admin por padrão
            sid = u_data.get('SID', {}).get('Value', '') # SID vem como objeto no JSON
            if sid and sid.endswith('-500'): # SID do Administrador padrão termina com -500
                 is_admin_check = True
            # Nota: esta verificação só pega a conta 'Administrador' interna, não outros admins.

            user_info = {
                'username': username,
                'active': is_active,
                'password_expires': not password_never_expires, # Convertemos para nossa lógica (True=Expira)
                'is_admin': is_admin_check, # Verificação básica pelo SID
                'risk': 'Low', # Recalcular risco
                'error': None
            }

            # Recalcula risco
            if user_info['active'] == False: user_info['risk'] = 'Info'
            elif user_info['password_expires'] == False: user_info['risk'] = 'Medium'
            if user_info['is_admin'] == True: user_info['risk'] = 'High'

            detailed_users.append(user_info)

        users_data['users'] = detailed_users
        users_data['status'] = "Success"
        # Adiciona aviso se não conseguiu verificar admin de forma robusta
        users_data['error'] = "Verificação de Admin limitada (apenas SID -500). Detalhes completos podem requerer privilégios."


    except FileNotFoundError:
        users_data['status'] = "Error"
        users_data['error'] = "Comando 'powershell' não encontrado."
    except subprocess.CalledProcessError as e:
        # Verifica se o erro é porque Get-LocalUser não existe (Windows mais antigo?)
        stderr_lower = e.stderr.lower() if e.stderr else ""
        if "não é reconhecido como nome de cmdlet" in stderr_lower or "is not recognized as the name of a cmdlet" in stderr_lower:
             users_data['status'] = "Error"
             users_data['error'] = "Comando 'Get-LocalUser' não disponível neste sistema."
             # Poderíamos tentar fallback para 'net user' aqui, mas vamos manter simples por ora
        else:
             users_data['status'] = "Error"
             users_data['error'] = f"Erro ao executar Get-LocalUser (Código: {e.returncode})."
             users_data['details'] = stderr_lower
    except json.JSONDecodeError:
         users_data['status'] = "Error"
         users_data['error'] = "Falha ao analisar a saída JSON do Get-LocalUser."
         users_data['details'] = output
    except Exception as e:
        users_data['status'] = "Error"
        users_data['error'] = f"Erro inesperado via PowerShell: {e}"

    return users_data


# Função principal agora chama a versão PowerShell
def check_local_users():
    """Verifica contas de usuário locais."""
    system = platform.system()
    if system == "Windows":
        return check_local_users_windows_powershell()
    else:
        return {"os": system, "status": "Not Implemented", "users": [], "error": "Verificação não implementada para este SO."}

# Bloco __main__ como antes, para teste direto do check_users.py
if __name__ == "__main__":
    user_info = check_local_users()
    print("--- Verificação de Contas de Usuário Locais (via PowerShell) ---")
    print(f"Sistema Operacional: {user_info.get('os')}")
    print(f"Status: {user_info.get('status')}")
    if user_info.get('error'):
        print(f"Erro/Aviso: {user_info.get('error')}")
    if user_info.get('details'): # Mostra detalhes de erro se houver
        print(f"Detalhes do Erro: {user_info.get('details')}")

    if user_info.get('users'):
        print("\nUsuários Encontrados e Analisados:")
        for u in user_info['users']:
            risk_map = {'Low': '', 'Medium': '[MÉDIO]', 'High': '[ALTO]', 'Info': '[INFO]'}
            risk_str = risk_map.get(u.get('risk', 'Low'), '')
            details = f"Ativo={u.get('active', '?')}, Senha Expira={u.get('password_expires', '?')}, Admin(SID)?={u.get('is_admin', '?')}"
            if u.get('error'):
                details += f", Erro='{u['error']}'"
            print(f"  - {u.get('username', 'N/A')} {risk_str}: ({details})")