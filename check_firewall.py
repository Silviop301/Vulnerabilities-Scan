import subprocess
import platform
import re # Importa módulo de expressões regulares

def check_firewall_status():
    """
    Verifica o status do firewall no Windows e Linux (ufw).
    Análise do Windows adaptada para formato PT-BR com 'Ligado'/'Desligado'.

    Retorna:
        dict: Dicionário com 'os', 'status', 'details', 'error'.
    """
    system = platform.system()
    result_data = {"os": system, "status": "Unknown", "details": "", "error": None}

    if system == "Windows":
        try:
            command = "chcp 65001 > nul && netsh advfirewall show allprofiles"
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, check=True,
                encoding='utf-8', errors='ignore'
            )
            output = result.stdout
            result_data["details"] = output

            # --- Lógica de Análise Adaptada ---
            # Regex para encontrar o estado (Ligado/Desligado) de cada perfil PT-BR
            # Procura pelo nome do perfil e depois pela linha exata de Estado
            pattern = re.compile(
                # Procura "Perfil <nome> Configurações:" (incluindo "do Domínio")
                r"^\s*Perfil\s+(?:do\s+)?(?P<profile_name>Domínio|Particular|Público)\s+Configurações:.*?$"
                # Procura linha que começa com "Estado" seguido de espaços e "Ligado" ou "Desligado"
                r".*?^\s*Estado\s+(?P<profile_state>Ligado|Desligado)\s*$",
                re.MULTILINE | re.IGNORECASE | re.DOTALL
            )

            matches = pattern.finditer(output)
            profile_states = [] # Lista para guardar 'ON' ou 'OFF' para cada perfil encontrado
            profiles_matched = set() # Para evitar contar o mesmo perfil mais de uma vez

            for match in matches:
                profile_name = match.group('profile_name').capitalize() # Ex: Domínio, Particular, Público
                state = match.group('profile_state').upper() # Ex: LIGADO, DESLIGADO

                # Garante que processamos cada tipo de perfil apenas uma vez
                if profile_name not in profiles_matched:
                    profiles_matched.add(profile_name)
                    if state == "LIGADO":
                        profile_states.append("ON")
                    elif state == "DESLIGADO":
                        profile_states.append("OFF")

            num_profiles = len(profile_states)
            num_on = profile_states.count("ON")

            # Determina o status com base nos perfis encontrados
            # Idealmente, esperamos encontrar 3 perfis
            if num_profiles >= 3: # Considera sucesso se encontrar pelo menos 3
                if num_on == num_profiles:
                    result_data["status"] = "Enabled" # Todos Ligados
                elif num_on == 0:
                    result_data["status"] = "Disabled (All Profiles)" # Todos Desligados
                else:
                    result_data["status"] = "Partially Enabled" # Mistura de Ligado/Desligado
            elif num_profiles > 0 : # Encontrou menos de 3, mas pelo menos 1
                 # Poderia ser mais específico, mas vamos classificar como parcial/indeterminado
                 result_data["status"] = f"Partially Enabled ({num_on}/{num_profiles} profiles ON)"
            else:
                # Não encontrou NENHUM perfil correspondente ao padrão PT-BR
                result_data["status"] = "Unknown (Parsing Failed)"
            # --- Fim da Lógica de Análise ---

        except subprocess.CalledProcessError as e:
            result_data["status"] = "Error"
            result_data["error"] = f"Erro ao executar netsh (Código: {e.returncode})"
            result_data["details"] = e.stderr if e.stderr else e.stdout
        except Exception as e:
            result_data["status"] = "Error"
            result_data["error"] = f"Erro inesperado: {e}"

    elif system == "Linux":
        # (Lógica para Linux como antes)
        try:
            # ... (código do Linux permanece o mesmo) ...
             try:
                result = subprocess.run(
                    ["ufw", "status", "verbose"], capture_output=True, text=True, check=True,
                    encoding='utf-8', errors='ignore'
                )
             except subprocess.CalledProcessError:
                 result = subprocess.run(
                    ["ufw", "status"], capture_output=True, text=True, check=True,
                    encoding='utf-8', errors='ignore'
                )
             output = result.stdout
             result_data["details"] = output
             if "Status: active" in output:
                 result_data["status"] = "Enabled"
             elif "Status: inactive" in output:
                 result_data["status"] = "Disabled"
             else:
                 result_data["status"] = "Unknown"
        except FileNotFoundError:
            result_data["status"] = "Not Installed"
            result_data["error"] = "'ufw' command not found. Try: sudo apt install ufw"
        except subprocess.CalledProcessError as e:
             result_data["status"] = "Error"
             result_data["error"] = f"Erro ao executar ufw (Código: {e.returncode})"
             result_data["details"] = e.stderr if e.stderr else e.stdout
        except Exception as e:
            result_data["status"] = "Error"
            result_data["error"] = f"Erro inesperado: {e}"
    else:
        result_data["status"] = "Unsupported OS"
        result_data["os"] = "Unsupported"

    return result_data

if __name__ == "__main__":
    # Bloco de teste
    firewall_info = check_firewall_status()
    print("--- Verificação de Firewall ---")
    print(f"Sistema Operacional: {firewall_info['os']}")
    print(f"Status Determinado: {firewall_info['status']}")
    if firewall_info['error']:
        print(f"Erro: {firewall_info['error']}")
    print("\nDetalhes Completos:")
    print(firewall_info['details'] if firewall_info['details'] else "Nenhum detalhe disponível.")