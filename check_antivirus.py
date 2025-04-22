import subprocess
import platform
import json # Para analisar a saída do PowerShell em formato JSON

def parse_product_state(state_code):
    """
    Analisa o código de estado do produto antivírus do WMI/PowerShell.
    Retorna um dicionário com 'enabled' (bool) e 'updated' (bool).
    Baseado em documentação comum (pode haver variações).
    """
    try:
        code = int(state_code)
        # Verifica o bit para 'ativado' (geralmente 0x00004000 ou parte do segundo byte)
        # O bit exato pode variar, mas estados comuns ativados (ex: 266240, 397312)
        # têm o segundo byte (hex) como 10 ou 90. Estados desativados como 00.
        # Vamos simplificar checando se o código > 262144 (base desativado) e não é um estado desativado conhecido.
        # Bit de ativação: (code & 0x00004000) != 0 -> 16384
        # Bit de desatualizado: (code & 0x00000010) != 0 -> 16

        # Abordagem mais simples baseada em valores comuns:
        # Valores ON/UP-TO-DATE: 266240 (0x41000), 397312 (0x61000)
        # Valores ON/OUT-OF-DATE: 266256 (0x41010), 397568 (0x61110)
        # Valores OFF/UP-TO-DATE: 262144 (0x40000), 393216 (0x60000)
        # Valores OFF/OUT-OF-DATE: 262160 (0x40010), 393472 (0x60110)

        is_enabled = state_code in [266240, 397312, 266256, 397568] # Se está em algum estado 'ON'
        is_up_to_date = state_code in [266240, 397312, 262144, 393216] # Se está em algum estado 'UP-TO-DATE'

        # Alternativa por bits (mais técnica, pode ser mais frágil)
        # is_enabled_bit = (code & 16384) != 0 # 0x4000
        # is_up_to_date_bit = (code & 16) == 0 # 0x10 (bit set = desatualizado)

        return {"enabled": is_enabled, "updated": is_up_to_date}

    except ValueError:
        return {"enabled": None, "updated": None} # Estado inválido

def check_antivirus_status_windows():
    """
    Verifica o status do Antivírus no Windows via PowerShell e WMI SecurityCenter2.
    """
    result_data = {"os": "Windows", "status": "Not Found", "products": [], "error": None}
    try:
        # Comando PowerShell para obter produtos AntiVirus e converter para JSON
        # Seleciona apenas nome e estado para simplificar
        command = "powershell -Command \"Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName, productState | ConvertTo-Json\""

        process = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            check=True,
            encoding='utf-8', # Tentar UTF-8 primeiro
            errors='ignore'
        )
        output = process.stdout.strip()

        # Tenta analisar o JSON
        av_products_json = json.loads(output)

        # Pode retornar um único objeto ou uma lista
        if not isinstance(av_products_json, list):
            av_products_json = [av_products_json]

        if not av_products_json: # Se a lista está vazia
             result_data["status"] = "Not Found"
             result_data["error"] = "Nenhum produto antivírus registrado na Central de Segurança."
             return result_data

        products = []
        overall_status = "Disabled" # Assume desativado até encontrar um ativo
        found_enabled = False

        for product in av_products_json:
            name = product.get('displayName', 'Nome Desconhecido')
            state_code = product.get('productState')
            parsed_state = parse_product_state(state_code)

            products.append({
                "name": name,
                "state_code": state_code,
                "enabled": parsed_state["enabled"],
                "updated": parsed_state["updated"]
            })

            if parsed_state["enabled"]:
                found_enabled = True
                # Se encontrarmos um ativo E atualizado, o status geral é bom
                if parsed_state["updated"]:
                    overall_status = "Enabled and Updated"
                # Se está ativo mas desatualizado, o status geral é de atenção
                elif overall_status != "Enabled and Updated": # Não sobrescreve se já achou um atualizado
                    overall_status = "Enabled but Outdated"

        result_data["products"] = products
        if not found_enabled and len(products) > 0:
             result_data["status"] = "Disabled" # Encontrou produtos, mas nenhum ativo
        elif not found_enabled and len(products) == 0:
              result_data["status"] = "Not Found" # Nenhum produto encontrado
        else:
             result_data["status"] = overall_status # Usa o status determinado (Enabled/Updated, Enabled/Outdated)


    except FileNotFoundError:
        result_data["status"] = "Error"
        result_data["error"] = "Comando 'powershell' não encontrado."
    except subprocess.CalledProcessError as e:
        result_data["status"] = "Error"
        result_data["error"] = f"Erro ao executar PowerShell (Código: {e.returncode}). A Central de Segurança pode não estar acessível ou o comando falhou."
        result_data["details"] = e.stderr if e.stderr else e.stdout
    except json.JSONDecodeError:
         result_data["status"] = "Error"
         result_data["error"] = "Falha ao analisar a saída JSON do PowerShell. Saída inesperada."
         result_data["details"] = output # Guarda a saída bruta para depuração
    except Exception as e:
        result_data["status"] = "Error"
        result_data["error"] = f"Erro inesperado ao verificar Antivírus: {e}"

    return result_data


def check_antivirus_status():
    """
    Verifica o status do Antivírus no sistema operacional atual.
    Atualmente, implementado apenas para Windows.
    """
    system = platform.system()
    if system == "Windows":
        return check_antivirus_status_windows()
    else:
        # Poderia adicionar verificações para Linux (ex: ClamAV) ou macOS aqui
        return {"os": system, "status": "Not Implemented", "products": [], "error": "Verificação não implementada para este SO."}

if __name__ == "__main__":
    av_info = check_antivirus_status()
    print("--- Verificação de Antivírus ---")
    print(f"Sistema Operacional: {av_info.get('os')}")
    print(f"Status Geral: {av_info.get('status')}")
    if av_info.get('error'):
        print(f"Erro/Aviso: {av_info.get('error')}")
    if av_info.get('products'):
        print("\nProdutos Detectados:")
        for p in av_info['products']:
            status_str = f"Enabled={p['enabled']}, Updated={p['updated']}"
            print(f"  - {p['name']} (Estado: {p['state_code']} -> {status_str})")
    if av_info.get('details'):
        print("\nDetalhes do Erro/Saída:")
        print(av_info['details'])