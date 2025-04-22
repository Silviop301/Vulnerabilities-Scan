# check_encryption.py
import subprocess
import platform
import json
import ctypes
import os

def is_admin():
    """Verifica se o script está rodando com privilégios de Admin no Windows."""
    try:
        return os.getuid() == 0
    except AttributeError:
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except AttributeError:
             print("[AVISO] Não foi possível verificar privilégios de Admin via ctypes.")
             return False

def check_bitlocker_status_windows_powershell(drive="C"):
    """Verifica o status do BitLocker via PowerShell Get-BitLockerVolume."""
    encryption_data = {"os": "Windows", "drive": drive, "status": "Unknown", "protection": "Unknown", "error": None}
    drive_letter = drive.strip(':')

    if not is_admin():
        encryption_data["status"] = "Error"
        encryption_data["error"] = "Requer privilégios de Administrador para Get-BitLockerVolume."
        return encryption_data

    try:
        command = f"powershell -NoProfile -ExecutionPolicy Bypass -Command \"Get-BitLockerVolume -MountPoint '{drive_letter}:' | Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionPercentage | ConvertTo-Json -Compress\""
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, check=True,
            encoding='utf-8', errors='ignore', timeout=20
        )
        output = result.stdout.strip()

        # ***** AJUSTE AQUI: Trata saída vazia/não JSON como 'Não Habilitado' *****
        if not output or not output.startswith('{'):
             encryption_data['status'] = "Not Enabled/Not Found"
             encryption_data['protection'] = "Off" # Se não existe, não está protegido
             encryption_data['error'] = "BitLocker não ativo ou não encontrado para este volume via Get-BitLockerVolume."
             return encryption_data
        # ***** FIM DO AJUSTE *****

        volume_info = json.loads(output)

        mount_point = volume_info.get("MountPoint", "?")
        volume_status = volume_info.get("VolumeStatus", "Unknown").lower()
        protection_status = volume_info.get("ProtectionStatus", "Unknown").lower()

        encryption_data["drive"] = mount_point.strip(':')

        if "fullyencrypted" in volume_status: encryption_data["status"] = "Encrypted"
        elif "fullydecrypted" in volume_status: encryption_data["status"] = "Decrypted"
        elif "encrypting" in volume_status: encryption_data["status"] = "Encrypting"
        elif "decrypting" in volume_status: encryption_data["status"] = "Decrypting"
        else: encryption_data["status"] = f"Unknown ({volume_status})"

        if "on" in protection_status: encryption_data["protection"] = "On"
        elif "off" in protection_status: encryption_data["protection"] = "Off"
        else: encryption_data["protection"] = "Unknown"

    # (Tratamento de outros erros como antes)
    except FileNotFoundError:
        encryption_data["status"] = "Error"; encryption_data["error"] = "'powershell' não encontrado."
    except subprocess.CalledProcessError as e:
        stderr_lower = e.stderr.lower() if e.stderr else ""
        if "não é reconhecido como nome de cmdlet" in stderr_lower or "is not recognized as the name of a cmdlet" in stderr_lower:
            encryption_data["status"] = "Error"; encryption_data["error"] = "'Get-BitLockerVolume' não disponível."
        elif "não foi possível localizar uma unidade" in stderr_lower or "cannot find a mounted volume" in stderr_lower or "o dispositivo não está pronto" in stderr_lower:
             encryption_data["status"] = "Not Found/Ready"; encryption_data["protection"] = "Off"; encryption_data["error"] = f"Volume {drive_letter}: não encontrado/pronto."
        elif "privilégios" in stderr_lower or "privileges" in stderr_lower:
             encryption_data["status"] = "Error"; encryption_data["error"] = "Requer privilégios de Administrador."
        else:
            encryption_data["status"] = "Error"; encryption_data["error"] = f"Erro Get-BitLockerVolume (Cod:{e.returncode})."; encryption_data["details"] = stderr_lower or e.stdout
    except json.JSONDecodeError:
         encryption_data['status'] = "Error"; encryption_data['error'] = "Falha ao analisar JSON (saída inesperada)."
         encryption_data['details'] = output
    except Exception as e:
        encryption_data["status"] = "Error"; encryption_data["error"] = f"Erro inesperado (BitLocker PS): {e}"

    return encryption_data

# Função principal e Bloco __main__ como antes
def check_disk_encryption():
    system = platform.system()
    if system == "Windows":
        return check_bitlocker_status_windows_powershell(drive="C")
    else:
        return {"os": system, "drive": "N/A", "status": "Not Implemented", "protection":"Unknown", "error": "Verificação não implementada para este SO."}

if __name__ == "__main__":
    if platform.system() == "Windows" and not is_admin():
         print("[FATAL] Requer privilégios de Administrador.")
    else:
        encryption_info = check_disk_encryption()
        print("--- Verificação de Criptografia de Disco (BitLocker via PS) ---")
        print(f"OS: {encryption_info.get('os')}, Drive: {encryption_info.get('drive')}:")
        print(f"Status Criptografia: {encryption_info.get('status')}")
        print(f"Status Proteção: {encryption_info.get('protection')}")
        if encryption_info.get('error'): print(f"Erro/Aviso: {encryption_info.get('error')}")
        if encryption_info.get('details'): print(f"Detalhes Erro: {encryption_info.get('details')}")