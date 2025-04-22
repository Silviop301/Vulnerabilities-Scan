from fpdf import FPDF
import os
import sys
from datetime import datetime
import webbrowser
import string
import platform

# --- Constantes ---
SUGGESTION_FIREWALL = "[source: 2] Sugestão: Se o firewall estiver ativo, habilite logs..."
SUGGESTION_UPDATES = "[source: 3] Sugestão: Mantenha o sistema operacional atualizado..."
SUGGESTION_ANTIVIRUS = "[source: 4] Sugestão: Garanta que seu antivírus esteja sempre ativo..."
SUGGESTION_USERS = "[source: 5] Sugestão: Revise contas de usuário. Desative contas inativas..."
SUGGESTION_ENCRYPTION = "[source: 6] Sugestão: Criptografia de disco (BitLocker) protege seus dados..."
COLOR_BLACK = (0, 0, 0)
COLOR_GREEN = (0, 128, 0)
COLOR_ORANGE = (255, 165, 0)
COLOR_RED = (200, 0, 0)
COLOR_GRAY = (128, 128, 128)

# --- Função Auxiliar para Caminhos (CORRIGIDA) ---
def resource_path(relative_path):
    """ Obtem caminho absoluto para recurso, funciona em dev e no PyInstaller """
    try:
        # PyInstaller cria pasta temporária e guarda caminho em _MEIPASS
        base_path = sys._MEIPASS
        print(f"[DEBUG] Executando via PyInstaller, base_path: {base_path}") # DEBUG
    except Exception:
        # _MEIPASS não definido, rodando em ambiente Python normal
        base_path = os.path.dirname(os.path.abspath(__file__))
        print(f"[DEBUG] Executando via Python normal, base_path: {base_path}") # DEBUG

    path = os.path.join(base_path, relative_path)
    print(f"[DEBUG] Caminho final para {relative_path}: {path}") # DEBUG
    return path

# --- Constantes de Fonte (MOVIDAS PARA DEPOIS da função resource_path) ---
FONT_NORMAL_PATH = resource_path("DejaVuSans.ttf")
FONT_BOLD_PATH = resource_path("DejaVuSans-Bold.ttf")

def filter_basic(text):
    if not isinstance(text, str):
        text = str(text)
    printable = set(string.ascii_letters + string.digits + string.punctuation + ' ')
    filtered = ''.join(filter(lambda x: x in printable or ord(x) >= 128, text))
    filtered = filtered.replace('\r', '').replace('\b', '')
    return filtered

def format_bool(value):
    if value is True:
        return "Sim"
    if value is False:
        return "Não"
    return "?"

# Assinatura da função como antes
def generate_pdf_report(open_ports, firewall_data, update_data, av_data, users_data, encryption_data, output_path="relatorio_zenithscan.pdf"):
    pdf = FPDF(orientation='P', unit='mm', format='A4')
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # --- Configuração da Fonte ---
    fonts_loaded = False
    force_helvetica = True # LEMBRETE: Mude para False se quiser TENTAR usar DejaVu
    current_font = "Helvetica"
    try:
        if force_helvetica:
            print("✅ Usando fonte padrão Helvetica (compatibilidade).")
            pdf.set_font("Helvetica", size=12)
        elif os.path.exists(FONT_NORMAL_PATH) and os.path.exists(FONT_BOLD_PATH):
            print(f"ℹ️ Tentando carregar fontes DejaVu de caminhos resolvidos:")
            print(f"   Normal: {FONT_NORMAL_PATH}") # Debug path
            print(f"   Bold: {FONT_BOLD_PATH}") # Debug path
            pdf.add_font("DejaVu", "", FONT_NORMAL_PATH, uni=True)
            pdf.add_font("DejaVu", "B", FONT_BOLD_PATH, uni=True)
            pdf.set_font("DejaVu", size=12)
            fonts_loaded = True
            current_font = "DejaVu"
            print(f"✅ Fontes DejaVu (Normal/Bold) carregadas com sucesso!")
        else:
            print(f"⚠️ Aviso: Arquivos de fonte DejaVu não encontrados. Usando Helvetica.")
            print(f"   Esperado Normal: {FONT_NORMAL_PATH}") # Debug path
            print(f"   Esperado Bold: {FONT_BOLD_PATH}") # Debug path
            pdf.set_font("Helvetica", size=12)
    except Exception as e:
        print(f"❌ Erro ao carregar/definir fontes: {e}. Usando Helvetica.")
        pdf.set_font("Helvetica", size=12)
        current_font = "Helvetica" # Garante fallback

    # Margens e Posição Y
    left_margin = 15
    right_margin = 15
    top_margin = 15
    page_width = 210
    current_y = top_margin
    line_height_normal = 5
    line_height_small = 4
    line_height_title = 6
    content_indent = 6

    # --- Cabeçalho ---
    try:
        hostname = platform.node()
        os_info = f"{platform.system()} {platform.release()}"
        pdf.set_font(current_font, style="B", size=16)
        title_width = pdf.get_string_width("Relatório de Verificação de Segurança Local")
        pdf.text(x=(page_width - title_width) / 2, y=current_y + 4, txt="Relatório de Verificação de Segurança Local")
        current_y += 10

        pdf.set_font(current_font, size=10)
        computer_line = f"Computador: {hostname} ({os_info})"
        computer_width = pdf.get_string_width(computer_line)
        pdf.text(x=(page_width - computer_width) / 2, y=current_y + 4, txt=computer_line)
        current_y += line_height_normal

        date_line = f"Gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}"
        date_width = pdf.get_string_width(date_line)
        pdf.text(x=(page_width - date_width) / 2, y=current_y + 4, txt=date_line)
        current_y += 10
    except Exception as e:
        print(f"⚠️ Erro Cabeçalho: {e}")

    # --- Seção: 1. Portas Abertas ---
    try:
        section_start_y = current_y
        pdf.set_font(current_font, style='B', size=12)
        pdf.text(x=left_margin, y=current_y, txt="1. Portas Abertas Detectadas")
        current_y += line_height_title
        pdf.set_font(current_font, size=10)

        if open_ports:
            risky_ports = {21, 23, 25, 110, 139, 445, 3389}
            for port, service in open_ports:
                service_str = service if isinstance(service, str) else str(service)
                line_text = f"- Porta {port:<5} ({filter_basic(service_str)})"
                is_risky = port in risky_ports
                try:
                    if is_risky:
                        pdf.set_text_color(*COLOR_ORANGE)
                        pdf.text(x=left_margin + content_indent, y=current_y, txt=line_text)
                        pdf.set_text_color(*COLOR_BLACK)
                    else:
                        pdf.text(x=left_margin + content_indent, y=current_y, txt=line_text)
                    current_y += line_height_normal
                except Exception as text_error:
                    if is_risky:
                        pdf.set_text_color(*COLOR_BLACK) # Reset color on error too
                    print(f"⚠️ Erro porta {port}: {text_error}")
                    continue # Skip to next port if text fails
        else:
            pdf.text(x=left_margin + content_indent, y=current_y, txt="Nenhuma porta aberta comum encontrada.")
            current_y += line_height_normal

        current_y = max(current_y, section_start_y + line_height_title + 5) # Ensure space after title
        current_y += 5 # Extra space before next section
    except Exception as e:
        print(f"⚠️ Erro Seção Portas: {e}")

    # --- Seção: 2. Status do Firewall ---
    try:
        section_start_y = current_y
        pdf.set_font(current_font, style='B', size=12)
        pdf.text(x=left_margin, y=current_y, txt=f"2. Status do Firewall ({firewall_data.get('os', 'N/A')})")
        current_y += line_height_title
        pdf.set_font(current_font, size=10)

        status_fw = firewall_data.get('status', 'Desconhecido')
        status_text = f"Status: {filter_basic(status_fw)}"

        if status_fw == "Enabled":
            color = COLOR_GREEN
        elif status_fw in ["Disabled (All Profiles)", "Partially Enabled", "Error", "Not Installed"]:
            color = COLOR_RED
        else:
            color = COLOR_BLACK

        pdf.set_text_color(*color)
        pdf.text(x=left_margin + content_indent, y=current_y, txt=status_text)
        pdf.set_text_color(*COLOR_BLACK)
        current_y += line_height_normal

        if firewall_data.get('error'):
            pdf.set_text_color(*COLOR_RED)
            pdf.text(x=left_margin + content_indent, y=current_y, txt=f"Erro: {filter_basic(firewall_data['error'])}")
            pdf.set_text_color(*COLOR_BLACK)
            current_y += line_height_normal

        pdf.set_font(current_font, size=9)
        sug_fw_lines = SUGGESTION_FIREWALL.split('\n')
        for line in sug_fw_lines:
            pdf.text(x=left_margin + content_indent, y=current_y, txt=filter_basic(line))
            current_y += line_height_small

        current_y = max(current_y, section_start_y + line_height_title + 5)
        current_y += 5
    except Exception as e:
        print(f"⚠️ Erro Seção Firewall: {e}")

    # --- Seção: 3. Atualizações Pendentes ---
    try:
        section_start_y = current_y
        pdf.set_font(current_font, style='B', size=12)
        pdf.text(x=left_margin, y=current_y, txt=f"3. Atualizações Pendentes ({update_data.get('os', 'N/A')})")
        current_y += line_height_title
        pdf.set_font(current_font, size=10)

        status_upd = update_data.get('status', 'Desconhecido')
        count_upd = update_data.get('count', 0)
        status_text = f"Status: {filter_basic(status_upd)}"

        if status_upd == "No Updates":
            color = COLOR_GREEN
        elif status_upd == "Updates Pending":
            color = COLOR_ORANGE
        elif status_upd in ["Error", "Skipped", "Unsupported OS"]:
            color = COLOR_RED
        else:
            color = COLOR_BLACK

        pdf.set_text_color(*color)
        pdf.text(x=left_margin + content_indent, y=current_y, txt=status_text)
        pdf.set_text_color(*COLOR_BLACK)
        current_y += line_height_normal

        if status_upd == "Updates Pending":
            pdf.text(x=left_margin + content_indent, y=current_y, txt=f"Contagem: {count_upd}")
            current_y += line_height_normal

        if update_data.get('error'):
            pdf.set_text_color(*COLOR_RED)
            error_text = filter_basic(update_data['error'])
            if "pywin32" in error_text:
                error_text += ". Instale: pip install pywin32"
            elif "sudo" in error_text:
                error_text += ". Verifique permissões (sudo)."
            pdf.text(x=left_margin + content_indent, y=current_y, txt=f"Erro: {error_text}")
            pdf.set_text_color(*COLOR_BLACK)
            current_y += line_height_normal
        elif update_data.get('details') and status_upd == "Updates Pending":
            pdf.set_font(current_font, size=8)
            pdf.text(x=left_margin + content_indent, y=current_y, txt="Detalhes (Updates encontrados):")
            current_y += line_height_small + 1

            details_string = update_data['details']
            if isinstance(details_string, list):
                details_lines = details_string
            elif isinstance(details_string, str):
                details_lines = details_string.strip().split('\n')
            else:
                details_lines = []

            line_count = 0
            max_lines_to_show = 8
            available_width = page_width - left_margin - right_margin - content_indent - 3
            detail_indent_x = left_margin + content_indent + 3

            for line in details_lines:
                if line_count >= max_lines_to_show:
                    pdf.text(x=detail_indent_x, y=current_y, txt="...")
                    current_y += line_height_small
                    break

                line = filter_basic(line.strip())
                line = line[2:] if line.lower().startswith("- ") else line
                if not line or line.startswith("..."):
                    continue

                max_text_width = max(1, available_width * 0.98)
                original_length = len(line)
                while pdf.get_string_width(line) > max_text_width and len(line) > 0:
                    line = line[:-1]

                if len(line) > 0:
                    if len(line) < original_length:
                        line += "..."
                    try:
                        pdf.text(x=detail_indent_x, y=current_y, txt=f"- {line}")
                        line_count += 1
                        current_y += line_height_small
                    except Exception as text_error:
                        print(f"❌❌ ERRO Linha {line_count+1} Updates: {text_error} | Texto: '{line}'")
                        continue

            if len(details_lines) > max_lines_to_show:
                pdf.set_font(current_font, size=7)
                pdf.text(x=detail_indent_x, y=current_y, txt="(Lista pode estar truncada)")
                current_y += line_height_small
            pdf.set_font(current_font, size=10) # Reset font size after details

        pdf.set_font(current_font, size=9)
        sug_upd_lines = SUGGESTION_UPDATES.split('\n')
        for line in sug_upd_lines:
            pdf.text(x=left_margin + content_indent, y=current_y, txt=filter_basic(line))
            current_y += line_height_small

        current_y = max(current_y, section_start_y + line_height_title + 5)
        current_y += 5
    except Exception as e:
        print(f"⚠️ Erro Seção Updates: {e}")


    # --- Seção: 4. Status do Antivírus ---
    try:
        section_start_y = current_y
        pdf.set_font(current_font, style='B', size=12)
        pdf.text(x=left_margin, y=current_y, txt=f"4. Status do Antivírus ({av_data.get('os', 'N/A')})")
        current_y += line_height_title
        pdf.set_font(current_font, size=10)

        status_av = av_data.get('status', 'Desconhecido')
        status_text = f"Status Geral: {filter_basic(status_av)}"

        if status_av == "Enabled and Updated":
            color = COLOR_GREEN
        elif status_av == "Enabled but Outdated":
            color = COLOR_ORANGE
        elif status_av in ["Disabled", "Error", "Not Found", "Not Implemented", "Skipped"]:
            color = COLOR_RED
        else:
            color = COLOR_BLACK

        pdf.set_text_color(*color)
        pdf.text(x=left_margin + content_indent, y=current_y, txt=status_text)
        pdf.set_text_color(*COLOR_BLACK)
        current_y += line_height_normal

        if av_data.get('error'):
            pdf.set_text_color(*COLOR_RED)
            pdf.text(x=left_margin + content_indent, y=current_y, txt=f"Erro: {filter_basic(av_data['error'])}")
            pdf.set_text_color(*COLOR_BLACK)
            current_y += line_height_normal
        elif av_data.get('products'):
            print(f"DEBUG (report_generator) - Lista AV recebida: {av_data.get('products')}") # DEBUG
            pdf.set_font(current_font, size=8)
            pdf.text(x=left_margin + content_indent, y=current_y, txt="Produtos Detectados:")
            current_y += line_height_small + 1
            detail_indent_x = left_margin + content_indent + 3

            for product_item in av_data['products']:
                p_name = filter_basic(product_item.get('name', 'N/A'))
                p_enabled = product_item.get('enabled')
                p_updated = product_item.get('updated')

                status_text_line = f"Ativo={format_bool(p_enabled)}"
                if p_enabled:
                    status_text_line += f", Atualizado={format_bool(p_updated)}"
                line_text = f"- {p_name} ({status_text_line})"

                if p_enabled == False:
                    prod_color = COLOR_ORANGE
                elif p_updated == False: # Only check updated if enabled
                    prod_color = COLOR_ORANGE
                else: # Enabled and Updated (or unknown update status)
                    prod_color = COLOR_BLACK # Default to black if status is good/unknown

                try:
                    pdf.set_text_color(*prod_color)
                    pdf.text(x=detail_indent_x, y=current_y, txt=line_text)
                    pdf.set_text_color(*COLOR_BLACK)
                    current_y += line_height_small
                except Exception as text_error:
                    pdf.set_text_color(*COLOR_BLACK) # Reset color on error
                    print(f"⚠️ Erro AV {p_name}: {text_error}")
                    continue # Skip product on error

            pdf.set_font(current_font, size=10) # Reset font size

        pdf.set_font(current_font, size=9)
        sug_av_lines = SUGGESTION_ANTIVIRUS.split('\n')
        for line in sug_av_lines:
            pdf.text(x=left_margin + content_indent, y=current_y, txt=filter_basic(line))
            current_y += line_height_small

        current_y = max(current_y, section_start_y + line_height_title + 5)
        current_y += 5
    except Exception as e:
        print(f"⚠️ Erro Seção Antivírus: {e}")

    # --- Seção: 5. Contas de Usuário Locais ---
    try:
        section_start_y = current_y
        pdf.set_font(current_font, style='B', size=12)
        pdf.text(x=left_margin, y=current_y, txt=f"5. Contas de Usuário Locais ({users_data.get('os', 'N/A')})")
        current_y += line_height_title
        pdf.set_font(current_font, size=10)

        status_usr = users_data.get('status', 'Desconhecido')
        users_list = users_data.get('users', [])

        if status_usr == "Success":
            color = COLOR_GREEN
        elif status_usr in ["Error", "Skipped", "Not Implemented"]:
            color = COLOR_RED
        else:
            color = COLOR_BLACK

        pdf.set_text_color(*color)
        pdf.text(x=left_margin + content_indent, y=current_y, txt=f"Status: {filter_basic(status_usr)}")
        pdf.set_text_color(*COLOR_BLACK)
        current_y += line_height_normal

        if status_usr == "Success":
            pdf.text(x=left_margin + content_indent, y=current_y, txt=f"Usuários Analisados: {len(users_list)}")
            current_y += line_height_normal

        if users_data.get('error'):
            error_text_usr = filter_basic(users_data['error'])
            # Gray out admin required errors, red for others
            err_color = COLOR_GRAY if "Admin" in error_text_usr else COLOR_RED
            pdf.set_text_color(*err_color)
            pdf.text(x=left_margin + content_indent, y=current_y, txt=f"Aviso: {error_text_usr}")
            pdf.set_text_color(*COLOR_BLACK)
            current_y += line_height_normal

        if users_list:
            pdf.set_font(current_font, size=8)
            pdf.text(x=left_margin + content_indent, y=current_y, txt="Detalhes:")
            current_y += line_height_small + 1
            line_count = 0
            max_lines_to_show = 7
            detail_indent_x = left_margin + content_indent + 3

            for u in users_list:
                if line_count >= max_lines_to_show:
                    pdf.text(x=detail_indent_x, y=current_y, txt="...")
                    current_y += line_height_small
                    break

                u_name = filter_basic(u.get('username','?'))
                u_active = u.get('active')
                u_expires = u.get('password_expires')
                u_admin = u.get('is_admin')
                u_error = u.get('error')
                u_risk = u.get('risk', 'Low') # Assume Low risk if not specified

                status_parts = []
                status_parts.append(f"Ativo={format_bool(u_active)}")
                status_parts.append(f"Senha Expira={format_bool(u_expires)}")
                status_parts.append(f"Admin(SID)?={format_bool(u_admin)}")
                line_text = f"- {u_name} ({', '.join(status_parts)})"
                if u_error:
                    line_text += f" [!] ({u_error})"

                # Truncate line if too long
                max_text_width = max(1, (page_width - detail_indent_x - right_margin) * 0.98)
                original_length = len(line_text)
                while pdf.get_string_width(line_text) > max_text_width and len(line_text) > 0:
                    line_text = line_text[:-1]
                if len(line_text) < original_length :
                    line_text += "..."

                # Determine color based on risk/status
                if u_error:
                    user_color = COLOR_RED
                elif u_risk == 'High':
                    user_color = COLOR_RED
                elif u_risk == 'Medium':
                    user_color = COLOR_ORANGE
                elif u_active == False:
                    user_color = COLOR_GRAY # Inactive users are gray
                else: # Low risk, active
                    user_color = COLOR_BLACK

                try:
                    pdf.set_text_color(*user_color)
                    pdf.text(x=detail_indent_x, y=current_y, txt=line_text)
                    pdf.set_text_color(*COLOR_BLACK)
                    current_y += line_height_small
                    line_count += 1
                except Exception as text_error:
                    pdf.set_text_color(*COLOR_BLACK) # Reset color on error
                    print(f"❌❌ ERRO Linha {line_count+1} Usuários: {text_error} | Texto: '{line_text}'")
                    continue # Skip user on error

            if len(users_list) > max_lines_to_show:
                pdf.set_font(current_font, size=7)
                pdf.text(x=detail_indent_x, y=current_y, txt="(Lista de usuários pode estar truncada)")
                current_y += line_height_small
            pdf.set_font(current_font, size=10) # Reset font size

        pdf.set_font(current_font, size=9)
        sug_usr_lines = SUGGESTION_USERS.split('\n')
        for line in sug_usr_lines:
            pdf.text(x=left_margin + content_indent, y=current_y, txt=filter_basic(line))
            current_y += line_height_small

        current_y = max(current_y, section_start_y + line_height_title + 5)
        current_y += 5
    except Exception as e:
        print(f"⚠️ Erro Seção Usuários: {e}")


    # --- Seção: 6. Criptografia de Disco (BitLocker) ---
    try:
        section_start_y = current_y
        drive_checked = encryption_data.get('drive', 'N/A')
        pdf.set_font(current_font, style='B', size=12)
        pdf.text(x=left_margin, y=current_y, txt=f"6. Criptografia de Disco ({drive_checked}:)")
        current_y += line_height_title

        pdf.set_font(current_font, size=10)
        status_enc = encryption_data.get('status', 'Desconhecido')
        protection_enc = encryption_data.get('protection', 'Desconhecido')
        error_enc = encryption_data.get('error')

        # Determine overall status color
        if status_enc == "Encrypted" and protection_enc == "On":
            color = COLOR_GREEN
        elif status_enc in ["Error", "Skipped", "Not Implemented"]:
            color = COLOR_RED
        elif status_enc == "Decrypted" or protection_enc == "Off":
             color = COLOR_RED # Decrypted or Protection Off is Red
        elif status_enc in ["Encrypting", "Decrypting"]:
            color = COLOR_ORANGE # In progress is Orange
        elif status_enc == "Not Enabled/Not Found":
            color = COLOR_GRAY # Not applicable/found is Gray
        else: # Unknown status
            color = COLOR_BLACK

        # Print Encryption Status
        pdf.set_text_color(*color)
        pdf.text(x=left_margin + content_indent, y=current_y, txt=f"Status Criptografia: {filter_basic(status_enc)}")
        pdf.set_text_color(*COLOR_BLACK)
        current_y += line_height_normal

        # Print Protection Status only if relevant
        if status_enc not in ["Not Enabled/Not Found", "Error", "Skipped", "Not Implemented"]:
            if protection_enc == "On":
                prot_color = COLOR_GREEN
            elif protection_enc == "Off":
                prot_color = COLOR_RED
            else: # Unknown protection status
                prot_color = COLOR_BLACK
            pdf.set_text_color(*prot_color)
            pdf.text(x=left_margin + content_indent, y=current_y, txt=f"Status Proteção: {filter_basic(protection_enc)}")
            pdf.set_text_color(*COLOR_BLACK)
            current_y += line_height_normal

        # Print Error/Warning if exists
        if error_enc:
            # Gray out admin required errors, red for others
            err_color = COLOR_RED if "Administrador" not in error_enc else COLOR_GRAY
            pdf.set_text_color(*err_color)
            pdf.text(x=left_margin + content_indent, y=current_y, txt=f"Erro/Aviso: {filter_basic(error_enc)}")
            pdf.set_text_color(*COLOR_BLACK)
            current_y += line_height_normal

        # Print Suggestion
        pdf.set_font(current_font, size=9)
        sug_enc_lines = SUGGESTION_ENCRYPTION.split('\n')
        for line in sug_enc_lines:
            pdf.text(x=left_margin + content_indent, y=current_y, txt=filter_basic(line))
            current_y += line_height_small

        current_y = max(current_y, section_start_y + line_height_title + 5)
        current_y += 5
    except Exception as e:
        print(f"⚠️ Erro Seção Criptografia: {e}")

    # --- Finalização --- (Número muda para 7)
    try:
        current_y += 10 # Add some space before final line
        pdf.set_font(current_font, style='B', size=12)
        pdf.text(x=left_margin, y=current_y, txt="7. Verificação concluída.")
    except Exception as e:
         print(f"⚠️ Erro ao gerar 'Verificação concluída': {e}")

    # --- Salvar e Abrir PDF ---
    print("\n⏳ Tentando finalizar e salvar o PDF...")
    try:
        pdf.output(output_path)
        print(f"✅ Relatório salvo com sucesso em: {os.path.abspath(output_path)}")
        try:
            absolute_path = os.path.realpath(output_path)
            webbrowser.open(f'file://{absolute_path}')
            print(f"🚀 Tentando abrir '{absolute_path}'...")
        except Exception as e_open:
            print(f"⚠️ Não foi possível abrir o PDF automaticamente: {e_open}")
    except Exception as e_save:
        print(f"❌ Falha CRÍTICA ao gerar/salvar PDF: {e_save}")

if __name__ == "__main__":
    # Bloco de teste
    print("Executando report_generator.py diretamente para teste...")
    example_ports = [(23, 'Telnet'),(135, 'RPC'), (445,'SMB'), (3389, 'RDP')]
    example_fw_data = {'os': 'Windows', 'status': 'Disabled (All Profiles)', 'error': None}
    # Example with long details list and error
    example_upd_data_long = {
        'os': 'Windows', 'status': 'Updates Pending', 'count': 12,
        'details': [f'KB12345{i} - Update de Segurança para Windows Teste {i}' for i in range(12)],
        'error': None #"Erro simulado ao buscar atualizações. Permissão negada."
    }
    example_av_data = {'os': 'Windows', 'status': 'Enabled but Outdated',
                       'products': [{'name': 'Defender', 'enabled': True, 'updated': False},
                                    {'name': 'OutroAV', 'enabled': False, 'updated': None}],
                       'error': None}
    example_usr_data_complex = {
        'os': 'Windows', 'status': 'Success',
        'users': [{'username': 'Administrador', 'active': True, 'password_expires': False, 'is_admin': True, 'risk':'High', 'error':None},
                  {'username': 'Usuário Padrão', 'active': True, 'password_expires': True, 'is_admin': False, 'risk':'Low', 'error':None},
                  {'username': 'guest', 'active': False, 'password_expires': None, 'is_admin': False, 'risk':'Medium', 'error':None},
                  {'username': 'ContaTesteExpiradaSenhaLongaParaTestarQuebraDeLinhaNoRelatorioPDF', 'active': True, 'password_expires': False, 'is_admin': False, 'risk':'Medium', 'error':None},
                  {'username': 'ErroUser', 'active': None, 'password_expires': None, 'is_admin': None, 'risk':'High', 'error': 'Falha ao ler info'},
                  {'username': 'User6', 'active': True, 'password_expires': True, 'is_admin': False, 'risk': 'Low', 'error': None},
                  {'username': 'User7', 'active': True, 'password_expires': True, 'is_admin': False, 'risk': 'Low', 'error': None},
                  {'username': 'User8', 'active': True, 'password_expires': True, 'is_admin': False, 'risk': 'Low', 'error': None}, # 8th user
                  {'username': 'User9 - Not Shown', 'active': True, 'password_expires': True, 'is_admin': False, 'risk': 'Low', 'error': None} # 9th user
                 ],
        'error': "Aviso: Não foi possível verificar grupos de Admin (requer privilégios elevados)."
    }
    example_enc_data_off = {'os': 'Windows', 'drive': 'C', 'status': 'Decrypted', 'protection': 'Off', 'error': None}
    example_enc_data_error = {'os': 'Windows', 'drive': 'C', 'status': 'Error', 'protection': None, 'error': 'Falha ao executar manage-bde. Requer permissão de Administrador.'}

    output_file = "relatorio_teste_zenithscan.pdf"
    # Use os dados de exemplo mais complexos para testar limites
    generate_pdf_report(example_ports,
                        example_fw_data,
                        example_upd_data_long, # Teste com lista longa
                        example_av_data, # Teste com multiplos AVs
                        example_usr_data_complex, # Teste com usuários complexos e erro
                        example_enc_data_error, # Teste com erro
                        output_file)

    print(f"\nRelatório de teste gerado: {output_file}")