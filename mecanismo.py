from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import mysql.connector
from datetime import datetime
import bcrypt  # <--- Biblioteca responsável por gerar hashes seguros de senha

app = Flask(__name__, template_folder='html', static_folder='css')
app.secret_key = 'chave_secreta_para_seguranca'

# =========================================================================
# === REGRA DE CYBERSECURITY: GERENCIAMENTO DE SESSÃO ATIVA ===
# =========================================================================
@app.before_request
def configurar_sessao():
    # Define que os dados de sessão (cookies) expiram imediatamente quando o navegador ou aba fecham,
    # impedindo que o usuário pule o login ao abrir o site novamente (Princípio de Privilégio Mínimo).
    session.permanent = False

def get_db_connection():
    return mysql.connector.connect(
        host='200.131.251.11',
        port=3341, 
        user='2026Hack',
        password='Hack@2026', 
        database='2026ProjetoHack',
        connection_timeout=5
    )

@app.route('/')
def home():
    # REGRA DE PROTEÇÃO: Força a limpeza de qualquer token residual na memória antes de avaliar a rota inicial
    session.clear()
    return redirect(url_for('login'))

# =========================================================================
# === SUBSISTEMA DE AUTENTICAÇÃO E ANÁLISE DE BRUTE-FORCE ===
# =========================================================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        if request.method == 'POST':
            email = request.form.get('email')
            senha = request.form.get('senha')
            
            # === CAPTURA DE TELEMETRIA AVANÇADA (AGENT USUÁRIO E REDE) ===
            # Captura o IP real tratando o proxy reverso do Render
            if request.headers.getlist("X-Forwarded-For"):
                ip_atual = request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
            else:
                ip_atual = request.remote_addr

            # Captura a string bruta do Agente de Usuário (Navegador, SO, Aparelho)
            # Exemplo de persistência: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36... Chrome/120.0..."
            agente_usuario = request.headers.get('User-Agent', 'Desconhecido')

            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            
            # Consulta a existência do usuário na base
            cursor.execute("SELECT * FROM usuario WHERE email = %s", (email,))
            user = cursor.fetchone()
            
            # Definição de variáveis para o log de tentativa de login
            id_usuario_log = user['num_usuario'] if user else None
            # Se o usuário existe, a tentativa atual é o número que já está no banco + 1, se não existir, define como 1
            numero_tentativa_log = (user['tentativas'] + 1) if user else 1

           # === PERSISTÊNCIA RIGOROSA NA TABELA 'LOGIN' (ALINHADO WITH O WORKBENCH) ===
            # Mapeia exatamente as colunas do print: num_tentativa, ip_origem, agente_usuario, num_usuario, data
            sql_log_login = """
                INSERT INTO login (num_tentativa, ip_origem, agente_usuario, num_usuario, data) 
                VALUES (%s, %s, %s, %s, CURDATE())
            """
            # Certifique-se de enviar as variáveis na mesma ordem das colunas especificadas acima
            cursor.execute(sql_log_login, (numero_tentativa_log, ip_atual, agente_usuario, id_usuario_log))
            conn.commit()

            # 1️⃣ CENÁRIO: O usuário existe no banco de dados
            if user:
                if user.get('id_status') == 2:
                    cursor.close()
                    conn.close()
                    return render_template('login.html', bloqueado=True, email_digitado=email, trava_demo=True)

                # Comparação da senha criptografada via Bcrypt
                senha_digitada_bytes = senha.encode('utf-8')
                senha_banco_bytes = user['senha_hash'].encode('utf-8')

                if bcrypt.checkpw(senha_digitada_bytes, senha_banco_bytes):
                    # Sucesso: Zera o contador de falhas na tabela usuario
                    cursor.execute("UPDATE usuario SET tentativas = 0 WHERE email = %s", (email,))
                    
                    # === AUDITORIA: PERSISTÊNCIA EM LOG DE ATIVIDADE (LOGIN COM SUCESSO E DATA/HORA) ===
                    agora = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
                    sql_sucesso_log = """
                        INSERT INTO log_atividade (descricao, id_status, id_tipo, num_tentativa)
                        VALUES (%s, 1, 1, %s)
                    """
                    msg_sucesso = f"LOGIN: Acesso concedido e autenticado para o usuario {email} em {agora}."
                    cursor.execute(sql_sucesso_log, (msg_sucesso, numero_tentativa_log))
                    
                    conn.commit()
                    
                    session['user_id'] = user['num_usuario']
                    session['user_nome'] = user['nome']
                    session['perfil'] = user.get('perfil', 0)
                    
                    cursor.close()
                    conn.close()
                    
                    if session['perfil'] == 1:
                        return redirect(url_for('admin_desbloqueio'))
                    else:
                        return redirect('https://www.google.com')
                
                # 2️⃣ CENÁRIO: O e-mail existe, mas a senha está errada
                else:
                    novas_tentativas = user['tentativas'] + 1
                    
                    if novas_tentativas >= 5:
                        # Bloqueia o usuário na tabela pai
                        cursor.execute("""
                            UPDATE usuario 
                            SET tentativas = %s, id_status = 2, ultimo_ip_bloqueio = %s 
                            WHERE email = %s
                        """, (novas_tentativas, ip_atual, email))
                        
                        # === ALTERAÇÃO CONFORME WORKBENCH ===
                        # Alimenta a tabela histórica de bloqueio mapeando rigorosamente suas colunas físicas
                        sql_historico_bloqueio = """
                            INSERT INTO bloqueio (data, num_tentativa, motivo) 
                            VALUES (CURDATE(), %s, %s)
                        """
                        motivo_bloqueio = "Excesso de tentativas de login (Brute-Force)"
                        cursor.execute(sql_historico_bloqueio, (novas_tentativas, motivo_bloqueio))
                        
                        # === AUDITORIA: PERSISTÊNCIA EM LOG DE ATIVIDADE (BLOQUEIO ATIVADO E DATA/HORA) ===
                        agora = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
                        sql_log_bloqueio_atividade = """
                            INSERT INTO log_atividade (descricao, id_status, id_tipo, num_tentativa)
                            VALUES (%s, 2, 1, %s)
                        """
                        msg_bloqueio_atividade = f"BLOQUEIO: Conta suspensa por excesso de tentativas no e-mail: {email} em {agora}"
                        cursor.execute(sql_log_bloqueio_atividade, (msg_bloqueio_atividade, novas_tentativas))
                        
                        conn.commit()
                        cursor.close()
                        conn.close()
                        return render_template('login.html', bloqueado=True, email_digitado=email, trava_demo=True)
                    
                    else:
                        # Apenas updates o contador de tentativas do usuário
                        cursor.execute("UPDATE usuario SET tentativas = %s WHERE email = %s", (novas_tentativas, email))
                        
                        # === AUDITORIA: PERSISTÊNCIA EM LOG DE ATIVIDADE (TENTATIVA DE LOGIN INCORRETA E DATA/HORA) ===
                        agora = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
                        sql_log_erro_atividade = """
                            INSERT INTO log_atividade (descricao, id_status, id_tipo, num_tentativa)
                            VALUES (%s, 2, 1, %s)
                        """
                        msg_erro_atividade = f"TENTATIVA DE LOGIN: Falha de autenticacao para o e-mail: {email} em {agora}"
                        cursor.execute(sql_log_erro_atividade, (msg_erro_atividade, novas_tentativas))
                        
                        conn.commit()
                        cursor.close()
                        conn.close()
                        # CORRIGIDO: Retorno explícito adicionado para renderizar o erro da tentativa malsucedida intermediária
                        return render_template('login.html', senha_incorreta=True, email_digitado=email, trava_demo=True)
            
            # 3️⃣ CENÁRIO: O e-mail digitado NÃO existe no banco de dados
            else:
                # === AUDITORIA: PERSISTÊNCIA EM LOG DE ATIVIDADE (CONTA INEXISTENTE E DATA/HORA) ===
                agora = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
                sql_log_inexistente = """
                    INSERT INTO log_atividade (descricao, id_status, id_tipo, num_tentativa)
                    VALUES (%s, 2, 1, %s)
                """
                msg_inexistente = f"TENTATIVA DE LOGIN: Usuario nao registrado tentou acesso com o e-mail: {email} em {agora}"
                cursor.execute(sql_log_inexistente, (msg_inexistente, numero_tentativa_log))
                
                conn.commit()
                cursor.close()
                conn.close()
                return render_template('login.html', conta_inexistente=True, email_digitado=email, trava_demo=True)

    except Exception as e:
        print(f"Erro no subsistema de login/telemetria: {e}")
        return render_template('login.html', db_error=True)
        
    return render_template('login.html')

# =========================================================================
# === SUBSISTEMA DE CADASTRO E GERAÇÃO DE ASSINATURA DE SEGURANÇA ===
# =========================================================================
@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        # 1. Captura os dados brutos enviados pelo formulário HTML
        num_usuario = request.form.get('num_usuario')
        nome = request.form.get('nome')
        email = request.form.get('email')
        
        # === CAPTURA DO CPF PARA VALIDAÇÃO DE TAMANHO ===
        # Captura o valor exatamente do jeito que veio do HTML (com os pontos e hífens da máscara)
        cpf_enviado = request.form.get('cpf', '')
        
        # === TRAVA DE SEGURANÇA (MÍNIMO 11 E MÁXIMO 14 CARACTERES) ===
        # Valida se o comprimento da string está dentro do limite exigido pelas regras de negócio.
        # Se falhar, interrompe o fluxo imediatamente antes de tocar no banco de dados.
        tamanho_cpf = len(cpf_enviado)
        if tamanho_cpf < 11 or tamanho_cpf > 14:
            return f"<h1>Erro de Validação: O CPF deve conter entre 11 e 14 caracteres! (Digitado: {tamanho_cpf})</h1><a href='/cadastro'>Voltar</a>"

        # === ATUALIZAÇÃO REQUISITADA: PRESERVAÇÃO DA MÁSCARA ===
        # Atribui o CPF enviado diretamente para a variável que vai para o banco de dados.
        # Com isso, os pontos e o hífen gerados pelo JavaScript preenchem a coluna varchar(14).
        cpf = cpf_enviado 
        
        telefone = request.form.get('telefone')
        senha = request.form.get('senha')
        repetir_senha = request.form.get('repetir_senha')

        # CAPTURA O IP DE ORIGEM DO USUÁRIO (Trata o proxy reverso do Render ou fallback local)
        if request.headers.getlist("X-Forwarded-For"):
            ip_cadastro = request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
        else:
            ip_cadastro = request.remote_addr

        # Validação simples de segurança antes do processamento
        if senha != repetir_senha:
            return "<h1>Senhas não coincidem!</h1><a href='/cadastro'>Voltar</a>"

        # === GERAÇÃO DE HASH DA SENHA COM SALT SECURITY ===
        # Passa a senha limpa recebida do formulário para bytes, gera um salt pseudo-aleatório
        # único e codifica a string resultante para armazenamento seguro e ininteligível.
        senha_bytes = senha.encode('utf-8')
        salt = bcrypt.gensalt()
        senha_criptografada = bcrypt.hashpw(senha_bytes, salt).decode('utf-8')

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # ESTRUTURA DML: Alinhamento de colunas para inserção segura no banco de dados
            sql = """INSERT INTO usuario (num_usuario, nome, email, senha_hash, cpf, telefone, perfil, id_status, data, ip_origem) 
                     VALUES (%s, %s, %s, %s, %s, %s, 0, 1, CURDATE(), %s)"""
            
            # Envia os dados consolidados, mantendo agora o CPF formatado visualmente no banco
            valores = (num_usuario, nome, email, senha_criptografada, cpf, telefone, ip_cadastro)
            cursor.execute(sql, valores)
            
            conn.commit() 
            cursor.close()
            conn.close()
            return redirect(url_for('login'))
            
        except Exception as e:
            print(f"Erro ao salvar no NEXUS: {e}")
            return f"<h1>Erro técnico ao salvar: {e}</h1>"
            
    return render_template('cadastro.html')

# =========================================================================
# === MÓDULOS ADMINISTRATIVOS PROTEGIDOS POR ISOLAMENTO DE ROTAS ===
# =========================================================================
@app.route('/admin/desbloqueio')
def admin_desbloqueio():
    # === BARREIRA DE PROTEÇÃO CONTRA ELEMENTOS EXTERNOS (TRAVA DE URL) ===
    # Verifica se a sessão do ID existe e valida se o privilégio corresponds a Administrador (1).
    # Caso tente forçar o acesso inserindo a URL direto na barra, o sistema rejeita e joga pro login.
    if 'user_id' not in session or session.get('perfil') != 1: 
        # === AUDITORIA EXTRA: ACESSO NEGADO COM IDENTIFICAÇÃO E DATA/HORA ===
        try:
            agora = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
            quem_tentou = f"Usuario ID #{session['user_id']}" if 'user_id' in session else "Acesso Anonimo"
            
            conn = get_db_connection()
            cursor = conn.cursor()
            sql_negado = "INSERT INTO log_atividade (descricao, id_status, id_tipo, num_tentativa) VALUES (%s, 2, 2, NULL)"
            msg_negado = f"ACESSO NEGADO: {quem_tentou} tentou forcar entrada na rota /admin/desbloqueio em {agora}"
            cursor.execute(sql_negado, (msg_negado,))
            conn.commit()
            cursor.close()
            conn.close()
        except: pass
        return redirect(url_for('login'))
    return render_template('desbloqueio.html')

@app.route('/admin/log_atividade')
def admin_log_activity():
    # BARREIRA DE PROTEÇÃO: Impede usuários comuns de acessarem os logs de auditoria
    if 'user_id' not in session or session.get('perfil') != 1:
        # === AUDITORIA EXTRA: ACESSO NEGADO COM IDENTIFICAÇÃO E DATA/HORA ===
        try:
            agora = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
            quem_tentou = f"Usuario ID #{session['user_id']}" if 'user_id' in session else "Acesso Anonimo"
            
            conn = get_db_connection()
            cursor = conn.cursor()
            sql_negado = "INSERT INTO log_atividade (descricao, id_status, id_tipo, num_tentativa) VALUES (%s, 2, 2, NULL)"
            msg_negado = f"ACESSO NEGADO: {quem_tentou} tentou forcar entrada na rota /admin/log_atividade em {agora}"
            cursor.execute(sql_negado, (msg_negado,))
            conn.commit()
            cursor.close()
            conn.close()
        except: pass
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Busca os logs trazendo a descrição e amarrando com as tentativas de login para auditoria
    cursor.execute("""
        SELECT num_log, descricao, id_status, id_tipo, num_tentativa 
        FROM log_atividade 
        ORDER BY num_log DESC
    """)
    logs_banco = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('log_atividade.html', lista_logs=logs_banco)

@app.route('/admin/usuarios')
def admin_usuarios():
    # === BARREIRA DE PROTEÇÃO CONTRA ELEMENTOS EXTERNOS (TRAVA DE URL) ===
    # Impede operadores não autenticados ou usuários padrão de acessar o inventário de monitoramento.
    if 'user_id' not in session or session.get('perfil') != 1:
        # === AUDITORIA EXTRA: ACESSO NEGADO COM IDENTIFICAÇÃO E DATA/HORA ===
        try:
            agora = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
            quem_tentou = f"Usuario ID #{session['user_id']}" if 'user_id' in session else "Acesso Anonimo"
            
            conn = get_db_connection()
            cursor = conn.cursor()
            sql_negado = "INSERT INTO log_atividade (descricao, id_status, id_tipo, num_tentativa) VALUES (%s, 2, 2, NULL)"
            msg_negado = f"ACESSO NEGADO: {quem_tentou} tentou forcar entrada na rota /admin/usuarios em {agora}"
            cursor.execute(sql_negado, (msg_negado,))
            conn.commit()
            cursor.close()
            conn.close()
        except: pass
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Busca com a auditoria de responsável incluída para listar no painel
    cursor.execute("SELECT num_usuario, nome, email, perfil, id_status, ip_origem, ultimo_ip_bloqueio, responsavel_desbloqueio FROM usuario")
    usuarios_banco = cursor.fetchall()
    conn.close()

    return render_template('usuario.html', lista=usuarios_banco)

# =========================================================================
# === SISTEMA DE ENDPOINTS: CONSULTA DINÂMICA DE RASTREAMENTO ===
# =========================================================================
@app.route('/buscar_ip_bloqueio', methods=['POST'])
def buscar_ip_bloqueio():
    # === ISOLAMENTO DE API (BACKEND LOCKDOWN) ===
    # Garante que requisições automatizadas em segundo plano vindas de scripts ou de fora do painel
    # sejam sumariamente interceptadas se não pertencerem a um administrador em sessão.
    if 'user_id' not in session or session.get('perfil') != 1:
        return jsonify({'ip': 'ACESSO NEGADO'}), 403

    try:
        dados = request.get_json()
        id_usuario = dados.get('id') if dados else None
        
        if not id_usuario:
            return jsonify({'ip': 'ID NÃO INFORMADO'})
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT ultimo_ip_bloqueio FROM usuario WHERE num_usuario = %s", (id_usuario,))
        resultado = cursor.fetchone()
        conn.close()
        
        # Retorna o IP dinâmico ou o status limpo capturado pelo proxy do Render para o front-end
        if resultado and resultado['ultimo_ip_bloqueio']:
            return jsonify({'ip': resultado['ultimo_ip_bloqueio']})
        
        return jsonify({'ip': 'IP DESCONHECIDO'})
    except Exception as e:
        print(f"Erro ao buscar IP: {e}")
        return jsonify({'ip': 'ERRO NO SERVIDOR'})

# =========================================================================
# === SUBSISTEMA DE REVERSÃO DE FALHAS E ASSINATURA FORENSE DE HISTÓRICO ===
# =========================================================================
@app.route('/finalizar_desbloqueio', methods=['POST'])
def finalizar_desbloqueio():
    # === VALIDAÇÃO DE AUTORIDADE EM BANCO ===
    # Protege a execução de comandos DML (UPDATE/INSERT) para evitar injeções ou modificações arbitrárias.
    if 'user_id' not in session or session.get('perfil') != 1:
        return redirect(url_for('login'))

    id_usuario = request.form.get('id_usuario')
    sigla_responsavel = request.form.get('responsavel')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True) # Alterado temporariamente para dict para buscar chaves amigáveis
    
    try:
        # === MODIFICAÇÃO DE AUDITORIA CONFORME WORKBENCH ===
        # Como a tabela 'bloqueio' não possui o ID do usuário diretamente, buscamos o registro 
        # mais recente inserido no histórico geral de travas para mapear o vínculo lógico.
        cursor.execute("SELECT num_bloqueio FROM bloqueio ORDER BY data DESC, num_bloqueio DESC LIMIT 1")
        registro_bloqueio = cursor.fetchone()
        
        # Se houver um bloqueio registrado na tabela, isolamos o ID. Se não, definimos como NULL (evita quebra de FK)
        id_bloqueio_vinculado = registro_bloqueio['num_bloqueio'] if registro_bloqueio else None

        # === COMPONENTE DML 1: RESET LÓGICO DE CONTA ===
        # Grava o responsável pela auditoria (LS, AR, EM) e limpa as restrições lógicas da tabela 'usuario'
        cursor.execute("""
            UPDATE usuario 
            SET id_status = 1, 
                tentativas = 0, 
                ultimo_ip_bloqueio = NULL,
                responsavel_desbloqueio = %s 
            WHERE num_usuario = %s
        """, (sigla_responsavel, id_usuario))
        
        # === COMPONENTE DML 2: PERSISTÊNCIA REAL NA TABELA 'DESBLOQUEIO' ===
        # Alinha o fluxo de backend com o modelo relacional estrito.
        # Insere um novo registro histórico documentando a ação da console administrativa.
        sql_historico = """
            INSERT INTO desbloqueio (data, usuario_responsavel, num_bloqueio) 
            VALUES (CURDATE(), %s, %s)
        """
        cursor.execute(sql_historico, (sigla_responsavel, id_bloqueio_vinculado))
        
        # === AUDITORIA: PERSISTÊNCIA EM LOG DE ATIVIDADE (DESBLOQUEIO CONCLUÍDO E DATA/HORA) ===
        agora = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
        sql_log_desbloqueio_atividade = """
            INSERT INTO log_atividade (descricao, id_status, id_tipo, num_tentativa)
            VALUES (%s, 1, 2, NULL)
        """
        msg_desbloqueio_atividade = f"DESBLOQUEIO: Administrador {sigla_responsavel} realizou a reativacao da conta do usuario #{id_usuario} em {agora}"
        cursor.execute(sql_log_desbloqueio_atividade, (msg_desbloqueio_atividade,))
        
        conn.commit()
        print(f"[AUDITORIA LOG] Usuário #{id_usuario} reativado com sucesso por {sigla_responsavel}. Histórico gravado.")

    except Exception as e:
        conn.rollback() # Aborta qualquer operação pendente caso ocorra falha de integridade referencial
        print(f"[ERRO CRÍTICO CRASH] Falha ao sincronizar tabelas de desbloqueio: {e}")
        
    finally:
        cursor.close()
        conn.close() 
    
    return redirect(url_for('admin_usuarios'))

# === ROTA ADICIONAL: ENCERRAMENTO SEGURO DE PRIVILÉGIOS (TERMINAÇÃO DE CONEXÃO) ===
@app.route('/logout')
def logout():
    # Destrói a sessão de forma segura limpando as chaves de acesso alocadas na memória RAM do servidor
    session.clear()
    return redirect(url_for('login'))

# =========================================================================
# === ROTA DE RECUPERAÇÃO DE SENHA (NEXUS CORE) ===
# =========================================================================
@app.route('/recuperacao', methods=['GET', 'POST'])
def recuperacao():
    if request.method == 'POST':
        email = request.form.get('email')
        print(f"[NEXUS LOG] Solicitação de recuperação para o e-mail: {email}")
        return redirect(url_for('login'))
        
    return render_template('recuperacao.html')

if __name__ == '__main__':
    app.run(debug=True, port=8080)