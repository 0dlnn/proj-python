from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import mysql.connector
from datetime import datetime
import bcrypt  # <--- Biblioteca responsável por gerar hashes seguros de senha
from pytz import timezone # <--- Trocado ZoneInfo por pytz

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
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("SELECT * FROM usuario WHERE email = %s", (email,))
            user = cursor.fetchone()
            
            # 1️⃣ CENÁRIO: O usuário existe no banco de dados
            if user:
                if user.get('id_status') == 2:
                    return render_template('login.html', bloqueado=True, email_digitado=email, trava_demo=True)

                # Comparação da senha criptografada via Bcrypt
                senha_digitada_bytes = senha.encode('utf-8')
                senha_banco_bytes = user['senha_hash'].encode('utf-8')

                if bcrypt.checkpw(senha_digitada_bytes, senha_banco_bytes):
                    # Zera as tentativas no banco primeiro para garantir o acesso
                    cursor.execute("UPDATE usuario SET tentativas = 0 WHERE email = %s", (email,))
                    conn.commit()

                    # === REGISTRO FORENSE ISOLADO: LOGIN COM SUCESSO (id_tipo = 1) ===
                    try:
                        cursor.execute("SELECT MAX(num_log) as maior_log FROM log_atividade")
                        resultado_log = cursor.fetchone()
                        maior_log_atual = resultado_log['maior_log'] if resultado_log['maior_log'] is not None else 0
                        proximo_log = int(maior_log_atual) + 1
                        
                        agora = datetime.now(timezone('America/Sao_Paulo')).strftime('%d/%m/%Y %H:%M:%S')
                        descricao = f"LOGIN: O usuario [{user['nome']}] ({email}) acessou a plataforma com sucesso em {agora}."
                        
                        cursor.execute("""
                            INSERT INTO log_atividade (num_log, descricao, id_status, id_tipo, num_tentativa)
                            VALUES (%s, %s, 1, 1, NULL)
                        """, (proximo_log, descricao))
                        conn.commit()
                    except Exception as log_e:
                        print(f"[ERRO LOG SUCESSO]: {log_e}")
                    
                    session['user_id'] = user['num_usuario']
                    session['user_nome'] = user['nome']
                    session['perfil'] = user.get('perfil', 0)
                    
                    if session['perfil'] == 1:
                        return redirect(url_for('admin_desbloqueio'))
                    else:
                        return redirect('https://www.google.com')
                
                # 2️⃣ CENÁRIO: O e-mail existe, mas a senha está errada
                else:
                    novas_tentativas = int(user['tentativas']) + 1
                    
                    if request.headers.getlist("X-Forwarded-For"):
                        ip_atual = request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
                    else:
                        ip_atual = request.remote_addr
                    
                    agora = datetime.now(timezone('America/Sao_Paulo')).strftime('%d/%m/%Y %H:%M:%S')

                    # Prioridade: Atualiza e commita as tentativas no banco imediatamente
                    if novas_tentativas >= 5:
                        cursor.execute("UPDATE usuario SET tentativas = %s, id_status = 2, ultimo_ip_bloqueio = %s WHERE email = %s", (novas_tentativas, ip_atual, email))
                        conn.commit()
                    else:
                        cursor.execute("UPDATE usuario SET tentativas = %s WHERE email = %s", (novas_tentativas, email))
                        conn.commit()

                    # === REGISTRO FORENSE ISOLADO: TENTATIVAS (id_tipo = 4) E BLOQUEIOS (id_tipo = 2) ===
                    try:
                        cursor.execute("SELECT MAX(num_log) as maior_log FROM log_atividade")
                        resultado_log = cursor.fetchone()
                        maior_log_atual = resultado_log['maior_log'] if resultado_log['maior_log'] is not None else 0
                        proximo_log = int(maior_log_atual) + 1

                        if novas_tentativas >= 5:
                            # id_tipo = 2 corresponde a BLOQUEIO na sua tabela tipo
                            descricao = f"BLOQUEIO: Conta suspensa por excesso de tentativas no e-mail: {email} em {agora}."
                            cursor.execute("""
                                INSERT INTO log_atividade (num_log, descricao, id_status, id_tipo, num_tentativa)
                                VALUES (%s, %s, 1, 2, %s)
                            """, (proximo_log, descricao, novas_tentativas))
                        else:
                            # id_tipo = 4 corresponde a TENTATIVA_LOGIN na sua tabela tipo
                            descricao = f"TENTATIVA_LOGIN: Falha de autenticacao para o e-mail: {email} em {agora}."
                            cursor.execute("""
                                INSERT INTO log_atividade (num_log, descricao, id_status, id_tipo, num_tentativa)
                                VALUES (%s, %s, 1, 4, %s)
                            """, (proximo_log, descricao, novas_tentativas))
                        conn.commit()
                    except Exception as log_e:
                        print(f"[ERRO LOG FALHA]: {log_e}")
                        
                    if novas_tentativas >= 5:
                        return render_template('login.html', bloqueado=True, email_digitado=email, tentativas=novas_tentativas, trava_demo=True)
                    else:
                        return render_template('login.html', senha_incorreta=True, email_digitado=email, tentativas=novas_tentativas, trava_demo=True)
            
            # 3️⃣ CENÁRIO: O e-mail digitado NÃO existe no banco de dados
            else:
                agora = datetime.now(timezone('America/Sao_Paulo')).strftime('%d/%m/%Y %H:%M:%S')
                
                # === REGISTRO FORENSE ISOLADO: ACESSO NEGADO (id_tipo = 5) ===
                try:
                    cursor.execute("SELECT MAX(num_log) as maior_log FROM log_atividade")
                    resultado_log = cursor.fetchone()
                    maior_log_atual = resultado_log['maior_log'] if resultado_log['maior_log'] is not None else 0
                    proximo_log = int(maior_log_atual) + 1
                    
                    # Nova descrição personalizada conforme solicitado
                    descricao = f"ACESSO_NEGADO: A conta do e-mail [{email}] nao pertence ao banco de dados mysql em {agora}."
                    
                    # id_tipo = 5 corresponds a ACESSO_NEGADO na sua tabela tipo
                    cursor.execute("""
                        INSERT INTO log_atividade (num_log, descricao, id_status, id_tipo, num_tentativa)
                        VALUES (%s, %s, 1, 5, NULL)
                    """, (proximo_log, descricao))
                    conn.commit()
                except Exception as log_e:
                    print(f"[ERRO LOG INEXISTENTE]: {log_e}")
                
                return render_template('login.html', conta_inexistente=True, email_digitado=email, trava_demo=True)

    except Exception as e:
        print(f"Erro crítico no login: {e}")
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
    # Verifica se a sessão do ID existe e valida se o privilégio corresponde a Administrador (1).
    # Caso tente forçar o acesso inserindo a URL direto na barra, o sistema rejeita e joga pro login.
    if 'user_id' not in session or session.get('perfil') != 1: 
        return redirect(url_for('login'))
    return render_template('desbloqueio.html')

@app.route('/admin/usuarios')
def admin_usuarios():
    # === BARREIRA DE PROTEÇÃO CONTRA ELEMENTOS EXTERNOS (TRAVA DE URL) ===
    # Impede operadores não autenticados ou usuários padrão de acessar o inventário de monitoramento.
    if 'user_id' not in session or session.get('perfil') != 1:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Busca com a auditoria de responsável incluída para listar no painel
    cursor.execute("SELECT num_usuario, nome, email, perfil, id_status, ip_origem, ultimo_ip_bloqueio, responsavel_desbloqueio FROM usuario")
    usuarios_banco = cursor.fetchall()
    conn.close()

    return render_template('usuario.html', lista=usuarios_banco)

@app.route('/admin/log_atividade') # NOVA ROTA
def admin_log_activity():
    # === BARREIRA DE PRIVILÉGIO MÍNIMO (SÓ ENTRA SE FOR ADMIN) ===
    if 'user_id' not in session or int(session.get('perfil', 0)) != 1:
        return redirect(url_for('login'))
        
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Busca os logs ordenando do mais recente para o mais antigo
        cursor.execute("""
            SELECT num_log, descricao, id_status, id_tipo, num_tentativa 
            FROM log_atividade 
            ORDER BY num_log DESC
        """)
        logs_banco = cursor.fetchall()
        
        # ⚠️ IMPORTANTE: 'lista_logs' é a variável que o seu HTML vai ler no Jinja2 {% for log in lista_logs %}
        return render_template('login_atividade.html', lista_logs=logs_banco)
        
    except Exception as e:
        print(f"\n[CRASH NA ROTA LOGS]: {e}\n")
        return render_template('login.html', db_error=True)
        
    finally:
        # Garante que a conexão remota fecha mesmo se o fetchall falhar
        if cursor:
            try: cursor.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass
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

@app.route('/finalizar_desbloqueio', methods=['POST'])
def finalizar_desbloqueio():
    if 'user_id' not in session or int(session.get('perfil', 0)) != 1:
        return redirect(url_for('login'))

    id_usuario = request.form.get('id_usuario')       
    sigla_responsavel = request.form.get('responsavel') 
    id_admin_logado = session.get('user_id')           

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True) # Usando dicionário para facilitar
        
        # === TRAVA DE TIMEZONE: GERA A DATA EXATA EM STRING PARA O BANCO E PARA O TEXTO ===
        agora_texto = datetime.now(timezone('America/Sao_Paulo')).strftime('%d/%m/%Y %H:%M:%S')
        agora_banco = datetime.now(timezone('America/Sao_Paulo')).strftime('%Y-%m-%d %H:%M:%S')
        
        # === ETAPA 1: DESCUBRA O MAIOR ID ATUAL (Select Simples) ===
        cursor.execute("SELECT MAX(num_desbloqueio) as maior_id FROM desbloqueio")
        resultado = cursor.fetchone()
        
        # Se a tabela estiver vazia, o maior ID é 0. Se não, pega o número dela.
        maior_id_atual = resultado['maior_id'] if resultado['maior_id'] is not None else 0
        proximo_id = maior_id_atual + 1  # Somamos 1 no Python mesmo!
        
        # === ETAPA 2: ATUALIZA O STATUS DO USUÁRIO ===
        cursor.execute("SET FOREIGN_KEY_CHECKS = 0;")
        cursor.execute("""
            UPDATE usuario 
            SET id_status = 1, 
                tentativas = 0, 
                responsavel_desbloqueio = %s 
            WHERE num_usuario = %s
        """, (sigla_responsavel, id_usuario)) # Mantendo o IP intacto conforme o combinado!
        
        # === ETAPA 3: INSERE NO DESBLOQUEIO USANDO O ID E A DATA DE SÃO PAULO CALCULADOS ===
        cursor.execute("""
            INSERT INTO desbloqueio (num_desbloqueio, data, usuario_responsavel, num_bloqueio) 
            VALUES (%s, %s, %s, %s)
        """, (proximo_id, agora_banco, id_admin_logado, id_usuario)) # Trocado CURDATE() por agora_banco em string
        
        # === ETAPA 4: LOG DE ATIVIDADES (CALCULANDO O ID MANUAL PARA NÃO FALHAR) ===
        try:
            cursor.execute("SELECT MAX(num_log) as maior_log FROM log_atividade")
            resultado_log = cursor.fetchone()
            maior_log_atual = resultado_log['maior_log'] if resultado_log['maior_log'] is not None else 0
            proximo_log = maior_log_atual + 1
            
            descricao_log = f"DESBLOQUEIO: O administrador [{sigla_responsavel}] realizou a liberacao do ID #{id_usuario} em {agora_texto}."
            
            cursor.execute("""
                INSERT INTO log_atividade (num_log, descricao, id_status, id_tipo, num_tentativa)
                VALUES (%s, %s, 1, 3, NULL)
            """, (proximo_log, descricao_log)) # Adicionado proximo_log e corrigido o id_tipo para 3 (DESBLOQUEIO)
        except Exception as log_err:
            print(f"[AVISO LOG_ATIVIDADE]: Falha ao registrar na auditoria: {log_err}")

        cursor.execute("SET FOREIGN_KEY_CHECKS = 1;")
        conn.commit()
        
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"[ERRO]: {e}")
        
    finally:
        if cursor:
            try: cursor.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass
            
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