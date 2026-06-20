from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import mysql.connector
from datetime import datetime
import bcrypt  # <--- Biblioteca responsável por gerar hashes seguros de senha

app = Flask(__name__, template_folder='html', static_folder='css')
app.secret_key = 'chave_secreta_para_seguranca'

# =========================================================================
# ⚙️ CONFIGURAÇÃO RÍGIDA DE SESSÃO E COOKIES (PROBLEMA Nº 4)
# =========================================================================
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

def get_db_connection():
    return mysql.connector.connect(
        host='200.131.251.11',
        port=3341, 
        user='2026Hack',
        password='Hack@2026', 
        database='2026ProjetoHack',
        connection_timeout=5
    )

# =========================================================================
# 🔄 ROTA RAIZ REESTRUTURADA (PROBLEMA Nº 1)
# =========================================================================
@app.route('/')
def home():
    if 'user_id' in session:
        if int(session.get('perfil', 0)) == 1:
            return redirect(url_for('admin_desbloqueio'))
        return "<h1>Usuário autenticado</h1>"
    return redirect(url_for('login'))

# =========================================================================
# 🧪 ROTAS DE DEBUG E ISOLAMENTO (PROBLEMA Nº 3 E Nº 5)
# =========================================================================
@app.route('/debug_session')
def debug_session():
    return {
        "session": dict(session)
    }

@app.route('/teste')
def teste():
    session['user_id'] = 1
    session['perfil'] = 1
    print("\n===== TESTE DEFINITIVO VIA URL =====")
    print("SESSAO CRIADA NO /TESTE:", dict(session))
    return redirect(url_for('admin_desbloqueio'))

# =========================================================================
# === SUBSISTEMA DE AUTENTICAÇÃO E ANÁLISE DE BRUTE-FORCE ===
# =========================================================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    conn = None
    cursor = None
    try:
        if request.method == 'POST':
            email = request.form.get('email')
            senha = request.form.get('senha')
            
            if request.headers.getlist("X-Forwarded-For"):
                ip_atual = request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
            else:
                ip_atual = request.remote_addr

            agente_usuario = request.headers.get('User-Agent', 'Desconhecido')

            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("SELECT * FROM usuario WHERE email = %s", (email,))
            user = cursor.fetchone()
            
            if not user:
                agora = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
                sql_log_inexistente = """
                    INSERT INTO log_atividade (descricao, id_status, id_tipo, num_tentativa)
                    VALUES (%s, 2, 1, NULL)
                """
                msg_inexistente = f"TENTATIVA DE LOGIN: Usuario nao registrado tentou acesso com o e-mail: {email} em {agora}"
                cursor.execute(sql_log_inexistente, (msg_inexistente,))
                conn.commit()
                return render_template('login.html', conta_inexistente=True, email_digitado=email, trava_demo=True)

            id_usuario_log = user['num_usuario']
            numero_tentativa_log = user['tentativas'] + 1

            try:
                sql_log_login = """
                    INSERT INTO login (num_tentativa, ip_origem, agente_usuario, num_usuario, data) 
                    VALUES (%s, %s, %s, %s, CURDATE())
                """
                cursor.execute(sql_log_login, (numero_tentativa_log, ip_atual, agente_usuario, id_usuario_log))
                conn.commit()
            except mysql.connector.Error as err_log:
                print(f"[AVISO DE BANCO] Falha não impeditiva ao gravar histórico de login: {err_log}")

            if user.get('id_status') == 2:
                return render_template('login.html', bloqueado=True, email_digitado=email, trava_demo=True)

            senha_digitada_bytes = senha.encode('utf-8')
            senha_banco_bytes = user['senha_hash'].encode('utf-8')

            if bcrypt.checkpw(senha_digitada_bytes, senha_banco_bytes):
                cursor.execute("UPDATE usuario SET tentativas = 0 WHERE email = %s", (email,))
                
                agora = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
                sql_sucesso_log = """
                    INSERT INTO log_atividade (descricao, id_status, id_tipo, num_tentativa)
                    VALUES (%s, 1, 1, NULL)
                """
                msg_sucesso = f"LOGIN: Acesso concedido e autenticado para o usuario {email} em {agora}."
                cursor.execute(sql_sucesso_log, (msg_sucesso,))
                conn.commit()
                
                print("\n" + "="*50)
                print("[DIAGNÓSTICO] LOGIN COM SUCESSO DETECTADO!")
                print(f"[DIAGNÓSTICO] Chaves vindas do banco: {list(user.keys())}")
                print(f"[DIAGNÓSTICO] Valor de 'perfil': {user.get('perfil')} | Tipo: {type(user.get('perfil'))}")
                print(f"[DIAGNÓSTICO] Valor de 'id_status': {user.get('id_status')} | Tipo: {type(user.get('id_status'))}")
                print("="*50 + "\n")

                session.permanent = False
                session['user_id'] = user['num_usuario']
                session['user_nome'] = user['nome']
                
                try:
                    session['perfil'] = int(user.get('perfil', 0))
                except (ValueError, TypeError):
                    session['perfil'] = 0
                
                cursor.close()
                conn.close()
                
                if session['perfil'] == 1:
                    print("[DIAGNÓSTICO LOGIN] Redirecionando para /admin/desbloqueio")
                    return redirect(url_for('admin_desbloqueio'))
                else:
                    print(f"[DIAGNÓSTICO LOGIN] Redirecionando para Google (Perfil: {session['perfil']})")
                    return redirect('https://www.google.com')
            
            else:
                novas_tentativas = user['tentativas'] + 1
                if novas_tentativas >= 5:
                    cursor.execute("""
                        UPDATE usuario 
                        SET tentativas = %s, id_status = 2, ultimo_ip_bloqueio = %s 
                        WHERE email = %s
                    """, (novas_tentativas, ip_atual, email))
                    
                    try:
                        sql_historico_bloqueio = """
                            INSERT INTO bloqueio (data, num_tentativa, motivo) 
                            VALUES (CURDATE(), %s, %s)
                        """
                        motivo_bloqueio = "Excesso de tentativas de login (Brute-Force)"
                        cursor.execute(sql_historico_bloqueio, (novas_tentativas, motivo_bloqueio))
                    except Exception as e_blq:
                        print(f"[AVISO DE BANCO] Falha ao persistir na tabela bloqueio: {e_blq}")
                    
                    agora = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
                    sql_log_bloqueio_atividade = """
                        INSERT INTO log_atividade (descricao, id_status, id_tipo, num_tentativa)
                        VALUES (%s, 2, 1, NULL)
                    """
                    msg_bloqueio_atividade = f"BLOQUEIO: Conta suspensa por excesso de tentativas no e-mail: {email} em {agora}"
                    cursor.execute(sql_log_bloqueio_atividade, (msg_bloqueio_atividade,))
                    conn.commit()
                    return render_template('login.html', bloqueado=True, email_digitado=email, trava_demo=True)
                
                else:
                    cursor.execute("UPDATE usuario SET tentativas = %s WHERE email = %s", (novas_tentativas, email))
                    
                    agora = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
                    sql_log_erro_atividade = """
                        INSERT INTO log_atividade (descricao, id_status, id_tipo, num_tentativa)
                        VALUES (%s, 2, 1, NULL)
                    """
                    msg_erro_atividade = f"TENTATIVA DE LOGIN: Falha de autenticacao para o e-mail: {email} em {agora}"
                    cursor.execute(sql_log_erro_atividade, (msg_erro_atividade,))
                    conn.commit()
                    return render_template('login.html', senha_incorreta=True, email_digitado=email, trava_demo=True)

    except Exception as e:
        print(f"\n[CRASH CRÍTICO NO BACKEND]: {e}\n")
        return render_template('login.html', db_error=True)
        
    finally:
        if cursor:
            try: cursor.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass
        
    return render_template('login.html')

# =========================================================================
# === SUBSISTEMA DE CADASTRO E GERAÇÃO DE ASSINATURA DE SEGURANÇA ===
# =========================================================================
@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        num_usuario = request.form.get('num_usuario')
        nome = request.form.get('nome')
        email = request.form.get('email')
        cpf_enviado = request.form.get('cpf', '')
        
        tamanho_cpf = len(cpf_enviado)
        if tamanho_cpf < 11 or tamanho_cpf > 14:
            return f"<h1>Erro de Validação: O CPF deve conter entre 11 e 14 caracteres! ({tamanho_cpf})</h1>"

        cpf = cpf_enviado 
        telefone = request.form.get('telefone')
        senha = request.form.get('senha')
        repetir_senha = request.form.get('repetir_senha')

        if request.headers.getlist("X-Forwarded-For"):
            ip_cadastro = request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
        else:
            ip_cadastro = request.remote_addr

        if senha != repetir_senha:
            return "<h1>Senhas não coincidem!</h1>"

        senha_bytes = senha.encode('utf-8')
        salt = bcrypt.gensalt()
        senha_criptografada = bcrypt.hashpw(senha_bytes, salt).decode('utf-8')

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            sql = """INSERT INTO usuario (num_usuario, nome, email, senha_hash, cpf, telefone, perfil, id_status, data, ip_origem) 
                     VALUES (%s, %s, %s, %s, %s, %s, 0, 1, CURDATE(), %s)"""
            
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
# === MÓDULOS ADMINISTRATIVOS COM TELEMETRIA ATIVA (PROBLEMA Nº 2) ===
# =========================================================================
@app.route('/admin/desbloqueio')
def admin_desbloqueio():
    print("\n===== ADMIN DESBLOQUEIO =====")
    print("SESSION RECEBIDA:", dict(session))

    if 'user_id' not in session:
        print("RESULTADO: ACESSO NEGADO -> SEM USER_ID NA SESSION")
        return redirect(url_for('login'))

    if int(session.get('perfil', 0)) != 1:
        print(f"RESULTADO: ACESSO NEGADO -> PERFIL NÄO É ADMIN (Valor: {session.get('perfil')})")
        return redirect(url_for('login'))

    print("RESULTADO: ACESSO LIBERADO COM SUCESSO!")
    return render_template('desbloqueio.html')

@app.route('/admin/log_atividade')
def admin_log_activity():
    if 'user_id' not in session or int(session.get('perfil', 0)) != 1:
        return redirect(url_for('login'))
        
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT num_log, descricao, id_status, id_tipo, num_tentativa FROM log_atividade ORDER BY num_log DESC")
        logs_banco = cursor.fetchall()
        return render_template('log_atividade.html', lista_logs=logs_banco)
    except Exception as e_db:
        print(f"Erro ao buscar registros: {e_db}")
        return render_template('login.html', db_error=True)
    finally:
        if cursor: try: cursor.close()
        except: pass
        if conn: try: conn.close()
        except: pass

@app.route('/admin/usuarios')
def admin_usuarios():
    if 'user_id' not in session or int(session.get('perfil', 0)) != 1:
        return redirect(url_for('login'))
        
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT num_usuario, nome, email, perfil, id_status, ip_origem, ultimo_ip_bloqueio, responsavel_desbloqueio FROM usuario")
        usuarios_banco = cursor.fetchall()
        return render_template('usuario.html', lista=usuarios_banco)
    except Exception as e_db:
        print(f"Erro ao listar tabela: {e_db}")
        return render_template('login.html', db_error=True)
    finally:
        if cursor: try: cursor.close()
        except: pass
        if conn: try: conn.close()
        except: pass