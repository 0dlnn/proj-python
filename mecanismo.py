from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import mysql.connector
from datetime import datetime
import bcrypt  # <--- Biblioteca responsável por gerar hashes seguros de senha

app = Flask(__name__, template_folder='html', static_folder='css')
app.secret_key = 'chave_secreta_para_seguranca'

# =========================================================================
# ⚙️ CONFIGURAÇÃO DE SEGURANÇA DOS COOKIES (BLINDAGEM CONTRA LOOPS)
# =========================================================================
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# =========================================================================
# === GERENCIAMENTO DE SESSÃO ATIVA ===
# =========================================================================
@app.before_request
def configurar_sessao():
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
    if 'user_id' in session:
        if int(session.get('perfil', 0)) == 1:
            return redirect(url_for('admin_desbloqueio'))
        return "<h1>Usuário autenticado</h1>"
    return redirect(url_for('login'))

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
            
            # Captura de IP e User-Agent para Auditoria
            if request.headers.getlist("X-Forwarded-For"):
                ip_atual = request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
            else:
                ip_atual = request.remote_addr
            agente_usuario = request.headers.get('User-Agent', 'Desconhecido')

            conn = get_db_connection()
            cursor = conn.connector.cursor(dictionary=True) if hasattr(conn, 'connector') else conn.cursor(dictionary=True)
            
            cursor.execute("SELECT * FROM usuario WHERE email = %s", (email,))
            user = cursor.fetchone()
            
            # 1️⃣ CENÁRIO: O usuário existe no banco de dados
            if user:
                if user.get('id_status') == 2:
                    return render_template('login.html', bloqueado=True, email_digitado=email, trava_demo=True)

                senha_digitada_bytes = senha.encode('utf-8')
                senha_banco_bytes = user['senha_hash'].encode('utf-8')

                if bcrypt.checkpw(senha_digitada_bytes, senha_banco_bytes):
                    # Mantém o reset idêntico ao código funcional
                    cursor.execute("UPDATE usuario SET tentativas = 0 WHERE email = %s", (email,))
                    conn.commit()
                    
                    # Definição segura da sessão
                    session['user_id'] = user['num_usuario']
                    session['user_nome'] = user['nome']
                    session['perfil'] = int(user.get('perfil', 0))
                    
                    # REGISTRO DE LOG COMPLEMENTAR (Executado após a validação da sessão ser garantida)
                    try:
                        agora = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
                        cursor.execute("""
                            INSERT INTO log_atividade (descricao, id_status, id_tipo, num_tentativa)
                            VALUES (%s, 1, 1, NULL)
                        """, (f"LOGIN: Acesso concedido e autenticado para o usuario {email} em {agora}.",))
                        
                        cursor.execute("""
                            INSERT INTO login (num_tentativa, ip_origem, agente_usuario, num_usuario, data) 
                            VALUES (0, %s, %s, %s, CURDATE())
                        """, (ip_atual, agente_usuario, user['num_usuario']))
                        conn.commit()
                    except Exception as log_err:
                        print(f"[AVISO OMITIDO] Falha ao gravar logs de sucesso: {log_err}")

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
                        cursor.execute("UPDATE usuario SET tentativas = %s, id_status = 2, ultimo_ip_bloqueio = %s WHERE email = %s", (novas_tentativas, ip_atual, email))
                        conn.commit()
                        
                        try:
                            agora = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
                            cursor.execute("INSERT INTO log_atividade (descricao, id_status, id_tipo, num_tentativa) VALUES (%s, 2, 1, NULL)",
                                           (f"BLOQUEIO: Conta suspensa por excesso de tentativas no e-mail: {email} em {agora}",))
                            cursor.execute("INSERT INTO bloqueio (data, num_tentativa, motivo) VALUES (CURDATE(), %s, %s)", 
                                           (novas_tentativas, "Excesso de tentativas de login (Brute-Force)"))
                            conn.commit()
                        except: pass
                        
                        return render_template('login.html', bloqueado=True, email_digitado=email, trava_demo=True)
                    else:
                        cursor.execute("UPDATE usuario SET tentativas = %s WHERE email = %s", (novas_tentativas, email))
                        conn.commit()
                        
                        try:
                            agora = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
                            cursor.execute("INSERT INTO log_atividade (descricao, id_status, id_tipo, num_tentativa) VALUES (%s, 2, 1, NULL)",
                                           (f"TENTATIVA DE LOGIN: Falha de autenticacao para o e-mail: {email} em {agora}",))
                            conn.commit()
                        except: pass
                        
                        return render_template('login.html', senha_incorreta=True, email_digitado=email, trava_demo=True)
            
            # 3️⃣ CENÁRIO: O e-mail digitado NÃO existe no banco de dados
            else:
                try:
                    agora = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
                    cursor.execute("INSERT INTO log_atividade (descricao, id_status, id_tipo, num_tentativa) VALUES (%s, 2, 1, NULL)",
                                   (f"TENTATIVA DE LOGIN: Usuario nao registrado tentou acesso com o e-mail: {email} em {agora}",))
                    conn.commit()
                except: pass
                return render_template('login.html', conta_inexistente=True, email_digitado=email, trava_demo=True)

    except Exception as e:
        print(f"Erro no login: {e}")
        return render_template('login.html', db_error=True)
        
    finally:
        # Fechamento seguro de cursores e conexões para evitar travamento do pool do MySQL
        if cursor:
            try: cursor.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass
        
    return render_template('login.html')

# =========================================================================
# === SUBSISTEMA DE CADASTRO ===
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
            return f"<h1>Erro de Validação: O CPF deve conter entre 11 e 14 caracteres! ({tamanho_cpf})</h1><a href='/cadastro'>Voltar</a>"

        cpf = cpf_enviado 
        telefone = request.form.get('telefone')
        senha = request.form.get('senha')
        repetir_senha = request.form.get('repetir_senha')

        if request.headers.getlist("X-Forwarded-For"):
            ip_cadastro = request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
        else:
            ip_cadastro = request.remote_addr

        if senha != repetir_senha:
            return "<h1>Senhas não coincidem!</h1><a href='/cadastro'>Voltar</a>"

        senha_bytes = senha.encode('utf-8')
        salt = bcrypt.gensalt()
        senha_criptografada = bcrypt.hashpw(senha_bytes, salt).decode('utf-8')

        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            sql = """INSERT INTO usuario (num_usuario, nome, email, senha_hash, cpf, telefone, perfil, id_status, data, ip_origem) 
                     VALUES (%s, %s, %s, %s, %s, %s, 0, 1, CURDATE(), %s)"""
            
            valores = (num_usuario, nome, email, senha_criptografada, cpf, telefone, ip_cadastro)
            cursor.execute(sql, valores)
            conn.commit() 
            return redirect(url_for('login'))
        except Exception as e:
            print(f"Erro ao salvar no NEXUS: {e}")
            return f"<h1>Erro técnico ao salvar: {e}</h1>"
        finally:
            if cursor: try: cursor.close()
            except: pass
            if conn: try: conn.close()
            except: pass
            
    return render_template('cadastro.html')

# =========================================================================
# === MÓDULOS ADMINISTRATIVOS PROTEGIDOS POR ISOLAMENTO DE ROTAS ===
# =========================================================================
@app.route('/admin/desbloqueio')
def admin_desbloqueio():
    if 'user_id' not in session or int(session.get('perfil', 0)) != 1: 
        return redirect(url_for('login'))
    return render_template('desbloqueio.html')

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
    except Exception as e:
        print(f"Erro ao carregar usuários: {e}")
        return redirect(url_for('login'))
    finally:
        if cursor: try: cursor.close()
        except: pass
        if conn: try: conn.close()
        except: pass

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
    except Exception as e:
        print(f"Erro logs: {e}")
        return render_template('login.html', db_error=True)
    finally:
        if cursor: try: cursor.close()
        except: pass
        if conn: try: conn.close()
        except: pass

# =========================================================================
# === SISTEMA DE ENDPOINTS: CONSULTA DINÂMICA DE RASTREAMENTO ===
# =========================================================================
@app.route('/buscar_ip_bloqueio', methods=['POST'])
def buscar_ip_bloqueio():
    if 'user_id' not in session or int(session.get('perfil', 0)) != 1:
        return jsonify({'ip': 'ACESSO NEGADO'}), 403

    conn = None
    cursor = None
    try:
        dados = request.get_json()
        id_usuario = dados.get('id') if dados else None
        
        if not id_usuario:
            return jsonify({'ip': 'ID NÃO INFORMADO'})
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT ultimo_ip_bloqueio FROM usuario WHERE num_usuario = %s", (id_usuario,))
        resultado = cursor.fetchone()
        
        if resultado and resultado['ultimo_ip_bloqueio']:
            return jsonify({'ip': resultado['ultimo_ip_bloqueio']})
        return jsonify({'ip': 'IP DESCONHECIDO'})
    except Exception as e:
        print(f"Erro ao buscar IP: {e}")
        return jsonify({'ip': 'ERRO NO SERVIDOR'})
    finally:
        if cursor: try: cursor.close()
        except: pass
        if conn: try: conn.close()
        except: pass

@app.route('/finalizar_desbloqueio', methods=['POST'])
def finalizar_desbloqueio():
    if 'user_id' not in session or int(session.get('perfil', 0)) != 1:
        return redirect(url_for('login'))

    id_usuario = request.form.get('id_usuario')
    sigla_responsavel = request.form.get('responsavel')

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE usuario 
            SET id_status = 1, 
                tentativas = 0, 
                ultimo_ip_bloqueio = NULL,
                responsavel_desbloqueio = %s 
            WHERE num_usuario = %s
        """, (sigla_responsavel, id_usuario))
        conn.commit()
    except Exception as e:
        if conn: conn.rollback()
        print(f"Erro no desbloqueio: {e}")
    finally:
        if cursor: try: cursor.close()
        except: pass
        if conn: try: conn.close()
        except: pass 
    
    return redirect(url_for('admin_usuarios'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/recuperacao', methods=['GET', 'POST'])
def recuperacao():
    if request.method == 'POST':
        return redirect(url_for('login'))
    return render_template('recuperacao.html')

if __name__ == '__main__':
    app.run(debug=True, port=8080)