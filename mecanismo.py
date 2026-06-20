from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import mysql.connector
from datetime import datetime
import bcrypt  # <--- Biblioteca responsável por gerar hashes seguros de senha

app = Flask(__name__, template_folder='html', static_folder='css')
app.secret_key = 'chave_secreta_para_seguranca'

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
    conn = None
    cursor = None
    try:
        if request.method == 'POST':
            email = request.form.get('email')
            senha = request.form.get('senha')
            
            # === CAPTURA DE TELEMETRIA AVANÇADA (AGENT USUÁRIO E REDE) ===
            if request.headers.getlist("X-Forwarded-For"):
                ip_atual = request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
            else:
                ip_atual = request.remote_addr

            agente_usuario = request.headers.get('User-Agent', 'Desconhecido')

            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            
            # 🔍 PASSO 1: Consulta PRIMEIRO a existência do usuário para evitar quebra de integridade (FK)
            cursor.execute("SELECT * FROM usuario WHERE email = %s", (email,))
            user = cursor.fetchone()
            
            # 1️⃣ CENÁRIO A: O e-mail digitado NÃO existe no banco de dados
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

            # Se o usuário existe, extraímos as variáveis de histórico de tentativas de forma segura
            id_usuario_log = user['num_usuario']
            numero_tentativa_log = user['tentativas'] + 1

            # 🔍 PASSO 2: Persistência na tabela 'login' apenas para usuários válidos existentes
            try:
                sql_log_login = """
                    INSERT INTO login (num_tentativa, ip_origem, agente_usuario, num_usuario, data) 
                    VALUES (%s, %s, %s, %s, CURDATE())
                """
                cursor.execute(sql_log_login, (numero_tentativa_log, ip_atual, agente_usuario, id_usuario_log))
                conn.commit()
            except mysql.connector.Error as err_log:
                print(f"[AVISO DE BANCO] Falha não impeditiva ao gravar histórico de login: {err_log}")

            # 2️⃣ CENÁRIO B: O usuário existe mas já se encontra bloqueado pelo sistema
            if user.get('id_status') == 2:
                return render_template('login.html', bloqueado=True, email_digitado=email, trava_demo=True)

            # 🔍 PASSO 3: Validação criptográfica do hash de senha via Bcrypt
            senha_digitada_bytes = senha.encode('utf-8')
            senha_banco_bytes = user['senha_hash'].encode('utf-8')

            if bcrypt.checkpw(senha_digitada_bytes, senha_banco_bytes):
                # SUCESSO: Reseta o contador de falhas acumuladas do usuário
                cursor.execute("UPDATE usuario SET tentativas = 0 WHERE email = %s", (email,))
                
                # Gravando o log forense de atividade bem-sucedida (Usando NULL na FK para evitar crash de restrição)
                agora = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
                sql_sucesso_log = """
                    INSERT INTO log_atividade (descricao, id_status, id_tipo, num_tentativa)
                    VALUES (%s, 1, 1, NULL)
                """
                msg_sucesso = f"LOGIN: Acesso concedido e autenticado para o usuario {email} em {agora}."
                cursor.execute(sql_sucesso_log, (msg_sucesso,))
                conn.commit()
                
                # Alocação limpa de chaves de privilégio na Sessão do Flask
                session.permanent = False
                session['user_id'] = user['num_usuario']
                session['user_nome'] = user['nome']
                session['perfil'] = user.get('perfil', 0)
                
                # Fechamento manual imediato antes do redirecionamento de rota para liberar o pool
                cursor.close()
                conn.close()
                
                if session['perfil'] == 1:
                    return redirect(url_for('admin_desbloqueio'))
                else:
                    return redirect('https://www.google.com')
            
            # 3️⃣ CENÁRIO C: O e-mail existe, mas a senha está incorreta
            else:
                novas_tentativas = user['tentativas'] + 1
                
                if novas_tentativas >= 5:
                    # Aplica bloqueio lógico imediato na tabela pai 'usuario'
                    cursor.execute("""
                        UPDATE usuario 
                        SET tentativas = %s, id_status = 2, ultimo_ip_bloqueio = %s 
                        WHERE email = %s
                    """, (novas_tentativas, ip_atual, email))
                    
                    # Alimenta a tabela histórica de bloqueio
                    try:
                        sql_historico_bloqueio = """
                            INSERT INTO bloqueio (data, num_tentativa, motivo) 
                            VALUES (CURDATE(), %s, %s)
                        """
                        motivo_bloqueio = "Excesso de tentativas de login (Brute-Force)"
                        cursor.execute(sql_historico_bloqueio, (novas_tentativas, motivo_bloqueio))
                    except Exception as e_blq:
                        print(f"[AVISO DE BANCO] Falha ao persistir na tabela bloqueio: {e_blq}")
                    
                    # Persiste a auditoria de incidente de segurança na tabela de atividades
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
                    # Apenas incrementa uma falha no contador do usuário
                    cursor.execute("UPDATE usuario SET tentativas = %s WHERE email = %s", (novas_tentativas, email))
                    
                    # Adiciona log descritivo de falha intermediária
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
        # O bloco finally garante que, caso a requisição saia por qualquer return de erro ou aviso, as conexões fechem
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
            return f"<h1>Erro de Validação: O CPF deve conter entre 11 e 14 caracteres! (Digitado: {tamanho_cpf})</h1><a href='/cadastro'>Voltar</a>"

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
# === MÓDULOS ADMINISTRATIVOS PROTEGIDOS POR ISOLAMENTO DE ROTAS ===
# =========================================================================
@app.route('/admin/desbloqueio')
def admin_desbloqueio():
    # === BARREIRA DE PROTEÇÃO CONTRA ELEMENTOS EXTERNOS (TRAVA DE URL) ===
    if 'user_id' not in session or session.get('perfil') != 1: 
        conn = None
        cursor = None
        try:
            agora = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
            quem_tentou = f"Usuario ID #{session['user_id']}" if 'user_id' in session else "Acesso Anonimo"
            
            conn = get_db_connection()
            cursor = conn.cursor()
            sql_negado = "INSERT INTO log_atividade (descricao, id_status, id_tipo, num_tentativa) VALUES (%s, 2, 2, NULL)"
            msg_negado = f"ACESSO NEGADO: {quem_tentou} tentou forcar entrada na rota /admin/desbloqueio em {agora}"
            cursor.execute(sql_negado, (msg_negado,))
            conn.commit()
        except Exception as e_log:
            # Imprime o erro no console para você saber o que houve sem travar o usuário
            print(f"[AVISO BANCO] Erro ao registrar auditoria de invasao: {e_log}")
        finally:
            # O bloco finally executa SEMPRE, limpando os problemas do VS Code
            if cursor:
                try: cursor.close()
                except: pass
            if conn:
                try: conn.close()
                except: pass
        return redirect(url_for('login'))
        
    return render_template('desbloqueio.html')

@app.route('/admin/log_atividade')
def admin_log_activity():
    if 'user_id' not in session or session.get('perfil') != 1:
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
    if 'user_id' not in session or session.get('perfil') != 1:
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
    
    cursor.execute("SELECT num_usuario, nome, email, perfil, id_status, ip_origem, ultimo_ip_bloqueio, responsavel_desbloqueio FROM usuario")
    usuarios_banco = cursor.fetchall()
    conn.close()

    return render_template('usuario.html', lista=usuarios_banco)

# =========================================================================
# === SISTEMA DE ENDPOINTS: CONSULTA DINÂMICA DE RASTREAMENTO ===
# =========================================================================
@app.route('/buscar_ip_bloqueio', methods=['POST'])
def buscar_ip_bloqueio():
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
    if 'user_id' not in session or session.get('perfil') != 1:
        return redirect(url_for('login'))

    id_usuario = request.form.get('id_usuario')
    sigla_responsavel = request.form.get('responsavel')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("SELECT num_bloqueio FROM bloqueio ORDER BY data DESC, num_bloqueio DESC LIMIT 1")
        registro_bloqueio = cursor.fetchone()
        id_bloqueio_vinculado = registro_bloqueio['num_bloqueio'] if registro_bloqueio else None

        cursor.execute("""
            UPDATE usuario 
            SET id_status = 1, 
                tentativas = 0, 
                ultimo_ip_bloqueio = NULL,
                responsavel_desbloqueio = %s 
            WHERE num_usuario = %s
        """, (sigla_responsavel, id_usuario))
        
        sql_historico = """
            INSERT INTO desbloqueio (data, usuario_responsavel, num_bloqueio) 
            VALUES (CURDATE(), %s, %s)
        """
        cursor.execute(sql_historico, (sigla_responsavel, id_bloqueio_vinculado))
        
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
        conn.rollback()
        print(f"[ERRO CRÍTICO CRASH] Falha ao sincronizar tabelas de desbloqueio: {e}")
        
    finally:
        cursor.close()
        conn.close() 
    
    return redirect(url_for('admin_usuarios'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/recuperacao', methods=['GET', 'POST'])
def recuperacao():
    if request.method == 'POST':
        email = request.form.get('email')
        print(f"[NEXUS LOG] Solicitação de recuperação para o e-mail: {email}")
        return redirect(url_for('login'))
        
    return render_template('recuperacao.html')

if __name__ == '__main__':
    app.run(debug=True, port=8080)