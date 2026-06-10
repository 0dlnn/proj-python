from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import mysql.connector
from datetime import datetime
import bcrypt  # <--- Biblioteca responsável por gerar hashes seguros de senha

app = Flask(__name__, template_folder='html', static_folder='css')
app.secret_key = 'chave_secreta_para_seguranca'

# === REGRA DE CYBERSECURITY: GERENCIAMENTO DE SESSÃO ATIVA ===
@app.before_request
def configurar_sessao():
    # Define que os dados de sessão (cookies) expiram imediatamente quando o navegador ou aba fecham,
    # impedindo que o usuário pule o login ao abrir o site novamente (Princípio de Privilégio Mínimo)
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
            
            if user:
                if user.get('id_status') == 2:
                    # Adicionado trava_demo para quando já está bloqueado
                    return render_template('login.html', bloqueado=True, email_digitado=email, trava_demo=True)

                # === COMPARAÇÃO DA SENHA CRIPTOGRAFADA VIA BACKEND ===
                # Converte as strings recebidas em bytes textuais e valida usando a regra interna do Bcrypt.
                # Se o registro no banco for antigo (texto limpo), o checkpw retornará falso de forma segura.
                senha_digitada_bytes = senha.encode('utf-8')
                senha_banco_bytes = user['senha_hash'].encode('utf-8')

                if bcrypt.checkpw(senha_digitada_bytes, senha_banco_bytes):
                    cursor.execute("UPDATE usuario SET tentativas = 0 WHERE email = %s", (email,))
                    conn.commit()
                    session['user_id'] = user['num_usuario']
                    session['user_nome'] = user['nome']
                    session['perfil'] = user.get('perfil', 0)
                    
                    # REGRA DE GOVERNANÇA: O roteamento é determinado estritamente pelas credenciais validadas no banco de dados.
                    # Perfil == 1 (Admin) acessa o dashboard; Perfil Comum é redirecionado para fora do escopo administrativo.
                    if session['perfil'] == 1:
                        return redirect(url_for('admin_desbloqueio'))
                    else:
                        return redirect('https://www.google.com')
                
                else:
                    novas_tentativas = user['tentativas'] + 1
                    
                    # CAPTURA DO IP REAL (Trata o proxy reverso do Render ou fallback local)
                    if request.headers.getlist("X-Forwarded-For"):
                        ip_atual = request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
                    else:
                        ip_atual = request.remote_addr
                    
                    if novas_tentativas >= 5:
                        # BLOQUEIO COM IP
                        cursor.execute("UPDATE usuario SET tentativas = %s, id_status = 2, ultimo_ip_bloqueio = %s WHERE email = %s", (novas_tentativas, ip_atual, email))
                        conn.commit()
                        return render_template('login.html', bloqueado=True, email_digitado=email, trava_demo=True)
                    else:
                        cursor.execute("UPDATE usuario SET tentativas = %s WHERE email = %s", (novas_tentativas, email))
                        conn.commit()
                        return render_template('login.html', erro=True, email_digitado=email, trava_demo=True)
            else:
                return render_template('login.html', erro=True, email_digitado=email, trava_demo=True)
    except Exception as e:
        print(f"Erro no login: {e}")
        return render_template('login.html', db_error=True)
        
    return render_template('login.html')

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        # 1. Captura os dados do formulário HTML
        num_usuario = request.form.get('num_usuario')
        nome = request.form.get('nome')
        email = request.form.get('email')
        cpf = request.form.get('cpf').replace('.', '').replace('-', '') 
        telefone = request.form.get('telefone')
        senha = request.form.get('senha')
        repetir_senha = request.form.get('repetir_senha')

        # CAPTURA O IP DE ORIGEM DO USUÁRIO (Trata o proxy reverso do Render ou fallback local)
        if request.headers.getlist("X-Forwarded-For"):
            ip_cadastro = request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
        else:
            ip_cadastro = request.remote_addr

        # Validação simples de segurança
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
            
            # CORREÇÃO: Alinhamento de colunas e marcadores %s (Eram 8 colunas mapeadas para 7 valores)
            sql = """INSERT INTO usuario (num_usuario, nome, email, senha_hash, cpf, telefone, perfil, id_status, data, ip_origem) 
                     VALUES (%s, %s, %s, %s, %s, %s, 0, 1, CURDATE(), %s)"""
            
            # Envia a senha mascarada, mantendo o CPF e Telefone normais em texto limpo
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
    
    # Busca com a auditoria de responsável incluída
    cursor.execute("SELECT num_usuario, nome, email, perfil, id_status, ip_origem, ultimo_ip_bloqueio, responsavel_desbloqueio FROM usuario")
    usuarios_banco = cursor.fetchall()
    conn.close()

    return render_template('usuario.html', lista=usuarios_banco)

# =========================================================================
# NOVAS ROTAS: SISTEMA DE DESBLOQUEIO E RASTREIO DE IP
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
        
        # Retorna o IP dinâmico ou o status limpo para o front-end
        if resultado and resultado['ultimo_ip_bloqueio']:
            return jsonify({'ip': resultado['ultimo_ip_bloqueio']})
        
        return jsonify({'ip': 'IP DESCONHECIDO'})
    except Exception as e:
        print(f"Erro ao buscar IP: {e}")
        return jsonify({'ip': 'ERRO NO SERVIDOR'})

@app.route('/finalizar_desbloqueio', methods=['POST'])
def finalizar_desbloqueio():
    # === VALIDAÇÃO DE AUTORIDADE EM BANCO ===
    # Protege a execução de comandos DML (UPDATE) para evitar injeções ou modificações arbitrárias.
    if 'user_id' not in session or session.get('perfil') != 1:
        return redirect(url_for('login'))

    id_usuario = request.form.get('id_usuario')
    sigla_responsavel = request.form.get('responsavel')

    conn = get_db_connection()
    cursor = conn.cursor()
    
    # RESET LÓGICO COMPLETO: Grava o responsável (LS, AR, EM) e limpa as travas
    cursor.execute("""
        UPDATE usuario 
        SET id_status = 1, 
            tentativas = 0, 
            ultimo_ip_bloqueio = NULL,
            responsavel_desbloqueio = %s 
        WHERE num_usuario = %s
    """, (sigla_responsavel, id_usuario))
    
    conn.commit()
    conn.close() 
    
    return redirect(url_for('admin_usuarios'))

# === ROTA ADICIONAL: ENCERRAMENTO SEGURO DE PRIVILÉGIOS (TERMINAÇÃO DE CONEXÃO) ===
@app.route('/logout')
def logout():
    # Destrói a sessão de forma segura limpando as chaves de acesso da memória RAM
    session.clear()
    return redirect(url_for('login'))

# =========================================================================
# ROTA DE RECUPERAÇÃO DE SENHA (NEXUS CORE)
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