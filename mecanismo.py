from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import mysql.connector
from datetime import datetime

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
    if 'user_id' in session:
        return redirect(url_for('admin_desbloqueio'))
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

                if user['senha_hash'] == senha:
                    cursor.execute("UPDATE usuario SET tentativas = 0 WHERE email = %s", (email,))
                    conn.commit()
                    session['user_id'] = user['num_usuario']
                    session['user_nome'] = user['nome']
                    session['perfil'] = user.get('perfil', 0)
                    return redirect(url_for('admin_desbloqueio') if session['perfil'] == 1 else 'https://www.google.com')
                
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
                        # Adicionado trava_demo para o momento do bloqueio
                        return render_template('login.html', bloqueado=True, email_digitado=email, trava_demo=True)
                    else:
                        cursor.execute("UPDATE usuario SET tentativas = %s WHERE email = %s", (novas_tentativas, email))
                        conn.commit()
                        # Adicionado trava_demo para erro simples de senha
                        return render_template('login.html', erro=True, email_digitado=email, trava_demo=True)
            else:
                # Adicionado trava_demo para usuário não encontrado (evita brute force de e-mails)
                return render_template('login.html', erro=True, email_digitado=email, trava_demo=True)
    except Exception as e:
        print(f"Erro: {e}")
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

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # 2. Comando SQL atualizado para incluir 'ip_origem'
            sql = """INSERT INTO usuario (num_usuario, nome, email, senha_hash, cpf, telefone, perfil, id_status, data, ip_origem) 
                     VALUES (%s, %s, %s, %s, %s, %s, 0, 1, CURDATE(), %s)"""
            
            # 3. Adicionando o ip_cadastro na tupla de valores (último %s)
            valores = (num_usuario, nome, email, senha, cpf, telefone, ip_cadastro)
            cursor.execute(sql, valores)
            
            # Grava os dados permanentemente
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
    if 'user_id' not in session: return redirect(url_for('login'))
    # ALTERAÇÃO: Nome do ficheiro atualizado para desbloqueio.html
    return render_template('desbloqueio.html')

@app.route('/admin/usuarios')
def admin_usuarios():
    # 1. Segurança: Verifica se quem está acessando é Admin
    if 'perfil' not in session or session['perfil'] != 1:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Puxa todas as colunas para garantir o funcionamento das bolinhas de status e IPs
    cursor.execute("SELECT * FROM usuario")
    
    usuarios_banco = cursor.fetchall()
    conn.close()

    return render_template('usuario.html', lista=usuarios_banco)

# =========================================================================
# NOVAS ROTAS: SISTEMA DE DESBLOQUEIO E RASTREIO DE IP
# =========================================================================

@app.route('/buscar_ip_bloqueio', methods=['POST'])
def buscar_ip_bloqueio():
    # ROTA ATUALIZADA: Busca o IP de Cadastro para conferência do Admin
    data = request.get_json()
    id_usuario = data.get('id')
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Alteramos a consulta para puxar o IP_ORIGEM
    cursor.execute("SELECT ip_origem FROM usuario WHERE num_usuario = %s", (id_usuario,))
    user = cursor.fetchone()
    conn.close()

    if user and user['ip_origem']:
        return jsonify({'ip': user['ip_origem']})
    
    # Caso seja um usuário antigo sem IP registrado ou ID inexistente
    return jsonify({'ip': 'Sem registro de IP de origem'})

@app.route('/finalizar_desbloqueio', methods=['POST'])
def finalizar_desbloqueio():
    # Rota que executa o desbloqueio real e limpa os rastros no banco
    id_usuario = request.form.get('id_usuario')
    # O motivo pode ser capturado aqui para logs futuros se necessário
    motivo = request.form.get('motivo') 

    conn = get_db_connection()
    cursor = conn.cursor()
    
    # RESET: Status volta a 1 (Ativo), zera tentativas e remove IP do bloqueio anterior
    cursor.execute("""
        UPDATE usuario 
        SET id_status = 1, tentativas = 0, ultimo_ip_bloqueio = NULL 
        WHERE num_usuario = %s
    """, (id_usuario,))
    
    conn.commit()
    conn.close()
    
    # Redireciona para a lista de utilizadores para validar a alteração visual
    return redirect(url_for('admin_usuarios'))

# =========================================================================
# ROTA DE RECUPERAÇÃO DE SENHA (NEXUS CORE)
# =========================================================================

@app.route('/recuperacao', methods=['GET', 'POST'])
def recuperacao():
    if request.method == 'POST':
        email = request.form.get('email')
        
        # Aqui no futuro você pode colocar a lógica de banco para verificar o e-mail,
        # mas para a sua demonstração, apenas redirecionar para o login funciona perfeito.
        print(f"[NEXUS LOG] Solicitação de recuperação para o e-mail: {email}")
        
        return redirect(url_for('login'))
        
    return render_template('recuperacao.html')

# =========================================================================

if __name__ == '__main__':
    app.run(debug=True, port=8080)