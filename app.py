from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

DATABASE = 'securecorp.db'

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Tabela de Usuários
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  email TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  role TEXT DEFAULT 'user',
                  is_premium INTEGER DEFAULT 0)''')
    
    # Tabela de Faturas (IDOR)
    c.execute('''CREATE TABLE IF NOT EXISTS invoices
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  amount REAL NOT NULL,
                  description TEXT,
                  flag TEXT,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    # Tabela de Configurações Globais
    c.execute('''CREATE TABLE IF NOT EXISTS global_settings
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  config_name TEXT UNIQUE NOT NULL,
                  config_value TEXT)''')

    # Inserir dados iniciais (Simulando migração de DB)
    # TODO: Mover credenciais para variáveis de ambiente em produção.
    # Credenciais temporárias para teste:
    # Admin: admin / admin123
    # Usuário: user1 / user123
    admin_pw = generate_password_hash('admin123')
    user_pw = generate_password_hash('user123')
    
    try:
        c.execute("INSERT INTO users (username, email, password, role, is_premium) VALUES (?, ?, ?, ?, ?)",
                  ('admin', 'admin@securecorp.com', admin_pw, 'admin', 1))
        c.execute("INSERT INTO users (username, email, password, role, is_premium) VALUES (?, ?, ?, ?, ?)",
                  ('user1', 'user1@example.com', user_pw, 'user', 0))
        
        user_id = 2
        c.execute("INSERT INTO invoices (user_id, amount, description) VALUES (?, ?, ?)",
                  (user_id, 150.00, 'Serviços de Consultoria Jan/2026'))
        
        # Fatura de outro usuário (IDOR Target)
        c.execute("INSERT INTO invoices (user_id, amount, description, flag) VALUES (?, ?, ?, ?)",
                  (1, 5000.00, 'Pagamento Secreto de Infraestrutura', 'FLAG{IDOR_INVOICE_EXPOSED_8829}'))
        
        c.execute("INSERT INTO global_settings (config_name, config_value) VALUES (?, ?)",
                  ('AWS_SECRET_KEY', 'AKIA_SECURECORP_FLAG{SENSITIVE_EXPORT_UNPROTECTED_4421}'))
    except sqlite3.IntegrityError:
        pass
        
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        db.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['is_premium'] = user['is_premium']
            return redirect(url_for('dashboard'))
        flash('Credenciais inválidas')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        # VULNERABILIDADE: Aceita 'role' diretamente do formulário (Mass Assignment / Priv Esc)
        role = request.form.get('role', 'user') 
        
        db = get_db()
        try:
            db.execute('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
                       (username, email, generate_password_hash(password), role))
            db.commit()
            flash('Registro concluído!')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Usuário já existe')
        finally:
            db.close()
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/api/v1/invoice/<int:invoice_id>')
def get_invoice(invoice_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # VULNERABILIDADE: IDOR - Não verifica se a fatura pertence ao usuário logado
    db = get_db()
    invoice = db.execute('SELECT * FROM invoices WHERE id = ?', (invoice_id,)).fetchone()
    db.close()
    
    if invoice:
        return jsonify(dict(invoice))
    return jsonify({'error': 'Not found'}), 404

@app.route('/api/v1/settings/export')
def export_settings():
    # VULNERABILIDADE: Falta de verificação de papel (Role Check)
    # Apenas verifica se está logado, mas não se é admin
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    db = get_db()
    settings = db.execute('SELECT * FROM global_settings').fetchall()
    db.close()
    
    return jsonify([dict(s) for s in settings])

@app.route('/admin_panel')
def admin_panel():
    # VULNERABILIDADE: Bypass de autorização simples
    if session.get('role') != 'admin':
        return "Acesso Negado", 403
    return render_template('admin.html', flag="FLAG{ADMIN_PATH_BYPASS_7731}")

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
