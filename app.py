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
                  paid INTEGER DEFAULT 0)''')
    
    # Tabela de Faturas (IDOR)
    c.execute('''CREATE TABLE IF NOT EXISTS invoices
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  amount REAL NOT NULL,
                  description TEXT,
                  flag TEXT,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    # Tabela de Configurações Administrativas (Oculta)
    c.execute('''CREATE TABLE IF NOT EXISTS admin_settings
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  setting_key TEXT UNIQUE NOT NULL,
                  setting_value TEXT)''')

    # Inserir dados iniciais (Simulando migração de DB)
    # Admin: admin / admin123
    # Usuário: user1 / user123
    admin_pw = generate_password_hash('admin123')
    user_pw = generate_password_hash('user123')
    
    try:
        c.execute("INSERT OR REPLACE INTO users (id, username, email, password, role, paid) VALUES (?, ?, ?, ?, ?, ?)",
                  (1, 'admin', 'admin@securecorp.com', admin_pw, 'admin', 1))
        c.execute("INSERT OR REPLACE INTO users (id, username, email, password, role, paid) VALUES (?, ?, ?, ?, ?, ?)",
                  (2, 'user1', 'user1@example.com', user_pw, 'user', 0))
        
        # Dados para IDOR
        c.execute("INSERT OR REPLACE INTO invoices (id, user_id, amount, description) VALUES (?, ?, ?, ?)",
                  (1, 2, 150.00, 'Serviços de Consultoria Jan/2026'))
        c.execute("INSERT OR REPLACE INTO invoices (id, user_id, amount, description, flag) VALUES (?, ?, ?, ?, ?)",
                  (2, 1, 5000.00, 'Pagamento Secreto de Infraestrutura', 'FLAG{IDOR_INVOICE_EXPOSED_8829}'))
        
        # Dados para Endpoints Ocultos
        c.execute("INSERT OR REPLACE INTO admin_settings (id, setting_key, setting_value) VALUES (?, ?, ?)",
                  (1, 'AWS_SECRET_KEY', 'AKIA_SECURECORP_FLAG{HIDDEN_ENDPOINT_ACCESS_7721}'))
        c.execute("INSERT OR REPLACE INTO admin_settings (id, setting_key, setting_value) VALUES (?, ?, ?)",
                  (2, 'BACKUP_SERVER_IP', '10.0.0.55'))
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
            return redirect(url_for('dashboard'))
        flash('Credenciais inválidas')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
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

# --- ENDPOINTS VULNERÁVEIS (BAC) ---

@app.route('/api/v1/invoice/<int:invoice_id>')
def get_invoice(invoice_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    db = get_db()
    invoice = db.execute('SELECT * FROM invoices WHERE id = ?', (invoice_id,)).fetchone()
    db.close()
    
    if invoice:
        return jsonify(dict(invoice))
    return jsonify({'error': 'Not found'}), 404

@app.route('/api/admin/settings')
def get_admin_settings():
    """VULNERABILIDADE: Endpoint oculto que não verifica o papel de admin.
    Qualquer usuário logado pode acessar se souber o caminho."""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    db = get_db()
    settings = db.execute('SELECT * FROM admin_settings').fetchall()
    db.close()
    
    return jsonify([dict(s) for s in settings])

@app.route('/api/user/paid-status')
def get_paid_status():
    """VULNERABILIDADE: O frontend confia cegamente nesta resposta.
    O atacante pode interceptar e mudar 'paid: 0' para 'paid: 1'."""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    db = get_db()
    user = db.execute('SELECT paid FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    db.close()
    
    return jsonify({'paid': user['paid']})

@app.route('/premium-content')
def premium_content():
    """Página de conteúdo premium que deve ser protegida."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('premium.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
