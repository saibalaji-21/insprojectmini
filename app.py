from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from Crypto.Cipher import AES
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.PublicKey import DSA
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import json

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<User {self.username}>'

# Create database tables
with app.app_context():
    db.create_all()

# Crypto setup
AES_KEY = os.urandom(16)
DSA_KEY = DSA.generate(2048)
PUBLIC_KEY = DSA_KEY.publickey()

def encrypt_data(data):
    cipher = AES.new(AES_KEY, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return nonce.hex(), ciphertext.hex(), tag.hex()

def decrypt_data(nonce, ciphertext, tag):
    cipher = AES.new(AES_KEY, AES.MODE_EAX, nonce=bytes.fromhex(nonce))
    data = cipher.decrypt_and_verify(bytes.fromhex(ciphertext), bytes.fromhex(tag))
    return data.decode()

def sign_data(data):
    hash_obj = SHA256.new(data.encode())
    signer = DSS.new(DSA_KEY, 'fips-186-3')
    signature = signer.sign(hash_obj)
    return signature.hex()

def verify_signature(data, signature):
    hash_obj = SHA256.new(data.encode())
    verifier = DSS.new(PUBLIC_KEY, 'fips-186-3')
    try:
        verifier.verify(hash_obj, bytes.fromhex(signature))
        return True
    except ValueError:
        return False

def log_signature_action(username, action, status, data=None):
    log = {
        "timestamp": datetime.now().isoformat(),
        "user": username,
        "action": action,
        "status": status,
        "message": data
    }
    with open("signature_logs.json", "a") as f:
        f.write(json.dumps(log) + "\n")

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user'] = username
            flash('You were successfully logged in!', 'success')
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password', 'danger')
    
    return render_template("login.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Basic validation
        if not username or not password:
            flash('Username and password are required', 'danger')
        elif password != confirm_password:
            flash('Passwords do not match', 'danger')
        elif User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
        else:
            # Create new user
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password_hash=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
    
    return render_template("register.html")

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    status = ""
    message = ""
    signature = ""

    if request.method == 'POST':
        action = request.form['action']
        message = request.form['message']

        if action == "sign":
            signature = sign_data(message)
            status = "Message signed!"
            log_signature_action(session['user'], "sign", "success", message)

        elif action == "tamper":
            message += " Namaskara [tampered]"
            status = "Message tampered!"

        elif action == "verify":
            sig = request.form.get('signature')
            if sig and verify_signature(message, sig):
                status = "✅ Signature is valid."
                log_signature_action(session['user'], "verify", "valid", message)
            else:
                status = "❌ Signature is invalid."
                log_signature_action(session['user'], "verify", "invalid", message)

    return render_template("dashboard.html", 
                         message=message, 
                         signature=signature, 
                         status=status,
                         username=session['user'])

if __name__ == '__main__':
    app.run(debug=True)