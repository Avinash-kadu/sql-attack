from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session, abort
import joblib
import psycopg2
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import os
from config import DATABASE_CONFIG
import re

app = Flask(__name__)
app.config.from_pyfile('config.py')

# Load the model and the fitted vectorizer
model = joblib.load(
    r'C:\Users\Jagoda\Desktop\bezpieczenstwo-piatek\Models\sql_injection_model.pkl')
vectorizer = joblib.load(
    r'C:\Users\Jagoda\Desktop\bezpieczenstwo-piatek\Models\vectorizer.pkl')

conn = psycopg2.connect(**DATABASE_CONFIG)
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP,
    query TEXT,
    is_sql_injection BOOLEAN,
    injection_type TEXT
)
''')
conn.commit()


def is_sql_injection(query):
    query_tfidf = vectorizer.transform([query])
    prediction = model.predict(query_tfidf)[0]
    return bool(prediction)


def classify_sql_injection(query):
    union_based_patterns = [
        r"(?i)\bUNION\b\s+\bSELECT\b",  # UNION SELECT pattern
    ]

    boolean_based_patterns = [
        # AND condition with string comparison
        r"(?i)\bAND\b\s*'[^']*'='[^']*'\s*(?:--|#)?",
        # OR condition with string comparison
        r"(?i)\bOR\b\s*'[^']*'='[^']*'\s*(?:--|#)?",
        # AND condition with integer comparison
        r"(?i)\bAND\b\s*\d+\s*=\s*\d+\s*(?:--|#)?",
        # OR condition with integer comparison
        r"(?i)\bOR\b\s*\d+\s*=\s*\d+\s*(?:--|#)?",
    ]

    time_based_patterns = [
        r"(?i)\bSLEEP\(\d+\)",           # SLEEP function
        r"(?i)\bpg_sleep\(\d+\)",        # pg_sleep function
    ]

    out_of_band_patterns = [
        # INTO OUTFILE pattern
        r"(?i)\b(SELECT|UPDATE|DELETE|INSERT)\b\s+\w+\s+(?i)INTO\b\s+(?i)OUTFILE\b",
        # INTO DUMPFILE pattern
        r"(?i)\b(SELECT|UPDATE|DELETE|INSERT)\b\s+\w+\s+(?i)INTO\b\s+(?i)DUMPFILE\b",
        r"(?i)\b(?:SELECT|UPDATE|DELETE|INSERT)\b\s+(?:[\w.]+|\*)\s+(?i)INTO(?:\s+OUTFILE\s+|\s+DUMPFILE\s+|[^)]*?\b(?:T\d{2,}|W\d{2,}))",
        r"(?i)\b(?:SELECT|UPDATE|DELETE|INSERT)\b\s+(?:[\w.]+|\*)\s+(?i)INTO(?:\s+DUMPFILE\s+|\s+OUTFILE\s+|[^)]*?\b(?:T\d{2,}|W\d{2,}))",
        r"(?i)\b(?:SELECT|UPDATE|DELETE|INSERT)\b\s+(?:[\w.]+|\*)\s+(?i)INTO(?:\s+DUMPFILE\s+|\s+OUTFILE\s+|[^)]*?\b(?:T\d{2,}|W\d{2,}))",
    ]

    error_based_patterns = [
        r"(?i)'.*?(?:--|#)",  # Single quote followed by comment
        r'(?i)".*?(?:--|#)',  # Double quote followed by comment
        # AND condition with integer comparison
        r"(?i)\bAND\b\s*\d+\s*=\s*\d+\s*(?:--|#)?",
        # OR condition with integer comparison
        r"(?i)\bOR\b\s*\d+\s*=\s*\d+\s*(?:--|#)?",
    ]

    if any(re.search(pattern, query) for pattern in union_based_patterns):
        return "Union-based SQLi"

    if any(re.search(pattern, query) for pattern in boolean_based_patterns):
        return "Boolean-based Blind SQLi"

    if any(re.search(pattern, query) for pattern in time_based_patterns):
        return "Time-based Blind SQLi"

    if any(re.search(pattern, query) for pattern in out_of_band_patterns):
        return "Out-of-band SQLi"

    if any(re.search(pattern, query) for pattern in error_based_patterns):
        return "Error-based SQLi"

    return "Unknown"


def log_attempt(query, is_sql_injection, injection_type):
    cursor.execute('''
    INSERT INTO logs (timestamp, query, is_sql_injection, injection_type)
    VALUES (%s, %s, %s, %s)
    ''', (datetime.now(), query, is_sql_injection, injection_type))
    conn.commit()
    # Log to terminal
    print(
        f"Query: {query}, Wykryto SQL Injection: {is_sql_injection}, Type: {injection_type}")


def detect_and_log_request():
    for key, value in request.form.items():  # Check if the request contains potential SQL injection
        if is_sql_injection(value):
            injection_type = classify_sql_injection(value)
            log_attempt(value, True, injection_type)
            abort(400, description=f"Wykryto SQL Injection: {injection_type}")
    for key, value in request.args.items():
        if is_sql_injection(value):
            injection_type = classify_sql_injection(value)
            log_attempt(value, True, injection_type)
            abort(400, description=f"Wykryto SQL Injection: {injection_type}")


@app.before_request
def before_request():
    if request.method in ['POST', 'GET']:
        detect_and_log_request()


@app.route('/register', methods=['GET', 'POST'])
def register():
    sql_injection_detected = False

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if is_sql_injection(username) or is_sql_injection(password):
            sql_injection_detected = True
        else:
            hashed_password = generate_password_hash(
                password, method='pbkdf2:sha256')
            try:
                cursor.execute('''
                INSERT INTO users (username, password) VALUES (%s, %s)
                ''', (username, hashed_password))
                conn.commit()
                flash('Zarejestrowano pomyślnie.', 'success')
                return redirect(url_for('login'))
            except psycopg2.IntegrityError as e:
                conn.rollback()
                if 'unique constraint' in str(e):
                    flash('Użytownik już istnieje.', 'danger')
                else:
                    flash(
                        'Wystąpił problem przy rejestracji, spróbuj później.', 'danger')

    return render_template('register.html', sql_injection_detected=sql_injection_detected)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cursor.execute('''
        SELECT * FROM users WHERE username = %s
        ''', (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user[2], password):
            session['username'] = username
            flash('Zalogowano pomyślnie!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Nieprawidłowy login lub hasło!', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Poprawnie wylogowano.', 'info')
    return redirect(url_for('login'))


@app.route('/')
def dashboard():
    if 'username' in session:
        logged_in = True
        cursor.execute('SELECT * FROM logs')
        logs = cursor.fetchall()
    else:
        logged_in = False
        logs = []
    return render_template('dashboard.html', logged_in=logged_in, logs=logs)


@app.route('/check_query', methods=['POST'])
def check_query():
    data = request.json
    query = data.get('query', '')

    is_injection = is_sql_injection(query)
    injection_type = classify_sql_injection(query)
    log_attempt(query, is_injection, injection_type)

    if is_injection:
        return jsonify({'error': f'Wykryto atak typu SQL Injection: {injection_type}'}), 400

    return jsonify({'is_sql_injection': "Zapytanie bezpieczne"})


@app.route('/logs', methods=['GET'])
def get_logs():
    if 'username' in session:
        cursor.execute('SELECT * FROM logs')
        logs = cursor.fetchall()
        return jsonify(logs)
    else:
        return jsonify({'error': 'Nieautoryzowany dostep'}), 401


if __name__ == '__main__':
    app.run(debug=True)
