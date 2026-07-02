"""
Intentionally vulnerable Python file for Checkmarx SAST testing.
Contains multiple CWE patterns that Checkmarx SAST will detect as Code Weaknesses.

DO NOT USE IN PRODUCTION - This file is for testing purposes only.
"""

import os
import subprocess
import sqlite3
import pickle
import hashlib
import yaml
import xml.etree.ElementTree as ET
from flask import Flask, request, redirect, render_template_string, send_file, jsonify

app = Flask(__name__)

# ============================================================================
# CWE-89: SQL Injection
# ============================================================================
@app.route('/users')
def get_user():
    """SQL Injection - user input directly concatenated into SQL query."""
    username = request.args.get('username')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # VULNERABLE: Direct string concatenation in SQL query
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return str(results)


@app.route('/search')
def search_users():
    """SQL Injection via f-string formatting."""
    search_term = request.args.get('q')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # VULNERABLE: f-string in SQL query
    cursor.execute(f"SELECT * FROM users WHERE name LIKE '%{search_term}%'")
    results = cursor.fetchall()
    conn.close()
    return str(results)


# ============================================================================
# CWE-78: OS Command Injection
# ============================================================================
@app.route('/ping')
def ping_host():
    """Command Injection - user input passed directly to shell command."""
    host = request.args.get('host')
    # VULNERABLE: User input in shell command
    result = os.popen('ping -c 1 ' + host).read()
    return result


@app.route('/execute')
def execute_command():
    """Command Injection via subprocess with shell=True."""
    cmd = request.args.get('cmd')
    # VULNERABLE: User input passed to subprocess with shell=True
    output = subprocess.check_output(cmd, shell=True)
    return output


# ============================================================================
# CWE-79: Cross-Site Scripting (XSS)
# ============================================================================
@app.route('/greet')
def greet():
    """Reflected XSS - user input rendered directly in HTML response."""
    name = request.args.get('name', 'World')
    # VULNERABLE: User input directly in HTML without escaping
    return f"<html><body><h1>Hello, {name}!</h1></body></html>"


@app.route('/profile')
def profile():
    """Stored XSS via render_template_string."""
    bio = request.args.get('bio', '')
    # VULNERABLE: User input in template string
    template = f"<html><body><div>{bio}</div></body></html>"
    return render_template_string(template)


# ============================================================================
# CWE-22: Path Traversal
# ============================================================================
@app.route('/download')
def download_file():
    """Path Traversal - user input used directly as file path."""
    filename = request.args.get('file')
    # VULNERABLE: No path validation, allows ../../../etc/passwd
    return send_file('/uploads/' + filename)


@app.route('/read')
def read_file():
    """Path Traversal via open()."""
    filepath = request.args.get('path')
    # VULNERABLE: User-controlled file path
    with open(filepath, 'r') as f:
        content = f.read()
    return content


# ============================================================================
# CWE-502: Unsafe Deserialization
# ============================================================================
@app.route('/load', methods=['POST'])
def load_data():
    """Unsafe deserialization of user-supplied data."""
    data = request.get_data()
    # VULNERABLE: Deserializing untrusted data with pickle
    obj = pickle.loads(data)
    return str(obj)


@app.route('/load_yaml', methods=['POST'])
def load_yaml_data():
    """Unsafe YAML deserialization."""
    data = request.get_data(as_text=True)
    # VULNERABLE: yaml.load without SafeLoader allows arbitrary code execution
    parsed = yaml.load(data)
    return str(parsed)


# ============================================================================
# CWE-611: XML External Entity (XXE) Injection
# ============================================================================
@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    """XXE Injection - parsing XML without disabling external entities."""
    xml_data = request.get_data(as_text=True)
    # VULNERABLE: XML parsing without disabling external entities
    root = ET.fromstring(xml_data)
    return ET.tostring(root, encoding='unicode')


# ============================================================================
# CWE-327: Use of Broken Cryptographic Algorithm
# ============================================================================
@app.route('/hash')
def hash_password():
    """Weak cryptographic hash - MD5 is broken for password hashing."""
    password = request.args.get('password')
    # VULNERABLE: MD5 is cryptographically broken
    hashed = hashlib.md5(password.encode()).hexdigest()
    return jsonify({'hash': hashed})


@app.route('/hash_sha1')
def hash_sha1():
    """Weak cryptographic hash - SHA1 is deprecated."""
    data = request.args.get('data')
    # VULNERABLE: SHA1 is deprecated for security purposes
    hashed = hashlib.sha1(data.encode()).hexdigest()
    return jsonify({'hash': hashed})


# ============================================================================
# CWE-798: Hardcoded Credentials
# ============================================================================
# VULNERABLE: Hardcoded database credentials
DB_HOST = "production-db.example.com"
DB_USER = "admin"
DB_PASSWORD = "SuperSecret123!"
API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"


def connect_to_database():
    """Hardcoded credentials in source code."""
    import pymysql
    # VULNERABLE: Hardcoded credentials
    connection = pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database='production'
    )
    return connection


# ============================================================================
# CWE-918: Server-Side Request Forgery (SSRF)
# ============================================================================
@app.route('/fetch')
def fetch_url():
    """SSRF - user-controlled URL in server-side request."""
    import requests
    url = request.args.get('url')
    # VULNERABLE: User-controlled URL without validation
    response = requests.get(url)
    return response.text


# ============================================================================
# CWE-601: Open Redirect
# ============================================================================
@app.route('/redirect')
def open_redirect():
    """Open Redirect - user-controlled redirect URL."""
    target = request.args.get('url')
    # VULNERABLE: Unvalidated redirect
    return redirect(target)


# ============================================================================
# CWE-209: Information Exposure Through Error Messages
# ============================================================================
@app.route('/debug')
def debug_endpoint():
    """Information exposure - detailed error messages to user."""
    try:
        data = request.args.get('data')
        result = eval(data)  # CWE-95: Eval injection too
        return str(result)
    except Exception as e:
        # VULNERABLE: Exposing stack trace and internal details
        import traceback
        return f"<pre>Error: {str(e)}\n\n{traceback.format_exc()}</pre>", 500


# ============================================================================
# CWE-312: Cleartext Storage of Sensitive Information
# ============================================================================
@app.route('/log_login', methods=['POST'])
def log_login():
    """Logging sensitive data in cleartext."""
    username = request.form.get('username')
    password = request.form.get('password')
    # VULNERABLE: Logging password in cleartext
    print(f"Login attempt: user={username}, password={password}")
    app.logger.info(f"User login: {username} with password {password}")
    return "OK"


if __name__ == '__main__':
    # VULNERABLE: Debug mode enabled in production
    app.run(debug=True, host='0.0.0.0', port=5000)
