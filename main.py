from flask import Flask, request, abort
import re
app = Flask(__name__)

# Function to detect SQL Injection
def detect_sql_injection(req_data):
    sql_keywords = ["DROP", "UNION", "SELECT", "INSERT", "DELETE", "--", "' OR 1=1", ";"]
    pattern = re.compile('|'.join(sql_keywords), re.IGNORECASE)
    if pattern.search(req_data):
        return True
    return False

# Function to detect XSS
def detect_xss(req_data):
    xss_patterns = ["<script>", "</script>", "onerror=", "onload=", "onmouseover=", "onfocus=", "onclick="]
    pattern = re.compile('|'.join(xss_patterns), re.IGNORECASE)
    if pattern.search(req_data):
        return True
    return False

# Function to detect Directory Traversal
def detect_directory_traversal(req_data):
    if "../" in req_data or "..\\" in req_data:
        return True
    return False

# Function to implement Rate Limiting (basic example)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["5 per 10 seconds"]
)

@app.route("/", methods=["GET", "POST"])
@limiter.limit("5 per 10 seconds")
def index():
    req_data = request.args.get('input', '') + request.form.get('input', '')

    if detect_sql_injection(req_data):
        abort(400, description="SQL Injection detected.")
    if detect_xss(req_data):
        abort(400, description="XSS attack detected.")
    if detect_directory_traversal(req_data):
        abort(400, description="Directory traversal attempt detected.")

    return "Request is clean."

if __name__ == "__main__":
    app.run(debug=True)
