"""INTENTIONALLY INSECURE demo code.

This file exists only so the security scanner has something to find.
Never copy these patterns into real code.
"""
import hashlib
import sqlite3
import subprocess

import yaml


def find_user(name):
    conn = sqlite3.connect("users.db")
    # SQL injection: string-built query
    return conn.execute("SELECT * FROM users WHERE name = '%s'" % name).fetchall()


def run_command(user_input):
    # Command injection: shell=True with user input
    return subprocess.run("ls " + user_input, shell=True)


def hash_password(password):
    # Weak hash
    return hashlib.md5(password.encode()).hexdigest()


def load_config(text):
    # Unsafe deserialization
    return yaml.load(text, Loader=yaml.Loader)


def run_code(expr):
    # Arbitrary code execution
    return eval(expr)
