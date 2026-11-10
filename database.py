import hashlib
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get('LAB_DB', str(ROOT / 'instance' / 'laboratorio.sqlite3')))


@contextmanager
def connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 220_000)
    return f'pbkdf2_sha256$220000${salt.hex()}${digest.hex()}'


def check_password(password, encoded):
    try:
        scheme, iterations, salt_hex, expected_hex = encoded.split('$')
        if scheme != 'pbkdf2_sha256':
            return False
        derived = hashlib.pbkdf2_hmac(
            'sha256', password.encode('utf-8'), bytes.fromhex(salt_hex), int(iterations)
        )
        return secrets.compare_digest(derived, bytes.fromhex(expected_hex))
    except (ValueError, TypeError):
        return False


def init_db(reset=False):
    if reset and DB_PATH.exists():
        DB_PATH.unlink()
    if reset and (DB_PATH.parent / 'admin_password.txt').exists():
        (DB_PATH.parent / 'admin_password.txt').unlink()
    with connection() as db:
        db.executescript('''
          CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('user','admin'))
          );
          CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY,
            owner_id INTEGER NOT NULL REFERENCES users(id),
            title TEXT NOT NULL,
            content TEXT NOT NULL
          );
          CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            csrf_token TEXT NOT NULL,
            expires_at INTEGER NOT NULL
          );
        ''')
        if db.execute('SELECT 1 FROM users LIMIT 1').fetchone():
            return
        admin_password = secrets.token_urlsafe(18)
        secret_file = DB_PATH.parent / 'admin_password.txt'
        secret_file.write_text(admin_password + '\n', encoding='utf-8')
        try:
            secret_file.chmod(0o600)
        except OSError:
            pass
        accounts = [
            (1, 'Admin Demo', 'admin@lab.local', admin_password, 'admin'),
            (2, 'Ana Torres', 'ana@lab.local', 'Ana123!', 'user'),
            (3, 'Luis Pérez', 'luis@lab.local', 'Luis123!', 'user'),
        ]
        db.executemany(
            'INSERT INTO users(id, name, email, password_hash, role) VALUES(?,?,?,?,?)',
            [(i, name, email, hash_password(pwd), role) for i,name,email,pwd,role in accounts]
        )
        db.executemany('INSERT INTO documents(id, owner_id, title, content) VALUES(?,?,?,?)', [
            (101, 2, 'Presupuesto de Ana', 'Datos: presupuesto de Ana: $15,000.'),
            (102, 3, 'Proyecto privado de Luis', 'Datos: el proyecto de Luis se entrega el viernes.'),
            (103, 1, 'Informe administrativo', 'Datos: reporte interno del administrador.'),
        ])


def find_user_by_email(email):
    with connection() as db:
        row = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
        return dict(row) if row else None


def find_user_by_id(uid):
    with connection() as db:
        row = db.execute('SELECT id, name, email, role FROM users WHERE id=?', (uid,)).fetchone()
        return dict(row) if row else None


def get_document(doc_id):
    with connection() as db:
        row = db.execute('''SELECT d.*, u.name AS owner_name FROM documents d
                            JOIN users u ON u.id=d.owner_id WHERE d.id=?''', (doc_id,)).fetchone()
        return dict(row) if row else None


def list_documents_for(uid):
    with connection() as db:
        return [dict(x) for x in db.execute(
            'SELECT id, title FROM documents WHERE owner_id=? ORDER BY id', (uid,))]


def list_users():
    with connection() as db:
        return [dict(x) for x in db.execute(
            'SELECT id, name, email, role FROM users ORDER BY id')]


def update_document(doc_id, title):
    with connection() as db:
        db.execute('UPDATE documents SET title=? WHERE id=?', (title, doc_id))


def update_role(uid, role):
    with connection() as db:
        db.execute('UPDATE users SET role=? WHERE id=?', (role, uid))


def token_digest(token):
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def create_session(uid):
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    with connection() as db:
        db.execute('DELETE FROM sessions WHERE expires_at<=?', (int(time.time()),))
        db.execute('INSERT INTO sessions VALUES(?,?,?,?)',
                   (token_digest(token), uid, csrf, int(time.time()) + 7200))
    return token


def get_session(token):
    if not token:
        return None
    with connection() as db:
        row = db.execute('''SELECT s.csrf_token, u.id, u.name, u.email, u.role
                            FROM sessions s JOIN users u ON u.id=s.user_id
                            WHERE s.token_hash=? AND s.expires_at>?''',
                         (token_digest(token), int(time.time()))).fetchone()
        return dict(row) if row else None


def revoke_session(token):
    if token:
        with connection() as db:
            db.execute('DELETE FROM sessions WHERE token_hash=?', (token_digest(token),))
