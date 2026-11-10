import argparse
import html
import json
import logging
import os
import re
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import access_policy as policy
import database as db

ROOT = Path(__file__).resolve().parent
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s %(message)s')
LOG = logging.getLogger('a01')


def esc(value):
    return html.escape(str(value), quote=True)


def page(title, user, body, *, error=False):
    name = esc(user['name']) if user else 'Visitante'
    nav = '''<a href="/dashboard">Inicio</a>'''
    if user and user['role'] == 'admin':
        nav += '<a href="/admin">Administración</a>'
    if user:
        nav += '<form class="inline" method="post" action="/logout">' \
               f'<input type="hidden" name="_csrf" value="{esc(user["csrf_token"])}">' \
               '<button class="ghost slim" type="submit">Cerrar sesión</button></form>'
    else:
        nav = '<a href="/login">Iniciar sesión</a>'
    status = '<span class="tag bad">VULNERABLE</span>' if policy.MODE == 'VULNERABLE' else '<span class="tag good">PROTEGIDO</span>'
    contents = f'''<!doctype html><html lang="es"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="csrf-token" content="{esc(user['csrf_token']) if user else ''}">
    <title>{esc(title)} | OWASP A01</title><link rel="stylesheet" href="/static/style.css"></head>
    <body><header><div class="bar"><div class="brand"><small>Control de Acceso Roto</small></div>
    <nav>{nav}</nav></div></header><main>{body}</main>
    </body></html>'''
    return contents


def dashboard(user):
    docs = db.list_documents_for(user['id'])
    tiles = ''.join(f'<div class="tile"><span class="eyebrow">Documento #{x["id"]}</span>'
                    f'<h2>{esc(x["title"])}</h2><a class="btn" href="/documents/{x["id"]}">Ver documento</a></div>'
                    for x in docs)
    if not tiles:
        tiles = '<p>No hay documentos.</p>'
    admin_note = '<p class="muted">No aparece el enlace de administración porque eres un usuario normal. En la versión vulnerable esto no protege la ruta.</p>' if user['role'] != 'admin' else '<p><a href="/admin">Abrir panel administrativo</a></p>'
    return f'''<div class="eyebrow">Panel personal</div><h1>Hola, {esc(user['name'])}</h1>
      <p>Cuenta <code>{esc(user['email'])}</code> — rol de base de datos: <span class="tag">{esc(user['role'])}</span></p>
      <div class="card"><h2>Mis documentos</h2><div class="grid">{tiles}</div></div>'''


def login_page(error=''):
    message = f'<div class="error">{esc(error)}</div>' if error else ''
    return f'''<div class="card narrow"><div class="eyebrow"></div><h1>Iniciar sesión</h1>
        {message}<form method="post" action="/login">
        <label>Correo electrónico<input name="email" type="email" required autocomplete="username"></label>
        <label>Contraseña<input name="password" type="password" required autocomplete="current-password"></label>
        <button type="submit">Entrar</button></form>
        Ana: <code>ana@lab.local</code> / <code>Ana123!</code><br>
        Luis: <code>luis@lab.local</code> / <code>Luis123!</code><br></div></div>'''


def document_page(user, document):
    return f'''<div class="eyebrow">Documento privado #{document['id']}</div>
      <h1>{esc(document['title'])}</h1>
      <div class="card"><p><strong>Propietario:</strong> {esc(document['owner_name'])} (ID {document['owner_id']})</p>
      <p>{esc(document['content'])}</p></div>
      <div class="card"><h2>Modificar título</h2>
      <form method="post" action="/documents/{document['id']}/edit">
      <input type="hidden" name="_csrf" value="{esc(user['csrf_token'])}">
      <label>Nuevo título<input name="title" maxlength="80" value="{esc(document['title'])}" required></label>
      <button type="submit">Guardar título</button></form></div><a href="/dashboard">Volver</a>'''


def admin_page(user):
    rows = ''.join('''<tr><td>{id}</td><td>{name}</td><td>{email}</td><td>{role}</td>
      <td><form method="post" action="/admin/users/{id}/role">
      <input type="hidden" name="_csrf" value="{csrf}"><select name="role">
      <option value="user" {user_selected}>Usuario</option><option value="admin" {admin_selected}>Administrador</option>
      </select><button class="slim" type="submit">Cambiar rol</button></form></td></tr>'''.format(
         id=u['id'], name=esc(u['name']), email=esc(u['email']), role=esc(u['role']),
         csrf=esc(user['csrf_token']),
         user_selected='selected' if u['role']=='user' else '',
         admin_selected='selected' if u['role']=='admin' else ''
      ) for u in db.list_users())
    return f'''<div class="eyebrow">Área restringida</div><h1>Panel de administración</h1>
      <p>La siguiente tabla no debe poder consultarse ni modificarse desde una cuenta normal.</p>
      <div class="card table-wrap"><table><thead><tr><th>ID</th><th>Nombre</th><th>Correo</th>
      <th>Rol</th><th>Cambiar rol</th></tr></thead><tbody>{rows}</tbody></table></div>
      <p>API administrativa: <a href="/api/admin/users">/api/admin/users</a></p>'''


class LabHandler(BaseHTTPRequestHandler):
    server_version = 'A01Lab/1.0'

    def log_message(self, fmt, *args):
        LOG.info('%s %s', self.client_address[0], fmt % args)

    def response(self, code, content, content_type='text/html; charset=utf-8', extra_headers=None):
        data = content.encode('utf-8') if isinstance(content, str) else content
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store, max-age=0')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        for k,v in (extra_headers or {}).items():
            self.send_header(k,v)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(data)

    def json_response(self, code, payload):
        self.response(code, json.dumps(payload, ensure_ascii=False), 'application/json; charset=utf-8')

    def redirect(self, path, headers=None):
        self.response(HTTPStatus.SEE_OTHER, '', extra_headers={'Location': path, **(headers or {})})

    def token_from_cookie(self):
        try:
            cookies = SimpleCookie()
            cookies.load(self.headers.get('Cookie', ''))
            return cookies['lab_session'].value if 'lab_session' in cookies else None
        except Exception:
            return None

    def authenticate(self):
        return db.get_session(self.token_from_cookie())

    def need_login(self, user, api):
        if user is not None:
            return False
        if api:
            self.json_response(401, {'error': 'AUTH_REQUIRED', 'message': 'Debes iniciar sesión.'})
        else:
            self.redirect('/login')
        return True

    def forbidden(self, user, action, api):
        LOG.warning('ACCESO DENEGADO: usuario=%s rol=%s accion=%s ip=%s',
                    user['id'] if user else '-', user['role'] if user else '-',
                    action, self.client_address[0])
        if api:
            self.json_response(403, {'error': 'ACCESS_DENIED', 'message': 'No tienes permiso.'})
        else:
            content = '<div class="error"><h1>403 — Acceso denegado</h1><p>No tienes permisos para esta operación.</p></div><a href="/dashboard">Regresar a mi panel</a>'
            self.response(403, page('Acceso denegado', user, content))

    def bad(self, status, message, api=False):
        if api:
            self.json_response(status, {'error': 'BAD_REQUEST', 'message': message})
        else:
            self.response(status, page('Solicitud incorrecta', None, f'<div class="error"><h1>{status}</h1><p>{esc(message)}</p></div>'))

    def body(self):
        length = int(self.headers.get('Content-Length', '0'))
        if length > 16384 or length < 0:
            raise ValueError('Cuerpo de solicitud demasiado grande.')
        raw = self.rfile.read(length)
        ctype = self.headers.get('Content-Type', '').split(';')[0].strip().lower()
        if ctype == 'application/json':
            result = json.loads(raw.decode('utf-8'))
            if not isinstance(result, dict):
                raise ValueError('Se requiere un objeto JSON.')
            return result
        if ctype == 'application/x-www-form-urlencoded':
            return {k: v[-1] for k,v in parse_qs(raw.decode('utf-8'), keep_blank_values=True).items()}
        raise ValueError('Usa Content-Type: application/json o application/x-www-form-urlencoded.')

    def method_not_allowed(self):
        self.json_response(405, {'error': 'METHOD_NOT_ALLOWED'})

    def dispatch(self):
        path = urlsplit(self.path).path
        method = self.command
        if path == '/static/style.css' and method in ('GET', 'HEAD'):
            return self.response(200, (ROOT / 'static' / 'style.css').read_bytes(), 'text/css; charset=utf-8')
        if path == '/':
            return self.redirect('/dashboard')
        user = self.authenticate()
        api = path.startswith('/api/')

        if path == '/login':
            if method in ('GET', 'HEAD'):
                return self.response(200, page('Iniciar sesión', user, login_page()))
            if method != 'POST':
                return self.method_not_allowed()
            try:
                data = self.body()
            except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
                return self.bad(400, str(exc))
            email = data.get('email', '')
            password = data.get('password', '')
            if not isinstance(email, str) or not isinstance(password, str):
                return self.bad(400, 'Datos inválidos.')
            account = db.find_user_by_email(email.strip().lower())
            if not account or not db.check_password(password, account['password_hash']):
                return self.response(401, page('Credenciales incorrectas', None, login_page('Correo o contraseña incorrectos.')))
            db.revoke_session(self.token_from_cookie())
            token = db.create_session(account['id'])
            return self.redirect('/dashboard', {'Set-Cookie': f'lab_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=7200'})

        if path == '/logout':
            if method != 'POST':
                return self.method_not_allowed()
            if self.need_login(user, False):
                return
            try:
                data = self.body()
            except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
                return self.bad(400, str(exc))
            if not policy.valid_csrf(user, data.get('_csrf')):
                return self.forbidden(user, 'CSRF logout', False)
            db.revoke_session(self.token_from_cookie())
            return self.redirect('/login', {'Set-Cookie': 'lab_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0'})

        if path == '/dashboard' and method in ('GET', 'HEAD'):
            if self.need_login(user, False): return
            return self.response(200, page('Mi panel', user, dashboard(user)))
        if path == '/api/me' and method in ('GET', 'HEAD'):
            if self.need_login(user, True): return
            return self.json_response(200, {'id':user['id'],'name':user['name'], 'role':user['role'], 'csrf_token':user['csrf_token']})

        doc_match = re.fullmatch(r'/documents/([0-9]+)', path)
        if doc_match and method in ('GET', 'HEAD'):
            if self.need_login(user, False): return
            document = db.get_document(int(doc_match[1]))
            if not document: return self.bad(404, 'Documento no encontrado.')
            if not policy.can_access_document(user, document):
                return self.forbidden(user, f'GET documento {document["id"]}', False)
            return self.response(200, page('Documento', user, document_page(user, document)))

        doc_edit_match = re.fullmatch(r'/documents/([0-9]+)/edit', path)
        api_doc_match = re.fullmatch(r'/api/documents/([0-9]+)', path)
        if (doc_edit_match and method == 'POST') or (api_doc_match and method in ('GET', 'HEAD', 'PATCH')):
            if self.need_login(user, bool(api_doc_match)): return
            doc_id = int((doc_edit_match or api_doc_match)[1])
            document = db.get_document(doc_id)
            if not document: return self.bad(404, 'Documento no encontrado.', bool(api_doc_match))
            is_write = method in ('PATCH','POST')
            allowed = policy.can_modify_document(user, document) if is_write else policy.can_access_document(user, document)
            if not allowed: return self.forbidden(user, f'{method} documento {doc_id}', bool(api_doc_match))
            if not is_write:
                return self.json_response(200, {k:document[k] for k in ('id','owner_id','title','content')})
            try:
                data = self.body()
            except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
                return self.bad(400, str(exc), bool(api_doc_match))
            if not policy.valid_csrf(user, data.get('_csrf') or self.headers.get('X-CSRF-Token')):
                return self.forbidden(user, 'CSRF al editar documento', bool(api_doc_match))
            title = data.get('title')
            if not isinstance(title, str) or not title.strip() or len(title.strip()) > 80:
                return self.bad(400, 'El título debe tener entre 1 y 80 caracteres.', bool(api_doc_match))
            db.update_document(doc_id, title.strip())
            if api_doc_match:
                return self.json_response(200, {'ok':True,'id':doc_id,'title':title.strip()})
            return self.redirect(f'/documents/{doc_id}')

        if path == '/admin' and method in ('GET', 'HEAD'):
            if self.need_login(user, False): return
            if not policy.can_access_admin(user): return self.forbidden(user, 'GET /admin', False)
            return self.response(200, page('Panel de administración', user, admin_page(user)))

        if path == '/api/admin/users' and method in ('GET', 'HEAD'):
            if self.need_login(user, True): return
            if not policy.can_access_admin(user): return self.forbidden(user, 'GET /api/admin/users', True)
            return self.json_response(200, {'users': db.list_users()})

        form_role_match = re.fullmatch(r'/admin/users/([0-9]+)/role', path)
        api_role_match = re.fullmatch(r'/api/admin/users/([0-9]+)/role', path)
        if (form_role_match or api_role_match) and method == 'POST':
            is_api = bool(api_role_match)
            if self.need_login(user, is_api): return
            if not policy.can_access_admin(user):
                return self.forbidden(user, f'POST rol usuario {(form_role_match or api_role_match)[1]}', is_api)
            try:
                data = self.body()
            except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
                return self.bad(400, str(exc), is_api)
            if not policy.valid_csrf(user, data.get('_csrf') or self.headers.get('X-CSRF-Token')):
                return self.forbidden(user, 'CSRF al cambiar rol', is_api)
            target = int((form_role_match or api_role_match)[1])
            role = data.get('role')
            if role not in ('admin','user') or db.find_user_by_id(target) is None:
                return self.bad(400, 'Rol o usuario incorrecto.', is_api)
            db.update_role(target, role)
            if is_api:
                return self.json_response(200, {'ok':True,'user_id':target,'role':role})
            return self.redirect('/admin')

        # Todo lo que no haya sido permitido explícitamente queda bloqueado.
        if method not in ('GET','HEAD','POST','PATCH'):
            return self.method_not_allowed()
        return self.bad(404, 'Ruta inexistente.', api)

    def handle_method(self):
        try:
            self.dispatch()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            LOG.exception('Error interno en %s %s', self.command, self.path)
            try:
                self.bad(500, 'Error interno, revisa la consola.', self.path.startswith('/api/'))
            except (BrokenPipeError, ConnectionResetError):
                pass

    do_GET = handle_method
    do_HEAD = handle_method
    do_POST = handle_method
    do_PATCH = handle_method
    do_PUT = handle_method
    do_DELETE = handle_method
    do_OPTIONS = handle_method


def make_server(host='127.0.0.1', port=5000):
    db.init_db()
    return ThreadingHTTPServer((host, port), LabHandler)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Laboratorio control de acceso roto OWASP A01')
    parser.add_argument('--host', default=os.environ.get('LAB_HOST', '127.0.0.1'), help='127.0.0.1 local; 0.0.0.0 red privada')
    parser.add_argument('--port', type=int, default=5000)
    args = parser.parse_args()
    httpd = make_server(args.host, args.port)
    print(f'\n== OWASP A01 LAB: {policy.MODE} ==')
    print(f'Servidor escuchando en http://{args.host}:{args.port}/')
    print('Ejemplo en LAN: http://IP-DE-WINDOWS:5000/  (solo red privada)')
    print('Para detener: Ctrl+C\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('\nLaboratorio detenido.')
    finally:
        httpd.server_close()
