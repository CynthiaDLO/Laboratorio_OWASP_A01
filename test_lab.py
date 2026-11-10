import http.cookiejar
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

TEMP = tempfile.TemporaryDirectory(prefix='owasp_a01_test_')
os.environ['LAB_DB'] = str(Path(TEMP.name) / 'pruebas.sqlite3')

import access_policy as policy
import database
from server import make_server


class LabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = make_server('127.0.0.1', 0)
        cls.url = f'http://127.0.0.1:{cls.httpd.server_address[1]}'
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.vulnerable = (policy.MODE == 'VULNERABLE')

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=3)
        TEMP.cleanup()

    def setUp(self):
        database.init_db(reset=True)
        self.jar = http.cookiejar.CookieJar()
        self.browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.login(self.browser, 'ana@lab.local', 'Ana123!')

    def request(self, opener, path, method='GET', payload=None, headers=None):
        hdr = headers or {}
        data = None
        if payload is not None:
            if hdr.get('Content-Type') == 'application/json':
                data = json.dumps(payload).encode()
            else:
                hdr['Content-Type'] = 'application/x-www-form-urlencoded'
                data = urllib.parse.urlencode(payload).encode()
        req = urllib.request.Request(self.url + path, data=data, headers=hdr, method=method)
        try:
            response = opener.open(req, timeout=5)
        except urllib.error.HTTPError as exc:
            response = exc
        return response.status, response.read().decode('utf-8')

    def login(self, opener, email, password):
        status, body = self.request(opener, '/login', 'POST', {'email':email, 'password':password})
        self.assertEqual(status, 200, 'El login debe redirigir al panel correctamente.')
        self.assertIn('Panel personal', body)

    def csrf(self, opener):
        code, text = self.request(opener, '/api/me')
        self.assertEqual(code, 200)
        return json.loads(text)['csrf_token']

    def expectation(self, vulnerable_code=200, secure_code=403):
        return vulnerable_code if self.vulnerable else secure_code

    def test_01_ruta_admin_y_api(self):
        status, body = self.request(self.browser, '/admin')
        self.assertEqual(status, self.expectation())
        if self.vulnerable: self.assertIn('Panel de administración', body)
        else: self.assertNotIn('Panel de administración', body)
        status, body = self.request(self.browser, '/api/admin/users')
        self.assertEqual(status, self.expectation())
        if not self.vulnerable: self.assertNotIn('admin@lab.local', body)

    def test_02_idor_lectura(self):
        self.assertEqual(self.request(self.browser, '/documents/101')[0], 200)
        for url in ('/documents/102', '/api/documents/102'):
            status, body = self.request(self.browser, url)
            self.assertEqual(status, self.expectation())
            if not self.vulnerable: self.assertNotIn('Proyecto privado de Luis', body)

    def test_03_edicion_no_autorizada_por_formulario_y_api(self):
        token = self.csrf(self.browser)
        status, _ = self.request(self.browser, '/documents/102/edit', 'POST',
                                 {'title':'Alterado por Ana', '_csrf':token})
        # Si es vulnerable hay redirect a /documents/102 (200), si está protegido 403.
        self.assertEqual(status, self.expectation())
        status, _ = self.request(self.browser, '/api/documents/102', 'PATCH',
                                 {'title':'Alterado por PATCH'},
                                 {'Content-Type':'application/json', 'X-CSRF-Token':token})
        self.assertEqual(status, self.expectation())
        title = database.get_document(102)['title']
        self.assertEqual(title, 'Alterado por PATCH' if self.vulnerable else 'Proyecto privado de Luis')

    def test_04_cabeceras_y_query_falsificadas(self):
        for path, hdr in [('/admin?role=admin', {'X-Role':'admin','X-User-ID':'1'}),
                          ('/api/admin/users', {'X-Role':'admin','X-Forwarded-User':'1'})]:
            status, _ = self.request(self.browser, path, headers=hdr)
            self.assertEqual(status, self.expectation())
        status, _ = self.request(self.browser, '/api/admin/users', headers={'Cookie':'lab_session=token_falso'})
        self.assertEqual(status, 401)

    def test_05_elevacion_de_privilegios_por_api(self):
        token = self.csrf(self.browser)
        status, _ = self.request(self.browser, '/api/admin/users/2/role', 'POST',
                                 {'role':'admin'},
                                 {'Content-Type':'application/json','X-CSRF-Token':token})
        self.assertEqual(status, self.expectation())
        self.assertEqual(database.find_user_by_id(2)['role'], 'admin' if self.vulnerable else 'user')

    def test_06_admin_legitimo_y_usuario_propietario(self):
        admin = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.login(admin, 'admin@lab.local', (database.DB_PATH.parent / 'admin_password.txt').read_text(encoding='utf-8').strip())
        self.assertEqual(self.request(admin, '/admin')[0], 200)
        self.assertEqual(self.request(admin, '/api/admin/users')[0], 200)
        self.assertEqual(self.request(admin, '/documents/102')[0], 200)
        csrf = self.csrf(admin)
        status, _ = self.request(admin, '/api/admin/users/3/role', 'POST',
                                 {'role':'admin'},
                                 {'Content-Type':'application/json','X-CSRF-Token':csrf})
        self.assertEqual(status, 200)
        self.assertEqual(database.find_user_by_id(3)['role'], 'admin')
        csrf_ana = self.csrf(self.browser)
        status, _ = self.request(self.browser, '/api/documents/101', 'PATCH',
                                 {'title':'Actualización legítima'},
                                 {'Content-Type':'application/json','X-CSRF-Token':csrf_ana})
        self.assertEqual(status, 200)

    def test_07_csrf_defensa_complementaria(self):
        admin = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.login(admin, 'admin@lab.local', (database.DB_PATH.parent / 'admin_password.txt').read_text(encoding='utf-8').strip())
        status, _ = self.request(admin, '/api/admin/users/3/role', 'POST',
                                 {'role':'admin'}, {'Content-Type':'application/json'})
        self.assertEqual(status, 200 if self.vulnerable else 403)
        self.assertEqual(database.find_user_by_id(3)['role'], 'admin' if self.vulnerable else 'user')

    def test_08_cerrar_sesion_invalida_cookie(self):
        self.assertEqual(self.request(self.browser, '/api/me')[0], 200)
        csrf = self.csrf(self.browser)
        status, _ = self.request(self.browser, '/logout', 'POST', {'_csrf':csrf})
        self.assertEqual(status, 200)  # Sigue redirección a /login.
        self.assertEqual(self.request(self.browser, '/api/me')[0], 401)

    def test_09_denegar_rutas_no_publicadas(self):
        self.assertEqual(self.request(self.browser, '/api/admin/secreto')[0], 404)
        self.assertEqual(self.request(self.browser, '/api/admin/users', 'PUT')[0], 405)


if __name__ == '__main__':
    print('\n>>> EJECUTANDO CONTRA POLÍTICA:', policy.MODE)
    print('>>> La prueba confirma el comportamiento esperado para ESTA fase.\n')
    unittest.main(verbosity=2)
