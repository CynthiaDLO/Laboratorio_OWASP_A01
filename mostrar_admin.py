import database

if __name__ == '__main__':
    database.init_db()
    password_path = database.DB_PATH.parent / 'admin_password.txt'
    print('USUARIO ADMIN: admin@lab.local')
    print('CONTRASEÑA DE ESTA INSTALACIÓN:', password_path.read_text(encoding='utf-8').strip())
