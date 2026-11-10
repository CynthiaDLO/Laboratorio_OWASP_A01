import database

if __name__ == '__main__':
    database.init_db(reset=True)
    print('Base ficticia reiniciada, roles originales restaurados y sesiones invalidadas.')
    print('Usuarios: admin@lab.local, ana@lab.local y luis@lab.local.')
    print('ADMIN: contraseña nueva generada. Consultarla SOLO en el servidor con: python mostrar_admin.py')
    print('Inicia sesión de nuevo. Detén server.py antes de reiniciar.')
