import sqlite3

DATABASE = 'tax_regime.db'

def check_users():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT rowid, name FROM users')
    users = cursor.fetchall()
    conn.close()
    if users:
        print("Current users in the database:")
        for user in users:
            print(f"ID: {user[0]}, Name: {user[1]}")
    else:
        print("No users found in the database.")

if __name__ == '__main__':
    check_users()
