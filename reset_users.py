import sqlite3

DATABASE = 'tax_regime.db'

def reset_users_table():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users')
    cursor.execute("DELETE FROM sqlite_sequence WHERE name='users'")
    conn.commit()
    conn.close()
    print("Users table cleared and autoincrement reset.")

if __name__ == '__main__':
    reset_users_table()
