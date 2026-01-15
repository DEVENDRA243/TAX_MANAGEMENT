import sqlite3

DATABASE = 'tax_regime.db'

def check_regular_users():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT name, phone, aadhaar, email FROM users WHERE is_admin = 0 ORDER BY rowid')
    users = cursor.fetchall()
    conn.close()
    if users:
        print("Regular users in the database:")
        for idx, user in enumerate(users, start=1):
            print(f"ID: {idx}, Name: {user[0]}, Phone: {user[1]}, Aadhaar: {user[2]}, Email: {user[3]}")
    else:
        print("No regular users found in the database.")

if __name__ == '__main__':
    check_regular_users()
