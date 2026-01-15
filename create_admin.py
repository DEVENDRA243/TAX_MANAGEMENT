import sqlite3
from werkzeug.security import generate_password_hash

DATABASE = 'tax_regime.db'

def create_admin():
    print("Starting admin user creation...")
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        admin_aadhaar = '000000000000'
        admin_name = 'Admin User'
        admin_phone = '9999999999'
        admin_email = 'admin@example.com'
        admin_password = 'admin123'  # Change as needed
        password_hash = generate_password_hash(admin_password)

        cursor.execute('INSERT INTO users (name, phone, aadhaar, email, password_hash, is_admin) VALUES (?, ?, ?, ?, ?, ?)',
                       (admin_name, admin_phone, admin_aadhaar, admin_email, password_hash, 1))
        conn.commit()
        print("Admin user created successfully.")
    except sqlite3.IntegrityError:
        print("Admin user already exists.")
    except Exception as e:
        print(f"Error creating admin user: {e}")
    finally:
        conn.close()
        print("Database connection closed.")

if __name__ == '__main__':
    create_admin()
