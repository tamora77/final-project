from app import app, mysql

with app.app_context():
    cur = mysql.connection.cursor()
    try:
        # Check if the 'public_key' column exists
        cur.execute("SHOW COLUMNS FROM users LIKE 'public_key'")
        if not cur.fetchone():
            # Add the 'public_key' column
            # Using TEXT to store PEM formatted public key
            cur.execute("ALTER TABLE users ADD public_key TEXT NULL") # Allow NULL initially
            mysql.connection.commit()
            print("Successfully added 'public_key' column to the users table.")
        else:
            print("'public_key' column already exists in the users table.")
    except Exception as e:
        print(f"Error: {e}")
        mysql.connection.rollback()
    finally:
        if cur:
            cur.close() 