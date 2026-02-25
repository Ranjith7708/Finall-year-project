from app import app, db, User
from werkzeug.security import generate_password_hash

def init_db():
    with app.app_context():
        # Create database tables
        db.create_all()
        print("[+] Database tables created.")

        # Check if admin user exists
        admin = User.query.filter_by(username="admin").first()
        if not admin:
            hashed_password = generate_password_hash("password123")
            admin = User(username="admin", password_hash=hashed_password)
            db.session.add(admin)
            db.session.commit()
            print("[+] Admin user created (admin / password123)")
        else:
            print("[!] Admin user already exists.")

if __name__ == "__main__":
    init_db()
