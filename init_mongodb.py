import os
from pymongo import MongoClient
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

load_dotenv()

# Replace with your Atlas connection string if not in environment
MONGO_URI = os.environ.get("MONGO_URI", "mongodb+srv://user:pass@cluster.mongodb.net/forensics?retryWrites=true&w=majority")

def init_mongodb():
    try:
        print(f"[...] Connecting to MongoDB...")
        client = MongoClient(MONGO_URI)
        db_name = MONGO_URI.split('/')[-1].split('?')[0] or 'forensics'
        db = client[db_name]
        
        users_col = db.users
        
        # Check if admin user exists
        admin = users_col.find_one({"username": "admin"})
        if not admin:
            print("[+] Creating admin user...")
            hashed_password = generate_password_hash("password123")
            users_col.insert_one({
                "username": "admin",
                "password_hash": hashed_password
            })
            print("[+] Admin user created (admin / password123)")
        else:
            print("[!] Admin user already exists.")
            
        print("[+] MongoDB initialization complete.")
        
    except Exception as e:
        print(f"[ERROR] Failed to initialize MongoDB: {e}")

if __name__ == "__main__":
    init_mongodb()
