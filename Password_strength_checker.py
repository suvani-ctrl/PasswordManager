import re
from pymongo import MongoClient

# Function to load common words from the rockyou.txt file
def load_rockyou_words(filename="rockyou.txt"):
    try:
        with open(filename, "r", encoding="latin-1") as file:
            words = set(word.strip().lower() for word in file.readlines())  # Store words in a set
        return words
    except FileNotFoundError:
        print(f"Error: {filename} not found.")
        return set()  # Return empty set if file is missing

# Function to check password strength
def check_password_strength(username, password):
    client = MongoClient('mongodb://localhost:27017/')
    db = client.password_manager
    users_collection = db.users

    if len(password) < 12 or len(password) > 16:
        return False, "Password length should be between 12 and 16 characters."
    
    if len(re.findall(r'[A-Z]', password)) < 3:
        return False, "Password must contain at least 3 uppercase letters."
    
    if len(re.findall(r'[a-z]', password)) < 3:
        return False, "Password must contain at least 3 lowercase letters."
    
    if len(re.findall(r'\d', password)) < 3:
        return False, "Password must contain at least 3 numbers."
    
    if len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', password)) < 3:
        return False, "Password must contain at least 3 special characters."
    
    # Check if password contains common dictionary words
    common_words = load_rockyou_words("rockyou.txt")
    for word in common_words:
        if word in password.lower().split():  # Check full words only
            return False, "Password must not contain common dictionary words."

    # Check if password exists in database
    if users_collection.find_one({"password": password}):
        return False, "Password is already used by another user."

    return True, "Strong password! Nice job."

