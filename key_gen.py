from cryptography.fernet import Fernet

if __name__ == '__main__':
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
