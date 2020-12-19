# from itsdangerous import URLSafeTimedSerializer
from cryptography.fernet import Fernet

def encrypt_data(data):
    """Encrypt string
    Args:
        data (str)
    Returns:
        str
    """

    # Get encryption key
    with open('encrypt.key', 'rb') as file:
        key = file.read()
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

def decrypt_data(data):
    """Encrypt string
    Args:
        data (str)
    Returns:
        str
    """

    # Get encryption key
    with open('encrypt.key', 'rb') as file:
        key = file.read()
    f = Fernet(key)
    return f.decrypt(data.encode()).decode()