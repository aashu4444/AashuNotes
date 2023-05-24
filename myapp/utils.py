from myapp.secrets import SECRET_KEY
import base64
from cryptography.fernet import Fernet


def bytes_string_to_bytes(bytes_string):
    """Convert bytes_string to bytes object"""
    return bytes(bytes_string.split("'")[1], 'utf-8')

def bytes_string_to_string(bytes_string):
    """Convert bytes_string to bytes object"""
    return str(bytes_string).split("'")[1]


def encrypt(request, text):
    key = bytes(SECRET_KEY[:6] + str(request.user.password)[:20] + SECRET_KEY[-7:-1], 'utf-8')
    key = base64.urlsafe_b64encode(key)

    return str(Fernet(key).encrypt(bytes(text,'utf-8')))

def decrypt(request, encrypted_text):
    key = bytes(SECRET_KEY[:6] + str(request.user.password)[:20] + SECRET_KEY[-7:-1], 'utf-8')
    key = base64.urlsafe_b64encode(key)


    decrypted = bytes_string_to_string(
        Fernet(key).decrypt(
            bytes_string_to_bytes(encrypted_text)
        )
    )


    return decrypted