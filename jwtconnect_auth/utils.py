import hashlib
import random
import string
import uuid


def get_random_string(length=16):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


def get_random_hash(length=16):
    salt = str(uuid.uuid4()).encode()
    randomness = get_random_string(length).encode() + salt
    return hashlib.sha256(randomness).hexdigest()


def get_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()
