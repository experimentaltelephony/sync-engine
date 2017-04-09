import random
import string

alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits


def generate_secret_string(length=20):
    return ''.join(random.SystemRandom().choice(alphabet) for _ in range(length))
