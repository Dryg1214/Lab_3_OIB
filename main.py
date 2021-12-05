# IDEA, длина ключа 128 бит.
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# 1.1. Сгеренировать ключ для симметричного алгоритма.
# 1.2. Сгенерировать ключи для ассиметричного алгоритма.
# 1.3. Сериализовать ассиметричные ключи.
# 1.4. Зашифровать ключ симметричного шифрования открытым ключом и сохранить по указанному пути.
def hybrid_system_encryption(path_enc, path_open, path_close):
    """Hybrid System key generation"""
    # Генерация ключа для симметричного алгоритма.
    key = os.urandom(16)
    algorithm = algorithms.IDEA(key)  # тут байты, 128 бит
    cipher_key = Cipher(algorithm, mode=None)

    # Генерация ключей для ассиметричного алгоритма.
    keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key = keys
    public_key = keys.public_key()
    # сериализация открытого ключа в файл
    with open(path_open, 'wb') as public_out:
        public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo))

    # сериализация закрытого ключа в файл
    with open(path_close, 'wb') as private_out:
        private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                    encryption_algorithm=serialization.NoEncryption()))

    # сериализация ключа симмеричного алгоритма в файл
    with open(path_enc, 'wb') as key_file:
        key_file.write(cipher_key)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print("gg не будет")
    key = os.urandom(16)
    algorithm = algorithms.IDEA(key)  # тут байты, 128 бит
    cipher = Cipher(algorithm, mode=None)
    print(cipher)
