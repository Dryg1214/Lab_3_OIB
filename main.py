# IDEA, длина ключа 128 бит.
import pickle
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

"""
algorithm = algorithms.IDEA(16) # тут байты, 128 бит
cipher = Cipher(algorithm, mode=None)
encryptor = cipher.encryptor()
ct = encryptor.update(b"a secret message")
decryptor = cipher.decryptor()
decryptor.update(ct)
"""
print(type(private_key))
print(private_key)
print(type(public_key))
print(public_key)
# 1.1. Сгеренировать ключ для симметричного алгоритма.
# 1.2. Сгенерировать ключи для ассиметричного алгоритма.
# 1.3. Сериализовать ассиметричные ключи.
# 1.4. Зашифровать ключ симметричного шифрования открытым ключом и сохранить по указанному пути.
def hybrid_system_encryption(path_enc, path_open, path_close):
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




# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print("gg не будет")

