# IDEA, длина ключа 128 бит.
import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as padding2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key


def generate_sym_key():
    """Генерация симметричного ключа"""
    key = os.urandom(16)
    print("Симетричный ключ сгенерирован")
    print(key)
    return key


def generate_assym_key():
    """Генерация ассиметричных ключей"""
    keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return keys


def serialize_assym_keys(as_key):
    """Сериализация ассиметричных ключей"""
    path_open = input("Введите путь для открытого ключа ")
    with open(path_open, 'wb') as public_out:
        public_out.write(as_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                          format=serialization.PublicFormat.SubjectPublicKeyInfo))
    print("Ассиметричный открытый ключ записан в файл")
    path_close = input("Введите путь для закрытого ключа ")
    with open(path_close, 'wb') as private_out:
        private_out.write(as_key.private_bytes(encoding=serialization.Encoding.PEM,
                                               format=serialization.PrivateFormat.TraditionalOpenSSL,
                                               encryption_algorithm=serialization.NoEncryption()))
    print("Ассиметричный закрытый ключ записан в файл")


def sym_key_encrypt(sym_key):
    """Шифрование симметричного ключа открытым ключом и запись его в файл"""
    print("Зашифрование ключа симметричного шифрования открытым ключом")
    path_open = input("Введите путь для открытого ключа ")
    with open(path_open, "rb") as f:
        public_bytes = f.read()
    d_public_key = load_pem_public_key(public_bytes)
    ciphertext = d_public_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    path_enc = input("Введите путь для зашифрованного симметричного ключа ")
    with open(path_enc, "wb") as f:
        f.write(ciphertext)
    print("Зашифрованный симметричный ключ записан в файл")


def hybrid_system_key_generate_without():
    """Генерация ключей гибридной системы"""
    key = generate_sym_key()
    ass_key = generate_assym_key()
    serialize_assym_keys(ass_key)
    sym_key_encrypt(key)


def decryption_sem_key():
    """Расшифровать симметричный ключ"""
    print("Расшифровываем симметричный ключ")
    path_enc = input(
        "Введите путь к файлу с зашифрованным симметричным ключом ")
    if os.path.getsize(path_enc) == 0:
        raise "Файл не существует"
    with open(path_enc, mode="rb") as f:
        en_key = f.read()
    path_close = input("Введите путь к файлу с закрытым ключом ")
    with open(path_close, 'rb') as pem_in:
        private_key = pem_in.read()
    dc_private_key = load_pem_private_key(private_key, password=None, )
    dc_key = dc_private_key.decrypt(en_key,
                                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                                 label=None))
    print("Дешифрованный ключ: ", dc_key)
    return dc_key


def encryption_text_sym_alg(sym_key):
    """Зашифровать текст симметричным алгоритмом и сохранить по указанному пути"""
    print("Зашифруем текст симметричным алгоритмом и сохраним по указанному пути")
    path_file = input("Введите путь к вашему тексту ")
    with open(path_file, 'r', encoding='utf-8') as f:
        text = f.read()
    iv = os.urandom(8)
    with open("iv.bin", 'wb') as key_file:
        key_file.write(iv)
    padder = padding2.ANSIX923(64).padder()
    padded_text = padder.update(bytes(text, 'utf-8')) + padder.finalize()
    cipher = Cipher(algorithms.IDEA(sym_key), mode=modes.CBC(iv))
    encryptor = cipher.encryptor()
    en_text = encryptor.update(padded_text) + encryptor.finalize()
    print("Текст зашифрован!")
    path_save = input("Введите путь для сохранения шифрованного текста ")
    with open(path_save, 'wb') as f:
        f.write(en_text)


def encryption_data_without():
    try:
        decrypt_key = decryption_sem_key()
        encryption_text_sym_alg(decrypt_key)
    except BaseException:
        print("Error")


def decrypt_text_sym_alg(dc_key):
    """Расшифровать текст симметричным алгоритмом и сохранить по указанному пути"""
    print("Расшифровать текст симметричным алгоритмом и сохранить по указанному пути")
    path_save = input("Введите путь, куда вы сохранили зашифрованный текст ")
    with open(path_save, 'rb') as f:
        en_text = f.read()
    with open("iv.bin", "rb") as f:
        iv = f.read()
    cipher = Cipher(algorithms.IDEA(dc_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    dc_text = decryptor.update(en_text) + decryptor.finalize()
    unpadder = padding2.ANSIX923(64).unpadder()
    unpadded_dc_text = unpadder.update(dc_text) + unpadder.finalize()
    print(unpadded_dc_text.decode("UTF-8"))
    print("Текст расшифрован!")
    path_decr = input("Введите путь, куда cохранить расшифрованный текст ")
    with open(path_decr, 'w') as f:
        f.write(dc_text.decode("UTF_8"))
    print("Текст Записан в файл")


def decryption_data_without():
    """Дешифрование данных гибридной системой"""
    try:
        dc_key = decryption_sem_key()
        decrypt_text_sym_alg(dc_key)
    except BaseException:
        print("Error")


if __name__ == '__main__':
    check = True
    while check:
        choice = int(input(
            '1. Генерация ключей гибридной системы\n2. Шифрование данных гибридной системой\n3.'
            ' Дешифрование данных гибридной системой\n4.Выход\n'))
        if choice == 1:
            hybrid_system_key_generate_without()
        if choice == 2:
            encryption_data_without()
        if choice == 3:
            decryption_data_without()
        if choice == 4:
            check = False
            break
