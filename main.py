# IDEA, длина ключа 128 бит.
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key

#Входные параметры:
# 1) путь, по которому сериализовать зашифрованный симметричный ключ;
# 2) путь, по которому сериализовать открытый ключ;
# 3) путь, по которому сериазизовать закрытый ключ
# 1.1. Сгеренировать ключ для симметричного алгоритма.
# 1.2. Сгенерировать ключи для ассиметричного алгоритма.
# 1.3. Сериализовать ассиметричные ключи.
# 1.4. Зашифровать ключ симметричного шифрования открытым ключом и сохранить по указанному пути.
def hybrid_system_key_generate(path_enc, path_open, path_close):
    """Hybrid System key generation"""
    # Генерация ключа для симметричного алгоритма.
    key = os.urandom(16)
    print("Симетричный ключ сгенерирован")
    # Генерация ключей для ассиметричного алгоритма.
    keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key = keys
    public_key = keys.public_key()
    print("Ассиметричный ключи сгенерирован")
    # сериализация открытого ключа в файл
    with open(path_open, 'wb') as public_out:
        public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo))
    print("Ассиметричный открытый ключ записан в файл")
    # сериализация закрытого ключа в файл
    with open(path_close, 'wb') as private_out:
        private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                    encryption_algorithm=serialization.NoEncryption()))
    print("Ассиметричный закрытый ключ записан в файл")
    # Зашифровать ключ симметричного шифрования открытым ключом и сохранить по указанному пути.
    c_key = public_key.encrypt(key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    print("Зашифрование ключа симметричного шифрования открытым ключом")
    with open(path_enc, "wb") as f:
        f.write(c_key)
    print("Зашифрованный симметричный ключ записан в файл")


# Входные параметры:
# 1) путь к шифруемому текстовому файлу (очевидно, что файл должен быть достаточно объемным);
# 2) путь к закрытому ключу ассиметричного алгоритма;
# 3) путь к зашированному ключу симметричного алгоритма;
# 4) путь, по которому сохранить зашифрованный текстовый файл;
# 2.1. Расшифровать симметричный ключ.
def encryption_data(path_file, path_close, path_enc, path_save):
    """Data encryption by hybrid system"""
    # 2.1. Расшифровать симметричный ключ.
    with open(path_enc, mode="rb") as f:
        en_key = f.read()

    with open(path_close, 'rb') as pem_in:
        private_key = pem_in.read()
    dc_private_key = load_pem_private_key(private_key, password=None, )
    dc_key = dc_private_key.decrypt(en_key,
                                   padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                                label=None))
    print("Дешифрованный ключ: ", dc_key)
    # 2.2. Зашифровать текст симметричным алгоритмом и сохранить по указанному пути.
    with open(path_file, 'r', encoding='utf-8') as f:
        text = f.read()
    algorithm = algorithms.IDEA(dc_key) # он 16 байт = 128 бит
    cipher = Cipher(algorithm, mode=None)
    encryptor = cipher.encryptor()
    en_text = encryptor.update(text) + encryptor.finalize()
    print("Текст зашифрован!")
    with open(path_save, 'wb') as f:
        f.write(en_text)

# Входные парметры:
# 1) путь к зашифрованному текстовому файлу;
# 2) путь к закрытому ключу ассиметричного алгоритма;
# 3) путь к зашированному ключу симметричного алгоритма;
# 4) путь, по которому сохранить расшифрованный текстовый файл.
# 3.1. Расшифровать симметричный ключ.
# 3.2. Расшифровать текст симметричным алгоритмом и сохранить по указанному пути.
def decryption_data(path_save, path_close, path_enc, path_decr):
    # 3.1. Расшифровать симметричный ключ.
    with open(path_enc, mode="rb") as f:
        en_key = f.read()

    with open(path_close, 'rb') as pem_in:
        private_key = pem_in.read()
    dc_private_key = load_pem_private_key(private_key, password=None, )
    dc_key = dc_private_key.decrypt(en_key,
                                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                                 label=None))
    print("Дешифрованный ключ: ", dc_key)
    # 3.2. Расшифровать текст симметричным алгоритмом и сохранить по указанному пути.
    with open(path_save, 'rb') as f:
        en_text = f.read()
    cipher = Cipher(algorithms.CAST5(dc_key), mode=None)
    decryptor = cipher.decryptor()
    dc_text = decryptor.update(en_text) + decryptor.finalize()
    # unpadder = padding.ANSIX923(1024).unpadder()
    # unpadded_dc_text = unpadder.update(dc_text) + unpadder.finalize()
    print(dc_text)
    print("Текст расшифрован!")
    with open(path_decr, 'w') as f:
        f.write(dc_text.decode("UTF_8"))
    print("Текст Записан в файл")


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    hybrid_system_key_generate("Encr_sym_key", "Open_key", "Close_key")
    encryption_data("MyText.txt", "Close_key", "Encr_sym_key", "Save_decr_Text.txt")
    decryption_data("Save_decr_Text.txt", "Close_key", "Encr_sym_key", "Decr_text.txt")
