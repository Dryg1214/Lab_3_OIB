# IDEA, длина ключа 128 бит.
import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as padding2
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
"""
def hybrid_system_key_generate():
    
    key = generation_symmetric_key()
    generation_asymmetric_keys()
    print("Симметричный ключ:", key)
    symmetric_key_encryption(key)
"""
def hybrid_system_key_generate(path_enc, path_open, path_close):
    
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
    
    with open(path_open, "rb") as f:
        public_bytes = f.read()
    d_public_key = load_pem_public_key(public_bytes)
    print(d_public_key)
    ciphertext = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    #c_key = d_public_key.encrypt(key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    print("Зашифрование ключа симметричного шифрования открытым ключом")
    with open(path_enc, "wb") as f:
        f.write(ciphertext)
    print("Зашифрованный симметричный ключ записан в файл")
# symmetric_key_encryption(key)

# Входные параметры:
# 1) путь к шифруемому текстовому файлу (очевидно, что файл должен быть достаточно объемным);
# 2) путь к закрытому ключу ассиметричного алгоритма;
# 3) путь к зашированному ключу симметричного алгоритма;
# 4) путь, по которому сохранить зашифрованный текстовый файл;
# 2.1. Расшифровать симметричный ключ.
def encryption_data(path_file, path_close, path_enc, path_save):

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

    iv = os.urandom(8)
    with open("iv.bin", 'wb') as key_file:
        key_file.write(iv)
    padder = padding2.ANSIX923(32).padder()
    padded_text = padder.update(bytes(text, 'utf-8')) + padder.finalize()
    cipher = Cipher(algorithms.IDEA(dc_key), mode = modes.CBC(iv))
    encryptor = cipher.encryptor()
    en_text = encryptor.update(padded_text) + encryptor.finalize()
    # cipher = Cipher(algorithm, mode=None)
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

    with open("iv.bin", "rb") as f:
        iv = f.read()
    cipher = Cipher(algorithms.IDEA(dc_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    dc_text = decryptor.update(en_text) + decryptor.finalize()
    unpadder = padding2.ANSIX923(32).unpadder()
    unpadded_dc_text = unpadder.update(dc_text) + unpadder.finalize()
    print(unpadded_dc_text.decode("UTF-8"))
    print("Текст расшифрован!")

    with open(path_decr, 'w') as f:
        f.write(dc_text.decode("UTF_8"))
    print("Текст Записан в файл")


"""
print("Вас приветствует программа гибридной криптосистемы.")
end_of_the_work = False
while not end_of_the_work:
    choice = int(input('Выберите номер опции,которую хоите применить:\n1. Сгенерировать ключи\n2. Зашифровать '
                       'текст/ключ\n3.Дешифровать текст/ключ\n4.Выход\n'))
    if choice == 1:
        sym_key = generation_symmetric_key()
        generation_asymmetric_keys()
        print("Симметричный ключ:", sym_key)
    if choice == 2:
        en_choice = int(input("Зашифровать:\n1. Симметричный ключ\n2. Текст\n"))
        if en_choice == 1:
            if sym_key is None:
                print("Шифрование ключа невозможно, т.к. он не сгенерирован!")
                continue
            else:
                symmetric_key_encryption(sym_key)
        if en_choice == 2:
            if sym_key is None:
                print("Шифрование текста невозможно, т.к. не сгенерирован симметричный ключ!")
                continue
            else:
                text_encryption(sym_key)
    if choice == 3:
        dc_choice = int(input("Дешифровать:\n1. Симметричный ключ\n2. Текст\n"))
        if dc_choice == 1:
            if sym_key is None:
                print("Дешифрование ключа невозможно, т.к. не сгенерирован симметричный ключ!")
                continue
            else:
                decryption_of_symmetric_key()
        if dc_choice == 2:
            if sym_key is None:
                print("Дешифрование текста невозможно, т.к. не сгенерирован симметричный ключ!")
                continue
            else:
                text_decryption(sym_key)
    if choice == 4:
        break
    cont = input("Продолжить работу программы? ")
    if cont == "да":
        continue
    if cont == "нет":
        end_of_the_work = True
# Press the green button in the gutter to run the script.
"""

"""
if __name__ == '__main__':
    key = os.urandom(16)
    print("Симетричный ключ сгенерирован")

    # Генерация ключей для ассиметричного алгоритма.
    keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key = keys
    public_key = keys.public_key()

    en_key = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(en_key)
   """

hybrid_system_key_generate("Enc", "Open_key", "Close_key")
encryption_data("MyText.txt", "Close_key", "Enc", "Save")
decryption_data("Save", "Close_key", "Enc", "Decr_text.txt")