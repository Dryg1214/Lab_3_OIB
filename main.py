# IDEA, длина ключа 128 бит.
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
import os
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




sym_key = None


def generation_symmetric_key() -> bytes:
    """
    Записывает по указанному пути в файл сгенерированный случайный ключ.
    Returns
    --------
        bytes: сгенерированный симметричный ключ
    """
    key = os.urandom(16)
    return key


def generation_asymmetric_keys() -> None:
    """
    Записывает по указанным путям в файл сгенерированные асимметричные открытый и закрытый ключи.
    Parameters
    ----------
    """
    keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key = keys
    print(type(private_key))
    public_key = keys.public_key()
    print("Асимметричные ключи созданы!\n")
    path_open_key = input("Введите путь для сохранения открытого ключа в файл: \n")
    with open(path_open_key, 'wb') as public_out:
        public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo))
    path_close_key = input("Введите путь для сохранения закрытого ключа в файл: \n")
    with open(path_close_key, 'wb') as private_out:
        private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                    encryption_algorithm=serialization.NoEncryption()))
    print("Асимметричные ключи записаны в файл!\n")


def symmetric_key_encryption(key) -> None:
    """
     Считывает из файла сгенерированный симметричный ключ, шифрует его и
     записывает по указанному пути в файл зашифрованный симметричный ключ.
    """
    path_open_key = input("Введите путь, где хранится открытый ключ: ")
    with open(path_open_key, "rb") as pem_in:
        public_bytes = pem_in.read()
    d_public_key = load_pem_public_key(public_bytes)

    en_key = d_public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    en_key_path = input("Введите путь для сохранения зашифрованного симметричного ключа в файл: ")
    with open(en_key_path, "wb") as f:
        f.write(en_key)


def decryption_of_symmetric_key() -> None:
    """
     Считывает из файла зашифрованный симметричный ключ, дешифрует его и
     записывает по указанному пути в файл.
    """
    en_key_path = input("Введите путь зашифрованного ключа: ")
    with open(en_key_path, mode="rb") as f:
        en_text = f.read()
    private_pem = input("Введите путь, по которому лежит файл с закрытым ключом: ")
    with open(private_pem, 'rb') as pem_in:
        private_bytes = pem_in.read()
    d_private_key = load_pem_private_key(private_bytes, password=None,)
    dc_key = d_private_key.decrypt(en_text,
                                   padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                                label=None))
    print("Дешифрованный ключ: ", dc_key)


def set_iv_to_file() -> None:
    """
    Генерирует ключ для щифрации и дещифрации текста и сохраняет его в бинарный файл.
    """
    iv = os.urandom(8)
    print(type(iv))
    with open("iv.bin", 'wb') as key_file:
        key_file.write(iv)


def get_iv() -> bytes:
    """
    Считывает из файла ключ для щифрации и дешифрации текста.
    Returns
    --------
        bytes: сгенерированный ключ
    """
    with open("iv.bin", "rb") as f:
        result = f.read()
    return result


def text_encryption(key) -> None:
    """
    Считывает текст из файла, шифрует его и сохраняет результат в файл по указанному пути
    """
    text_ = ""
    path_text = input("Введите путь к тексту, который нужно зашифровать\n")
    with open(path_text, 'r', encoding='utf-8') as f:
        text_ = f.read()
    set_iv_to_file()
    iv = get_iv()
    padder = padding.ANSIX923(1024).padder()
    padded_text = padder.update(bytes(text_, 'utf-8')) + padder.finalize()
    cipher = Cipher(algorithms.CAST5(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    c_text = encryptor.update(padded_text) + encryptor.finalize()
    print("Текст зашифрован!")
    save_to_file_text_encryption(c_text)


def text_decryption(key) -> None:
    """
    Считывает из файла зашифрованный текст, дешифрует его и сохраняет результат в файл по указанному пути.
    """
    path_en_text = input("Введите путь к зашифрованному тексту: ")
    with open(path_en_text, 'rb') as f:
        en_text = f.read()
    cipher = Cipher(algorithms.CAST5(key), modes.CBC(get_iv()))
    decryptor = cipher.decryptor()
    dc_text = decryptor.update(en_text) + decryptor.finalize()
    unpadder = padding.ANSIX923(1024).unpadder()
    unpadded_dc_text = unpadder.update(dc_text) + unpadder.finalize()
    print(unpadded_dc_text.decode("UTF-8"))
    print("Текст расшифрован!")
    save_to_file_text_descryption(unpadded_dc_text)


def save_to_file_text_encryption(c_text):
    """
    Сохраняет зашифрованный текст в файл.
    Parameters
    ----------
        c_text: bytes
            зашифрованный текст
    """
    path_text_en = input("Введите путь для сохранения зашифрованного текста\n")
    with open(path_text_en, 'wb') as f_text:
        f_text.write(c_text)


def save_to_file_text_descryption(ds_text):
    """
       Сохраняет дешифрованный текст в файл.
       Parameters
       ----------
           ds_text: str
               дешифрованный текст
       """
    path_text_ds = input("Введите путь для сохранения расшифрованного текста\n")
    with open(path_text_ds, 'w') as f:
        f.write(ds_text.decode("UTF_8"))


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
"""
  hybrid_system_key_generate("aa", "Open_key", "Close_key")
    encryption_data("MyText.txt", "Close_key.txt", "Encr_sym_key.txt", "Save_decr_Text.txt")
    decryption_data("Save_decr_Text.txt", "Close_key.txt", "Encr_sym_key.txt", "Decr_text.txt")
    """