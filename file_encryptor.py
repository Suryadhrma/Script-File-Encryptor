import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

def generate_key_from_password(password: str, salt: bytes) -> bytes:
    """Menghasilkan kunci enkripsi dari password dan salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    # Fernet key harus di-encode dengan base64
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# ... (lanjutkan di file file_encryptor.py)

def encrypt_file(file_path: str, password: str):
    """Membaca file, mengenkripsinya, dan menyimpan sebagai file .encrypted"""
    # 1. Buat salt acak
    salt = os.urandom(16)
    
    # 2. Buat kunci dari password dan salt
    key = generate_key_from_password(password, salt)
    
    # 3. Baca konten file asli
    with open(file_path, 'rb') as f:
        file_data = f.read()
        
    # 4. Enkripsi data
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(file_data)
    
    # 5. Simpan file terenkripsi (salt + data)
    new_file_path = f"{file_path}.encrypted"
    with open(new_file_path, 'wb') as f:
        f.write(salt + encrypted_data) # Gabungkan salt dan data
        
    print(f"Sukses! File '{file_path}' dienkripsi menjadi '{new_file_path}'")

    # ... (lanjutkan di file file_encryptor.py)

def decrypt_file(file_path: str, password: str):
    """Membaca file .encrypted, mendekripsinya, dan menyimpan sebagai file .decrypted"""
    # 1. Baca file terenkripsi
    with open(file_path, 'rb') as f:
        encrypted_data_with_salt = f.read()

    # 2. Pisahkan salt dan data
    salt = encrypted_data_with_salt[:16]
    encrypted_data = encrypted_data_with_salt[16:]
    
    # 3. Buat kembali kunci dari password dan salt
    key = generate_key_from_password(password, salt)
    
    # 4. Dekripsi data
    fernet = Fernet(key)
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
        
        # 5. Simpan file yang sudah didekripsi
        original_file_path = file_path.replace('.encrypted', '')
        new_file_path = f"{original_file_path}.decrypted"
        with open(new_file_path, 'wb') as f:
            f.write(decrypted_data)
        
        print(f"Sukses! File '{file_path}' didekripsi menjadi '{new_file_path}'")
        
    except Exception as e:
        print(f"Gagal dekripsi! Password salah atau file korup. Error: {e}")

    # ... (lanjutkan di file file_encryptor.py)
import sys

if __name__ == '__main__':
    args = sys.argv
    # Contoh penggunaan: python file_encryptor.py -e namafile.txt
    # Contoh penggunaan: python file_encryptor.py -d namafile.txt.encrypted

    if len(args) != 3:
        print("Penggunaan:")
        print("Untuk Enkripsi: python file_encryptor.py -e <nama_file>")
        print("Untuk Dekripsi: python file_encryptor.py -d <nama_file_terenkripsi>")
        sys.exit(1)

    mode = args[1]
    file_path = args[2]

    password = input("Masukkan password: ")

    if mode == '-e':
        encrypt_file(file_path, password)
    elif mode == '-d':
        decrypt_file(file_path, password)
    else:
        print("Mode tidak valid. Gunakan '-e' untuk enkripsi atau '-d' untuk dekripsi.")