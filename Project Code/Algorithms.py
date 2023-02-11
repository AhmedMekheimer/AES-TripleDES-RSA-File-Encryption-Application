from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.fernet import Fernet
from Crypto.Cipher import DES3
from hashlib import md5
def load_key_aes():
    return open("key.key", "rb").read()
def load_key_des():
    return open("key.des", "rb").read()
def write_key_des():
    key = Fernet.generate_key()
    with open("key.des", "wb") as key_file:
        key_file.write(key)
def write_key_aes():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)
def encryptRSA(keyfile,public_key,encrypted_keysfile):
    with open(keyfile, "rb") as file:
        keys = file.read()
    oaep_padding = asymmetric_padding.OAEP(mgf=asymmetric_padding.MGF1(algorithm=SHA256()), algorithm=SHA256(),
                                           label=None)
    encrypted_keys = public_key.encrypt(keys, oaep_padding)

    with open(encrypted_keysfile, "wb") as file:
        file.write(encrypted_keys)

def decryptRSA(encrypted_keys,private_key,recovered_keysfile):
    with open(encrypted_keys, "rb") as file:
        encrypted_keys = file.read()
    oaep_padding = asymmetric_padding.OAEP(mgf=asymmetric_padding.MGF1(algorithm=SHA256()), algorithm=SHA256(),
                                           label=None)
    recovered_keys = private_key.decrypt(encrypted_keys, oaep_padding)

    with open(recovered_keysfile, "wb") as file:
        file.write(recovered_keys)

def encryptAES(filename,filename2,keyfile):
    write_key_aes()
    key = load_key_aes()
    strkey = str(key, 'UTF-8')

    with open(keyfile, 'r') as file:
        # read a list of lines into data
        allkeys = file.readlines()

    allkeys[0] = strkey+'\n'
    # and write everything back
    with open(keyfile, 'w') as file:
        file.writelines(allkeys)

    f = Fernet(key)
    with open(filename, "rb") as file:
        # read all file data
        file_data = file.read()

    # encrypt data
    encrypted_data = f.encrypt(file_data)
    # write the encrypted file
    with open(filename2, "wb") as file:
        file.write(encrypted_data)

def decryptAES(filename,filename2,recovered_keysfile):
    # with open(recovered_keysfile, "rb") as file:
    #     recovered_key = file.read()
    with open(recovered_keysfile, 'r') as file:
        # read a list of lines into data
        allkeys = file.readlines()
    recovered_key=allkeys[0]

    f = Fernet(recovered_key)
    with open(filename, "rb") as file:
        # read the encrypted data
        encrypted_data = file.read()
    # decrypt data
    decrypted_data = f.decrypt(encrypted_data)
    # write the original file
    with open(filename2, "wb") as file:
        file.write(decrypted_data)   

def encryptDES(filename,filename2,keyfile):
    write_key_des()
    key = load_key_des()
    strkey = str(key, 'UTF-8')

    with open(keyfile, 'r') as file:
        # read a list of lines into data
        allkeys = file.readlines()
    print(allkeys)
    allkeys[1] = strkey
    # and write everything back
    with open(keyfile, 'w') as file:
        file.writelines(allkeys)
    # with open(keyfile, "a+") as file:
    #     file.write(strkey + "\n")
    key_hash = md5(strkey.encode('ascii')).digest()
    tdes_key = DES3.adjust_key_parity(key_hash)
    cipher = DES3.new(tdes_key, DES3.MODE_EAX, nonce=b'0')

    with open(filename, 'rb') as input_file:
        file_bytes = input_file.read()
        new_file_bytes = cipher.encrypt(file_bytes)

    with open(filename2, 'wb') as output_file:
        output_file.write(new_file_bytes)

def decryptDES(filename,filename2,recovered_keysfile):
    # with open(recovered_keysfile, "rb") as file:
    #     recovered_key = file.read()

    with open(recovered_keysfile, 'r') as file:
        # read a list of lines into data
        allkeys = file.readlines()
    recovered_key=allkeys[1]
    print(allkeys)

    key_hash = md5(recovered_key.encode('ascii')).digest()
    tdes_key = DES3.adjust_key_parity(key_hash)
    cipher = DES3.new(tdes_key, DES3.MODE_EAX, nonce=b'0')

    with open(filename, 'rb') as input_file:
        file_bytes = input_file.read()
        new_file_bytes = cipher.decrypt(file_bytes)

    with open(filename2, 'wb') as output_file:
        output_file.write(new_file_bytes)

{
# # Recipient's private key
# private_key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048
# )
# # Public key to make available to sender
# public_key = private_key.public_key()

####################################################
#     private_pem = private_key.private_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PrivateFormat.PKCS8,
#     encryption_algorithm=serialization.NoEncryption()
# )
# with open('private_key.pem', 'wb') as f:
#     f.write(private_pem)
# public_pem = public_key.public_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PublicFormat.SubjectPublicKeyInfo
# )
# with open('public_key.pem', 'wb') as f:
#     f.write(public_pem)
}
# with open("private_key.pem", "rb") as key_file:
#     private_key = serialization.load_pem_private_key(
#         key_file.read(),
#         password=None,
#         backend=default_backend()
#     )
#
# with open("public_key.pem", "rb") as key_file:
#     public_key = serialization.load_pem_public_key(
#         key_file.read(),
#         backend=default_backend()
#     )


