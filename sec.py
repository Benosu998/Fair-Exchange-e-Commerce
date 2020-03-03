from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes


def encrypt_data(data, recipient_key):
    data = data.encode()
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    return enc_session_key + cipher_aes.nonce + tag + ciphertext


def decrypt_data(enc_data, private_key):
    pl = private_key.size_in_bytes()

    # extract encrypted session key nonce tag and ciphertext from enc_data
    enc_session_key = enc_data[0:pl]
    nonce = enc_data[pl:pl + 16]
    tag = enc_data[pl + 16:pl + 32]
    ciphertext = enc_data[pl + 32:]

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    ResultData = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return ResultData.decode("utf-8")
