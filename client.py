import socket
from Crypto.PublicKey import RSA
import sec


def generate_rsa_pair():
    key = RSA.generate(1024)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key


# Generate RSA Public and Private keys for client
client_private, client_public = generate_rsa_pair()

# Load Merchant Public Key
merchant_public = RSA.import_key(open("receiver.pem").read())

if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("127.0.0.1", 1234))
        s.send(sec.encrypt_data(client_public.export_key().decode(), merchant_public))
        s.send(sec.encrypt_data("Hello Word", merchant_public))
        data = s.recv(1024)
        print(sec.decrypt_data(data, client_private))
