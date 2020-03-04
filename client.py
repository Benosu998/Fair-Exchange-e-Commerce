import socket
from Crypto.PublicKey import RSA
import sec
import pickle


def generate_rsa_pair():
    key = RSA.generate(1024)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key


# Generate RSA Public and Private keys for client
client_private, client_public = generate_rsa_pair()

# Load Merchant Public Key
merchant_public = RSA.import_key(open("receiver.pem").read())

# SID & Sig(SID)
SID = None
Sig_SID = None


def Setup(sock):
    global SID
    global Sig_SID
    # Send Client public key to merchant
    sock.send(sec.encrypt_data(client_public.export_key(), merchant_public))

    # Read Sid + Sig(Sid) from merchant
    data = pickle.loads(sec.decrypt_data(sock.recv(1024), client_private))
    SID = data[0]
    Sig_SID = data[1]


if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("127.0.0.1", 1234))
        Setup(s)
        print(sec.checksign(SID,merchant_public,Sig_SID))
        print("Client Finished")
