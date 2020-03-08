import socket
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import sec
import pickle


def generate_rsa_pair():
    key = RSA.generate(1024)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key


# Client data (Dummy)
CardN = "340449866050055"
CardExp = "12/2029"
CCode = "1406345698"

NC = get_random_bytes(16)
M = "Emag"
Amount = 200
OrderDesc = "HUAWEI P SMART Z"
# Generate RSA Public and Private keys for client
client_private, client_public = generate_rsa_pair()

# Load Merchant Public Key
merchant_public = RSA.import_key(open("merchant_receiver.pem").read())

# Load Payment Gateway Public Key
payment_gateway_public = RSA.import_key(open("payment_gateway_receiver.pem").read())

# SID & Sig(SID)
SID = None
Sig_SID = None


def Setup(sock):
    global SID
    global Sig_SID
    # 1.Send Client public key to merchant
    sock.send(sec.encrypt_data(client_public.export_key(), merchant_public))

    # 2.Read Sid + Sig(Sid) from merchant
    data = pickle.loads(sec.decrypt_data(sock.recv(1024), client_private))
    SID = data[0]
    Sig_SID = data[1]


def Exchange(sock):
    PI = [CardN, CardExp, CCode, SID, Amount, client_public.export_key(), NC, M]
    pick = pickle.dumps(PI)
    PM = sec.encrypt_data(pickle.dumps([pick, sec.sign(pick, client_private)]), payment_gateway_public)
    data = [OrderDesc, SID, Amount, NC]
    PO = [pickle.dumps(data), sec.sign(pickle.dumps(data), client_private)]
    # 3. Send {PM,PO}PubKM
    send_data = pickle.dumps((PM, PO))
    cyper = sec.encrypt_data(send_data, merchant_public)
    print(len(cyper))
    sock.send(cyper)


if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("127.0.0.1", 1234))
        Setup(s)
        Exchange(s)
        print(sec.checksign(SID, merchant_public, Sig_SID))
        print("Client Finished")
