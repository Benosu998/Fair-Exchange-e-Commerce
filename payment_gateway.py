import socket
from Crypto.PublicKey import RSA
import sec
import pickle

# Load Payment Gateway Private Key
payment_gateway_private = RSA.import_key(open("payment_gateway_private.pem").read())
# Load merchant public key
merchant_public = RSA.import_key(open("merchant_receiver.pem").read())
client_public = None


def Exchange(socket):
    global client_public
    # 4. Read {PM,SigM
    data = pickle.loads(sec.decrypt_data(socket.recv(2048), payment_gateway_private))
    PM, sign = data
    PI, signPI = pickle.loads(sec.decrypt_data(PM, payment_gateway_private))
    PI = pickle.loads(PI)
    print(PI)
    client_public = RSA.import_key(PI[5])

    print(sign)


if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 4321))
        s.listen(1)
        (connection, address) = s.accept()

    Exchange(connection)
