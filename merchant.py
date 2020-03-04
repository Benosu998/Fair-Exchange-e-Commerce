import socket
import sec
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import pickle

client_public = None
merchant_private = RSA.import_key(open("private.pem").read())
Sid = get_random_bytes(16)


# print(int(Sid.hex(),16))

def Setup(socket_client):
    global merchant_private
    global client_public
    data = socket_client.recv(1024)
    client_public = RSA.import_key(sec.decrypt_data(data, merchant_private))

    # Send to Client Sid+Sig(Sid)
    data = [Sid, sec.sign(Sid, merchant_private)]
    socket_client.send(sec.encrypt_data(pickle.dumps(data), client_public))


if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 1234))
        s.listen(1)

        (connection, address) = s.accept()

    print("Connected address:", address)

    Setup(connection)

    connection.close()
    print("Server closed")
