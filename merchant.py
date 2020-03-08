import socket
import sec
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import pickle

client_public = None

# Load Merchant Private Key
merchant_private = RSA.import_key(open("merchant_private.pem").read())

# Load Payment Gateway Public Key
payment_gateway_public = RSA.import_key(open("payment_gateway_receiver.pem").read())

Sid = get_random_bytes(16)


def Setup(socket_client):
    global merchant_private
    global client_public
    # 1.Read Client Public key and load it
    data = socket_client.recv(1024)
    client_public = RSA.import_key(sec.decrypt_data(data, merchant_private))

    # 2.Send to Client Sid+Sig(Sid)
    data = [Sid, sec.sign(Sid, merchant_private)]
    socket_client.send(sec.encrypt_data(pickle.dumps(data), client_public))


def Exchange(socket_client, socket_PG):
    # 3.Read {PM,PO}
    data = sec.decrypt_data(socket_client.recv(2048), merchant_private)
    PM, PO = pickle.loads(data)
    dataPO, signPO = PO
    if sec.checksign(dataPO, client_public, signPO):
        dataPO = pickle.loads(dataPO)
        signature = sec.sign(pickle.dumps([dataPO[1], client_public.export_key(), dataPO[2]]), merchant_private)
        sendData = pickle.dumps((PM, signature))
        # 4. Send {PM,SigM{..}} to PG
        socket_PG.send(sec.encrypt_data(sendData, payment_gateway_public))

        # 5. Recieve Response from PG
        dataCr = socket_PG.recv(2048)
        data = sec.decrypt_data(dataCr, merchant_private)

        # 6. Send Response to CLinet
        socket_client.send(sec.encrypt_data(data, client_public))


if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 1234))
        s.listen(1)
        (connection, address) = s.accept()

    print("Connected address:", address)

    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.connect(("127.0.0.1", 4321))

    Setup(connection)
    Exchange(connection, sk)
    connection.close()
    print("Server closed")
    sk.close()
