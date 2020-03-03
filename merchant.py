import socket
import sec
from Crypto.PublicKey import RSA

client_public = None
merchant_private = RSA.import_key(open("private.pem").read())


if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 1234))
        s.listen(1)

        (connection, address) = s.accept()

        print("Connected address:", address)
        client_public = RSA.import_key(sec.decrypt_data(connection.recv(1024), merchant_private))
        while True:
            data = connection.recv(1024)
            if not data:
                break
            print("Received: ", sec.decrypt_data(data, merchant_private))
            connection.send(sec.encrypt_data("Hello Back", client_public))
        connection.close()

        print("Server closed")
