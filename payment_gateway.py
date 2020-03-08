import socket
from Crypto.PublicKey import RSA
import sec
import pickle
import json

# Load Payment Gateway Private Key
payment_gateway_private = RSA.import_key(open("payment_gateway_private.pem").read())
# Load merchant public key
merchant_public = RSA.import_key(open("merchant_receiver.pem").read())
client_public = None
banking_data = json.load(open("banking_data.json", "r"))
# print(banking_data)

resolution = None


def Exchange(socket):
    global client_public
    # 4. Read {PM,SigM
    data = pickle.loads(sec.decrypt_data(socket.recv(2048), payment_gateway_private))
    PM, sign = data

    PI, signPI = pickle.loads(sec.decrypt_data(PM, payment_gateway_private))
    PI = pickle.loads(PI)
    # print(PI)
    if sec.checksign(pickle.dumps([PI[3], PI[5], PI[4]]), merchant_public, sign):
        client_public = RSA.import_key(PI[5])
        if sec.checksign(pickle.dumps(PI), client_public, signPI):
            print("semnaturi verificate")
            cardN = PI[0]
            cardExp = PI[1]
            CCode = PI[2]
            SID = PI[3]
            Amount = PI[4]
            NC = PI[6]
            M = PI[7]
            for i in range(len(banking_data)):
                Cid = banking_data[i]['id']
                card_data = banking_data[i]['card-data']
                balance = banking_data[i]['balance']
                if card_data['CardN'] == cardN and card_data['CardExp'] == cardExp and card_data['CCode'] == CCode:
                    global resolution
                    if Amount <= balance:
                        Resp = "Tranzactie Acceptata "
                        banking_data[i]['balance'] -= Amount
                        json.dump(banking_data, open("banking_data.json", "w"))
                    else:
                        Resp = "Tranzactie Refuzata , Fonduri Insuficiente"
                    signData = [Resp, SID, Amount, NC]
                    signature = sec.sign(pickle.dumps(signData), payment_gateway_private)
                    message = pickle.dumps([Resp, SID, signature])
                    # 5. Send Response to Merchant
                    resolution = message
                    socket.send(sec.encrypt_data(message, merchant_public))
                    break


def Resolution(socket):
    data = socket.recv(2048)
    if sec.decrypt_data(data, payment_gateway_private) == b'OK':
        print("Ok")
        return None
    else:
        socket.send(sec.encrypt_data(resolution, client_public))


if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 4321))
        s.listen(1)
        (connection, address) = s.accept()

    Exchange(connection)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 4411))
        s.listen(1)
        (connection2, address2) = s.accept()
    Resolution(connection2)
