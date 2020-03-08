from Crypto.PublicKey import RSA

# Generate public and private key for merchant
key = RSA.generate(1024)
private_key = key.export_key()
file_out = open("merchant_private.pem", "wb")
file_out.write(private_key)

public_key = key.publickey().export_key()
file_out = open("merchant_receiver.pem", "wb")
file_out.write(public_key)

# Generate public and private key for payment gateway
key = RSA.generate(1024)
private_key = key.export_key()
file_out = open("payment_gateway_private.pem", "wb")
file_out.write(private_key)

public_key = key.publickey().export_key()
file_out = open("payment_gateway_receiver.pem", "wb")
file_out.write(public_key)
