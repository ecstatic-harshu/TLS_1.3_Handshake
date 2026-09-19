import oqs

print(oqs.get_enabled_kem_mechanisms())
print(oqs.get_enabled_sig_mechanisms())

# import oqs


# print("Module:", oqs)
# print("Location:", oqs.__file__)
# print(dir(oqs))

# import oqs

# print(oqs.get_enabled_kem_mechanisms())

# print(oqs.get_enabled_sig_mechanisms())

# with oqs.KeyEncapsulation("ML-KEM-768") as server:

#     public_key = server.generate_keypair()

#     with oqs.KeyEncapsulation("ML-KEM-768") as client:

#         ciphertext, shared_secret_client = client.encap_secret(public_key)

#     shared_secret_server = server.decap_secret(ciphertext)

# print(shared_secret_client == shared_secret_server)

# message = b"Hello"

# with oqs.Signature("ML-DSA-65") as signer:

#     public_key = signer.generate_keypair()

#     signature = signer.sign(message)

#     valid = signer.verify(message, signature, public_key)

# print(valid)