from base64 import b64decode
from Crypto.Util.Padding import unpad
from oracle_service import Challenge
from attack import full_attack

if __name__ == "__main__":
    service = Challenge()
    iv, ct = service.get_string()
    recovered = full_attack(iv, ct, service.check_padding)
    plaintext = unpad(recovered, 16)
    print("Base64 plaintext:", plaintext)
    print("Decoded:", b64decode(plaintext).decode("ascii"))

