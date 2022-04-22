from idea import IDEA

def main():
    #plain = 0x68656C6C6F6F6F21 # hellooo!
    plain = 0x616C616D61707361 # alamapsa
    ask = input('\nEncryption or Decryption? (e/d)\t')
    if ask == 'e':
        ask = input('\nUse default key? (y/n)\t\t')
        if ask == 'y':
            key = 0x6E3272357538782F413F4428472B4B62
            print(f"\nKey:\t\t{hex(key)}\n")
        elif ask == 'n':
            key = input("Enter key (hex):\t\t")
            print("\n")
            key = int(key, 16)

        my_IDEA = IDEA(key)
        encrypted = my_IDEA.encrypt(plain)

        print(f"Encrypted:\thex: {hex(encrypted)}\n")

        ask = input("Decrypt / Check? (y/n)\t\t\t")
        if ask == 'y':
            decrypted = my_IDEA.decrypt(encrypted)
            print(f"\nDecrypted:\thex: {hex(decrypted)}")
            print(f"\t\tuni: {decrypted.to_bytes(64, 'big').decode('ASCII')}\n")
        else:
            pass
    elif ask == 'd':
        ask = input('\nUse default key? (y/n)\t\t')
        if ask == 'y':
            key = 0x6E3272357538782F413F4428472B4B62
            print(f"\nKey:\t\t{hex(key)}\n")
        elif ask == 'n':
            key = input("Enter key (hex):\t\t")
            print("\n")
            key = int(key, 16)

        my_IDEA = IDEA(key)
        encrypted = input("Enter ciphertext (hex):\t")
        #encrypted = int.from_bytes(encrypted.encode("ASCII"), 'big')
        encrypted = int(encrypted, 16)
        decrypted = my_IDEA.decrypt(encrypted)
        print(f"\nDecrypted:\thex: {hex(decrypted)}")
        print(f"\t\tuni: {decrypted.to_bytes(64, 'big').decode('ASCII')}\n")


if __name__ == '__main__':
    main()