from idea import IDEA

def main():
    ask = input('\nEncryption or Decryption? (e/d)\t')

    # Encryption option
    if ask == 'e':

        # Encryption key setup
        ask = input('\nUse default key? (y/n)\t\t')
        if ask == 'y':
            key = 0x6E3272357538782F413F4428472B4B62
            print(f"\nKey:\t\t{hex(key)}\n")
        elif ask == 'n':
            key = input("Enter key (hex):\t\t")
            print("\n")
            key = int(key, 16)

        my_IDEA = IDEA(key)

        # Plaintext input and transformation
        plain = input("Enter plain (ASCII):\t\t")
        plain = int.from_bytes(plain.encode("ASCII"), 'big')
        size = plain.bit_length()

        sub_plain = []
        sub_enc = []

        # Encryption
        x = size // 64
        if size % 64 != 0:
            x += 1
            size += 64 - size % 64
        for i in range(x):
            shift = size - (i+1) * 64
            sub_plain.append((plain >> shift) & 0xFFFFFFFFFFFFFFFF)
            encrypted = my_IDEA.encrypt(sub_plain[i])
            sub_enc.append(encrypted)
            encrypted = 0
        for i in range(x):
            sub_enc[i] = sub_enc[i] << (x - (i + 1)) * 64
            encrypted = encrypted | sub_enc[i]

        print(f"\nEncrypted:\thex: {hex(encrypted)}\n")

        ask = input("Decrypt / Check? (y/n)\t\t")

        # Decryption / Check
        if ask == 'y':
            sub_dec = []
            size = encrypted.bit_length()
            if size % 64 != 0:
                x = size // 64 + 1
                size += 64 - size % 64
            else:
                x = size // 64
            decrypted = 0
            for i in range(x):
                shift = size - (i+1) * 64
                k = (encrypted >> shift) & 0xFFFFFFFFFFFFFFFF
                sub_dec.append(my_IDEA.decrypt(k))
            for i in range(x):
                    sub_dec[i] = sub_dec[i] << (x - (i + 1)) * 64
                    decrypted = decrypted | sub_dec[i]
                
            print(f"\nDecrypted:\thex: {hex(decrypted)}")
            print(f"\t\tuni: {decrypted.to_bytes(64, 'big').decode('ASCII')}\n")
        else:
            pass

    # Decryption option
    elif ask == 'd':

        # Key setup
        ask = input('\nUse default key? (y/n)\t\t')
        if ask == 'y':
            key = 0x6E3272357538782F413F4428472B4B62
            print(f"\nKey:\t\t{hex(key)}\n")
        elif ask == 'n':
            key = input("Enter key (hex):\t\t")
            print("\n")
            key = int(key, 16)

        my_IDEA = IDEA(key)

        # Ciphertext input and transformation
        encrypted = input("Enter ciphertext (hex):\t")
        encrypted = int(encrypted, 16)
        sub_dec = []
        size = encrypted.bit_length()

        # Decryption
        if size % 64 != 0:
            x = size // 64 + 1
            size += 64 - size % 64
        else:
            x = size // 64
        decrypted = 0
        for i in range(x):
            shift = size - (i+1) * 64
            k = (encrypted >> shift) & 0xFFFFFFFFFFFFFFFF
            sub_dec.append(my_IDEA.decrypt(k))
        for i in range(x):
                sub_dec[i] = sub_dec[i] << (x - (i + 1)) * 64
                decrypted = decrypted | sub_dec[i]

        print(f"\nDecrypted:\thex: {hex(decrypted)}")
        print(f"\t\tuni: {decrypted.to_bytes(64, 'big').decode('ASCII')}\n")

    # No option selected
    else:
        pass 


if __name__ == '__main__':
    main()