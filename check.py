from idea import IDEA
from sys import getsizeof
from struct import calcsize
from ctypes import sizeof

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

        #ask = input('Use default plaintext? (y/n)\t')
        #if ask == 'y':
        #    encrypted = my_IDEA.encrypt(plain)
        #elif ask == 'n':
        if 1:
            plain = input("Enter plain (ASCII):\t\t")
            plain = int.from_bytes(plain.encode("ASCII"), 'big')
            size = plain.bit_length()
            sub_plain = []
            sub_enc = []
            #print(f"\nSize: {size}\n")
            if size > 64:
                x = size // 64
                if size % 64 != 0:
                    x += 1
                    size += 64 - size % 64
                for i in range(x):
                    #print(i)
                    shift = size - (i+1) * 64
                    #print(f"Shift: {shift}")
                    sub_plain.append((plain >> shift) & 0xFFFFFFFFFFFFFFFF)
                    #print(f"Pla: {hex(sub_plain[i])}")
                    encrypted = my_IDEA.encrypt(sub_plain[i])
                    sub_enc.append(encrypted)
                    encrypted = 0
                for i in range(x):
                    sub_enc[i] = sub_enc[i] << (x - (i + 1)) * 64
                    encrypted = encrypted | sub_enc[i]

            else:
                encrypted = my_IDEA.encrypt(plain)

        print(f"\nEncrypted:\thex: {hex(encrypted)}\n")

        ask = input("Decrypt / Check? (y/n)\t\t")
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
        encrypted = int(encrypted, 16)
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


if __name__ == '__main__':
    main()