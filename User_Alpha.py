import hashlib
from RC4 import encryption as RC4
Pad = 0X28BF4E5E4E758A4164004E56FFFA01082E2E00B6D0683E802F0CA9FE6453697A
#think about conversion of data from and to Ascii & UTF-8
USER = 0X872A1A1C24937669810CA9BB0093C30600000000000000000000000000000000
OWNER = 0XFBF4C8A869C1F92699465F0203C168D42B5BA43C7CA86771419AD0C03119B918
PValue = 0X400D0000
print(str(PValue))
ITRMDEHash = 0X0000000000000000000000000000000000000000000000000000000000000000
ID = 0X7DEEAD7F5A5ACB46A3B126DE5F216887
print(str(ID))
TestString = 0XFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
print(bin(TestString))
'''str function converts from any integer to decimal base integer
and str function doesn't alter the representation of ASCII characters
but ignore characters from other character sets'''
HashInput = str(TestString) + str(OWNER) + str(PValue) + str(ID)
print(HashInput)
#the idea is to find the right sequence of bits that when undergoes encryption transformation, equates to USER string
#then that sequence should be parsed by utf-8 to be entered in pdf viewer
while str(TestUser) != str(USER): #user passkey combination trial iterative loop
    TestString -= 1
    print(bin(TestString))
    HashInput = str(TestString) + str(OWNER) + str(PValue) + str(ID)
    FRSTHash = hashlib.md5(HashInput.encode()) #calling md5 hash method
    print(HashInput.encode())
    print(FRSTHash)
    ITRMDEHash = FRSTHash.hexdigest()
    print(ITRMDEHash)
    for x in range(1, 51):
        ITRMDEHash2 = hashlib.md5(ITRMDEHash.encode())
        ITRMDEHash = ITRMDEHash2.hexdigest()
    print(ITRMDEHash)
    # beginning of algorithm 3.5
    HashInput2 = str(Pad) + str(ID)
    ITRMDEHash3 = hashlib.md5(HashInput2.encode())
    ITRMDEHash4 = ITRMDEHash3.hexdigest()
    print(ITRMDEHash4)
    RC4.encryption().key =
    RC4.encryption().plain_text =
    RC4.encryption()
    for x in range(1, 20):
        RC4.encryption()
    TestUser = str(Pad[0:32])+ Final_ENCRPT_Step
    print(TestUser)
print(TestUser)