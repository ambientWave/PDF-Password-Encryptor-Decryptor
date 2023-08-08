# -> todo 29/10/2022 2h, from 11:00 am to 1:00 pm, set TestString_Bytes_Count to 3, set TestString to 0x425c1f, 0x1c1919, set ascii_limiter to 0x420000
#
# 2507526 change in TestString took 2h (about 15 times more efficient & faster than to scan all possible bit states
#
# 20 bit combination took 3h at 3rd byte
# 656684 trial took 4.8
# 493317 trial took 4.16 h
# 622552 trial took 4.5  h
import hashlib
from RC4 import encryption as RC4
Pad = b'\x28\xbf\x4e\x5e\x4e\x75\x8a\x41\x64\x00\x4e\x56\xff\xfa\x01\x08\x2e\x2e\x00\xb6\xd0\x68\x3e\x80\x2f\x0c\xa9\xfe\x64\x53\x69\x7a'
# think about conversion of data from and to Ascii & UTF-8
USER = b'\x87\x2a\x1a\x1c\x24\x93\x76\x69\x81\x0c\xa9\xbb\x00\x93\xc3\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
print(USER)
OWNER = b'\xfb\xf4\xc8\xa8\x69\xc1\xf9\x26\x99\x46\x5f\x02\x03\xc1\x68\xd4\x2b\x5b\xa4\x3c\x7c\xa8\x67\x71\x41\x9a\xd0\xc0\x31\x19\xb9\x18'
PValue = b'\x40\x0d\x00\x00'
print(str(PValue))
ITRMDEHash = 0X0000000000000000000000000000000000000000000000000000000000000000
ID = b'\x7d\xee\xad\x7f\x5a\x5a\xcb\x46\xa3\xb1\x26\xde\x5f\x21\x68\x87'
print(str(ID))
TestString = 0x2d1919
ascii_limiter = 0x2d0000  # observe the most significant numbers of TestString in the consoleincrement by 0x10000 when TestString = 0x2c8080. This pattern should be repeated until TestString = 0x808080
print(bin(TestString))
print(str(TestString))  # not equal to bin(TestString)
TestUser = "0"
TestString_Bytes_Count = 3
'''str function converts from any integer to decimal base integer
and str function doesn't alter the representation of ASCII characters
but ignore characters from other character sets'''
# the idea is to find the right sequence of bits that when undergoes encryption transformation, equates to USER string
# then that sequence should be parsed by utf-8 to be entered in pdf viewer
while (int(TestUser, 2).to_bytes(32, byteorder='big')) != USER:  # user passkey combination trial iterative loop
    try:
        # LogFile = open("Log.txt", "a")
        TestString += 1
        if TestString - ascii_limiter in [j for j in range(0x1980, 0x807c, 0x100)]:  # TestString and conditional values need to be updated if a ValueError shows up
            TestString += 0x99
        #  todo if TestString - ascii_limiter in [j for j in range(0x191980, 0x19807c, 0x100)]: # replace these lines with the above conditional statement
        #    TestString += 0x99
        #  todo elif TestString - ascii_limiter in [j for j in range(0x198080, 0x80807c, 0x10000)]:
        #    TestString += 0x9899
        elif TestString == ascii_limiter + 0x8080:  # TestString and conditional values need to be updated if a ValueError shows up
            TestString += 0x9899
            ascii_limiter += 0x10000
        elif TestString > 0x808080:
            raise ValueError
        else:
            pass
        print("Current Password Combination in decimal representation", TestString)
        TestWord = TestString.to_bytes(TestString_Bytes_Count, byteorder='big') + Pad[:32-TestString_Bytes_Count]
        print("Current Password Combination with padding in Bytes", TestWord)
        print("Current Password Combination with padding in Binary", bin(int.from_bytes(TestWord, "big"))[2:].zfill(256))  # , file=LogFile)
        HashInput = TestWord + OWNER + PValue + ID
        print("First Hash Input =", HashInput)
        FRSTHash = hashlib.md5(HashInput) # calling md5 hash method. (b'1' == 1) is not True
        #print("HashInput.encode =", HashInput)  # ******need further analysis. encode() converts string to respective utf-8 values not the actual string
        #print("FRSTHash =", FRSTHash)
        ITRMDEHash = FRSTHash.digest()
        print("first hash digest =", ITRMDEHash)
        for x in range(1, 51):
            ITRMDEHash2 = hashlib.md5(ITRMDEHash)
            ITRMDEHash = ITRMDEHash2.digest()
        ITRMDEHash_bin_trimmed = bin(int.from_bytes(ITRMDEHash, "big"))[2:].zfill(128)  # after the conversion to integer, most significant bits may be zeros. These zeros are omitted
        print("first hash digest = encryption key =", ITRMDEHash_bin_trimmed)
        # print(hex(int.from_bytes(ITRMDEHash, "big")))
        # beginning of algorithm 3.5
        # step 2, 3 in algorithm 3.5
        HashInput2 = Pad + ID
        ITRMDEHash3 = hashlib.md5(HashInput)
        ITRMDEHash4 = ITRMDEHash3.digest()
        ITRMDEHash4_bin_trimmed = bin(int.from_bytes(ITRMDEHash4, "big"))[2:].zfill(128)
        print("second hash digest = first encryption input =", ITRMDEHash4_bin_trimmed)
        #print(hex(int(ITRMDEHash4, 16))) #printing ITRMDEHash4 string after converting it to hexadecimal integer. It should be the same as the above digest except it's now hexadecimal integer not a string data type
        # step 4 in algorithm 3.5
        ECRPT_STR = RC4(ITRMDEHash_bin_trimmed, ITRMDEHash4_bin_trimmed, 8)
        print("encrypted string before loop", ECRPT_STR) # it's observed that once for loop is entered, it gives the same result as all trials
        # step 5 in algorithm 3.5
        '''key_bin = bin(int.from_bytes(ITRMDEHash, "big"))
        print("key_bin" ,key_bin)
        key_bin_str = key_bin.lstrip('-0b')
        print("key_bin_str", key_bin_str)'''
        key_byte_list = [ITRMDEHash_bin_trimmed[i:i + 8] for i in range(0, 128, 8)]
        print(key_byte_list)
        '''key generated by taking each byte of the original encryption key (obtained in step 1) and performing an XOR (exclusive or) operation between that
        byte and the single-byte value of the iteration counter (from 1 to 19)'''
        for y in range(1, 20):
            iter_count_str = bin(y)[2:]  # this is a string because of index operator
            iter_count_str_byte_pad = iter_count_str.zfill(8)
            epoch_key_list = [ord(a) ^ ord(b) for i in range(0, 16) for a,b in zip(key_byte_list[i], iter_count_str_byte_pad)]  # interpreter evaluates from the end of list comprehension. It iterates first through zip object using the left-side expression which by itself a for loop. The zip() function creates a zip object which is an iterator. Therefore, the right-hand for loop march through byte's string until it hits StopIteration exception then right-hand for loop marches one step in the interval [0,16)       print("{}th Epoch key string".format(y) ,''.join([str(elem) for elem in epoch_key_list]))
            #epoch_key = int(ITRMDEHash, 16) ^ y # ******@@#$$$$###***$$#*****need further analysis. Each 8 bits of ITRMDEHash should be fragmented and xor with y then appended with same order. what should be used list, array or dictionary?
            print("encrypted string of {0}th epoch (input of encryption)".format(y-1), ECRPT_STR)
            ITRMDE_ECRPT_INPUT = ECRPT_STR
            ECRPT_STR = RC4(''.join([str(elem) for elem in epoch_key_list]), ITRMDE_ECRPT_INPUT, 8)  # ****** n need further analysis after each iteration
            FNAL_ECRPT_STR = ECRPT_STR
            print("encrypted string of {0}th epoch (output of encryption)".format(y), ECRPT_STR)
        TestUser = FNAL_ECRPT_STR.ljust(256, "0") #+ "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" # 124 bit 0 padding to be appended'''. ******** RC4 is invoked again for 21th time !
        print("User Value based on Tried Password Combination in Binary =", TestUser)  # , file=LogFile)
        print("User Value based on Tried Password Combination in hexadecimal =", hex(int(TestUser, 2)))
        print("User Value based on Tried Password Combination in bytes =", int(TestUser, 2).to_bytes(32, byteorder='big'))  # , file=LogFile)
        # LogFile.close()
    except OverflowError:
        TestString_Bytes_Count += 1
        TestString -= 2
        pass
print("We have a Hit!", TestString)
