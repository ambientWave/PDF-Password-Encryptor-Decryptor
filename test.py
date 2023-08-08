from datetime import datetime, timedelta
import sys
from re import compile
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
with open("test.txt", "r") as log_file:
    lines = log_file.readlines()
    lastTestString, TestString = int(lines[1], 16), int(lines[1], 16)  # 0x2d8019
    TestString_Bytes_Count = int(lines[2], 10)
    total_time_str = lines[5][8:]
    print(total_time_str[0:2])
    time_sep = compile('[:.]')
    total_time_list = [int(i) for i in time_sep.split(total_time_str)]
    print(total_time_list)
    total_time = timedelta(days=int(lines[5][0:1]), hours=total_time_list[0], minutes=total_time_list[1], seconds=total_time_list[2], microseconds=total_time_list[3])
    print(total_time)
    del lines
    log_file.close()
TestUser = "0"
TestString_bytes = TestString.to_bytes(TestString_Bytes_Count, byteorder='big')
start_time = datetime.now()
# print(TestString_bytes[0] + 1)
# print(type(TestString_bytes))
'''str function converts from any integer to decimal base integer
and str function doesn't alter the representation of ASCII characters
but ignore characters from other character sets'''
# the idea is to find the right sequence of bits that when undergoes encryption transformation, equates to USER string
# then that sequence should be parsed by utf-8 to be entered in pdf viewer

while (int(TestUser, 2).to_bytes(32, byteorder='big')) != USER:  # user passkey combination trial iterative loop
    try:
        # log_file = open("Log.txt", "a")
        TestString += 1
        TestString_bytes = TestString.to_bytes(TestString_Bytes_Count, byteorder='big')
        for b in range(-1, -TestString_Bytes_Count - 1, -1):
            if 0x80 >= TestString_bytes[b] >= 0x19:
                pass
            elif TestString_bytes[b] == 0x81:
                TestString += (((TestString + (0x100 ** (-b))) - (0x68 * (0x100 ** (-b - 1)))) - TestString)
        print("Current Password Combination in decimal representation", TestString)
        TestWord = TestString.to_bytes(TestString_Bytes_Count, byteorder='big') + Pad[:32 - TestString_Bytes_Count]
        print("Current Password Combination with padding in Bytes", TestWord)
        print("Current Password Combination with padding in Binary",
              bin(int.from_bytes(TestWord, "big"))[2:].zfill(256))  # , file=log_file)
        HashInput = TestWord + OWNER + PValue + ID
        print("First Hash Input =", HashInput)
    except OverflowError:
        TestString_Bytes_Count += 1
        TestString -= 2
        pass
    except KeyboardInterrupt:
        with open("test.txt", "w") as log_file:
            end_time = datetime.now()
            elapsed_time = end_time - start_time
            log_file.write("{0}\n{1}\n{2}\nfrom {3} to {4}\n{5}\n0 days, {6}".format(hex(lastTestString), hex(TestString - 1), TestString_Bytes_Count, start_time, end_time, elapsed_time, total_time + elapsed_time))
            log_file.close()
            sys.exit()
