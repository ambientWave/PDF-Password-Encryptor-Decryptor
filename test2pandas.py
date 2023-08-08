import pandas as pd
import csv
from datetime import datetime
import os
from sys import exit

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

log_file = pd.read_csv('test.csv')
df = pd.DataFrame(log_file)
TestString = int(df.iloc[0, -1], 16)
TestString_Bytes_Count = df.iloc[0, -2]
del log_file, df
# with open('test.csv', 'rb') as log_file:
#     try:  # catch OSError in case of a one line file
#         log_file.seek(-2, os.SEEK_END)
#         while log_file.read(1) != b'\n':
#             log_file.seek(-2, os.SEEK_CUR)
#     except OSError:
#         log_file.seek(0)
#     last_line = log_file.readline().decode()
#     print(last_line)
# with open("test.csv", "r") as log_file:
#     field_names = ['start_time', 'end_time', 'run_interval_hours', 'TestString_Bytes_Count', 'TestString']
#     csv_reader = csv.DictReader(log_file, delimiter=",", quotechar=' ', fieldnames=field_names, quoting=csv.QUOTE_NONNUMERIC)
#     csv_reader_list = list(csv_reader) # todo
#     print(csv_reader_list)
#     print(log_file.readlines(-1)[1][-8:-1]) #[0:TestString_Bytes_Count + 5])  # 0x2d8019
#     TestString = int(csv_reader['TestString'], 16)
#     TestString_Bytes_Count = int(csv_reader['TestString_Bytes_Count'], 10)
#     log_file.close()
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
        # LogFile = open("Log.txt", "a")
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
              bin(int.from_bytes(TestWord, "big"))[2:].zfill(256))  # , file=LogFile)
        HashInput = TestWord + OWNER + PValue + ID
        print("First Hash Input =", HashInput)
    except OverflowError:
        TestString_Bytes_Count += 1
        TestString -= 2
        pass
    except KeyboardInterrupt:
        end_time = datetime.now()
        # with open("test.csv", "a") as log_file:
        #     csv_writer = csv.DictWriter(log_file, fieldnames=field_names)
        #     # csv_writer.writeheader()
        #     csv_writer.writerow({'start_time': start_time, 'end_time': end_time, 'run_interval_hours': end_time - start_time, 'TestString_Bytes_Count': TestString_Bytes_Count, 'TestString': hex(TestString)})
        #     log_file.close()
        df = pd.DataFrame([{'start_time': start_time, 'end_time': end_time, 'run_interval_hours': end_time - start_time, 'TestString_Bytes_Count': TestString_Bytes_Count, 'TestString': hex(TestString)}])
        df.to_csv("test.csv", sep=",", mode='a', header=False)
        exit()
