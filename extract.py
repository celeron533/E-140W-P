import lzw
import re
import sys
import requests
import logging as log
import xml.etree.ElementTree as ET  # python 3.2+

# log.basicConfig(format="%(levelname)s: %(message)s", level=log.INFO)

IP = "192.168.1.1"
header_pattern = r'<compressed alg=lzw len=(\d+)>.+<crc=0x([0-9A-Fa-f]+)>'
# password_pattern = r'<X_CT-COM_TeleComAccount>.*\n.*<Password>(.*)</Password>'
# pppoe_pattern = r'<Username>(\d\d*)</Username>\n.*<Password>(.*)</Password>'

requestUri = f"http://{IP}/downloadFile?file=/var/config/psi"
print(requestUri)
response = requests.get(requestUri)
if response.status_code != 200 :
    print('Unable to access the URI. Use your web browser to login useradmin first')
    sys.exit(1)

data = response.content
HEADER_LEN = 60
header = data[:HEADER_LEN]

match = re.search(header_pattern, str(header))
data_len = int(match.group(1))
print(f'Length:{data_len}')
compressed_data = data[HEADER_LEN : HEADER_LEN+data_len]
xml=""
try:
    # the file has multiple "pages" so we need to use the "PagingDecoder" here
    decoder = lzw.PagingDecoder(initial_code_size=258)
    log.info("LZW Decompressing data...")
    r = b"".join([b"".join(pg) for pg in decoder.decodepages(compressed_data)])
    xml = r.decode().rstrip()
    log.info("Data decompressed without any problem.")
except Exception as e:
    log.info(e)
    log.info("Data decompression failed! Possible file corruption.")
    sys.exit(1)

try:
    # workaround, there is a tag "<802-1pMark>" which does not following XML standard
    xml = xml.replace('802-1pMark','_802-1pMark')
    xml = xml[:-1] # workaround: remove the last '0x00'

    tree = ET.fromstring(xml)

    # teleadmin password
    # match = re.search(password_pattern, str(xml))
    # print("Password is: " + match.group(1))

    teleAdminNode = tree.find(".//X_CT-COM_TeleComAccount/Password")
    print(f'Telecomadmin Password: {teleAdminNode.text}')

    # pppoe password
    # match = re.search(pppoe_pattern, str(xml))
    # print("Phone number is: " + match.group(1))
    # print("Password is: " + match.group(2))

    pppNode = tree.find(".//WANPPPConnection")
    if pppNode:
        print(f'PPP Username: {pppNode.find("Username").text}')
        print(f'PPP Password: {pppNode.find("Password").text}')

except Exception as e:
    log.info(e)
    log.info("Error when looking up the config items.")
    sys.exit(1)