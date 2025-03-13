#!/usr/bin/env python3

# Based on the Kerberoast script from Tim Medin to extract the Kerberos tickets
# from a kirbi file.
# Modification to parse them into the JTR-format by Michael Kramer (SySS GmbH)
# Copyright [2015] [Tim Medin, Michael Kramer]
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License

import argparse
import glob
from multiprocessing import Manager
from pyasn1.codec.ber import decoder

def main():
    parser = argparse.ArgumentParser(
        description='Read Mimikatz kerberos ticket then modify it and save it in crack_file'
    )
    parser.add_argument('files', nargs='+', metavar='file.kirbi',
                        help='File name to crack. Use asterisk "*" for many files.\n'
                             'Files are exported with mimikatz or from extracttgsrepfrompcap.py')
    args = parser.parse_args()

    manager = Manager()
    enctickets = manager.list()

    i = 0
    for path in args.files:
        for f in glob.glob(path):
            with open(f, 'rb') as fd:
                data = fd.read()

            # Check if the first byte equals 0x76 (i.e. 118 in decimal)
            if data[0] == 0x76:
                try:
                    decoded, _ = decoder.decode(data)
                    # The original indexing was: [0][2][0][3][2]
                    # Assuming the element is a pyasn1 type, we get its octets.
                    ticket = decoded[2][0][3][2].asOctets()
                except Exception as e:
                    print(f"Error decoding ticket from file {f}: {e}")
                    continue
                enctickets.append((ticket, i, f))
                i += 1

            # Else if the file starts with b'6d' (hex representation)
            elif data[:2] == b'6d':
                # Process each hex-encoded ticket (split by newline)
                for ticket_line in data.strip().split(b'\n'):
                    try:
                        # Convert hex string to binary data.
                        # First decode the bytes to a string, then convert.
                        ticket_data = bytes.fromhex(ticket_line.decode('ascii'))
                        decoded, _ = decoder.decode(ticket_data)
                        ticket = decoded[4][3][2].asOctets()
                    except Exception as e:
                        print(f"Error decoding hex ticket from file {f}: {e}")
                        continue
                    enctickets.append((ticket, i, f))
                    i += 1

    # Write the output in the expected JTR hash format.
    # Using text mode because we are writing a text string.
    with open("crack_file", "w") as out:
        for ticket, idx, filename in enctickets:
            # Convert the first 16 bytes and the rest into hex strings.
            ticket_hex1 = ticket[:16].hex()
            ticket_hex2 = ticket[16:].hex() if len(ticket) > 16 else ""
            line = f"$krb5tgs${filename}:{ticket_hex1}${ticket_hex2}\n"
            out.write(line)

if __name__ == '__main__':
    main()
