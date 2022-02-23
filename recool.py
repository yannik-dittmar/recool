import argparse
import nmap
import json
from pwn import log
import ip_tools

def ParseArguments():
    parser = argparse.ArgumentParser(description='Reconstruct the hash for the I-Sec Keysafe.')
    parser.add_argument('-i', '--ip', dest='ip', metavar='IP', type=str, default=ip_tools.DefaultIP(),
                        help='Your local IP address.')
    parser.add_argument('-s', '--storage-file', dest='storage', metavar='STORAGE_FILE', type=str, default=None,
                        help='The file where information about the network will be stored or loaded from.')

    args = parser.parse_args()

    if not ip_tools.ParseIP(args.ip):
        log.error(f'The IP "{args.ip}" address you provided is not valid.')
    args.ip = ip_tools.ParseIP(args.ip)

    if not args.storage:
        args.storage = f'{args.ip}.json'

    return args

def PrintBanner():
    print("""

 /$$$$$$$                                          /$$
| $$__  $$                                        | $$
| $$  \ $$  /$$$$$$   /$$$$$$$  /$$$$$$   /$$$$$$ | $$
| $$$$$$$/ /$$__  $$ /$$_____/ /$$__  $$ /$$__  $$| $$
| $$__  $$| $$$$$$$$| $$      | $$  \ $$| $$  \ $$| $$
| $$  \ $$| $$_____/| $$      | $$  | $$| $$  | $$| $$
| $$  | $$|  $$$$$$$|  $$$$$$$|  $$$$$$/|  $$$$$$/| $$
|__/  |__/ \_______/ \_______/ \______/  \______/ |__/
                                                      
""")

if __name__ == '__main__':
    ParseArguments()
    PrintBanner()
    