import argparse
from multiprocessing.connection import wait
from time import sleep
import nmap
import json
from yaspin import yaspin
from colored import fg, bg, attr, stylize
import logging as log
import ip_tools

STYLE_HIGHLIGHT = fg("orange_3") + attr("bold")
STYLE_SUCCESS = fg("green") + attr("bold")
STYLE_FAILURE = fg("red_3a") + attr("bold")

def parse_arguments():
    parser = argparse.ArgumentParser(description='Reconstruct the hash for the I-Sec Keysafe.')
    parser.add_argument('-i', '--ip', dest='ip', metavar='IP', type=str, default=ip_tools.default_ip(),
                        help='Your local IP address.')
    parser.add_argument('-s', '--storage-file', dest='storage', metavar='STORAGE_FILE', type=str, default=None,
                        help='The file where information about the network will be stored or loaded from.')
    parser.add_argument('--speed', dest='speed', metavar='SPEED', type=str, default='-T5',
                        help='An nmap speed argument. Default: T4')

    args = parser.parse_args()

    if not ip_tools.parse_ip(args.ip):
        log.error(f'The IP "{args.ip}" address you provided is not valid.')
    args.ip = ip_tools.parse_ip(args.ip)

    if not args.storage:
        args.storage = f'{args.ip.replace(".", "-")}.json'

    return args

def print_banner(args):
    # Clear terminal
    print(chr(27) + "[2J")

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
    
    log.info(f'Selected IP for network scanning: {stylize(args.ip, STYLE_HIGHLIGHT)}')
    log.info(f'Selected storage file: {stylize(args.storage, STYLE_HIGHLIGHT)}')
    log.info(f'Selected speed argument: {stylize(args.speed, STYLE_HIGHLIGHT)}')
    log.info('')

if __name__ == '__main__':
    log.basicConfig(encoding='utf-8', level=log.DEBUG, format='%(message)s')
    args = parse_arguments()
    print_banner(args)
    
    with yaspin(text="Initializing scan", color="yellow") as spinner:
        ns = ip_tools.NetworkScanner(args, [], spinner)
        ns.ping_scan_subnet('24')
        ns.full_scan_up()
    