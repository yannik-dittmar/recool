#! /usr/bin/env python3

import argparse
from multiprocessing.connection import wait
from time import sleep
from pathlib import Path
from yaspin import kbi_safe_yaspin
from colored import fg, bg, attr, stylize
import logging as log
from shutil import which
import os
import ip_tools

STYLE_HIGHLIGHT = fg("orange_3") + attr("bold")
STYLE_SUCCESS = fg("green") + attr("bold")
STYLE_FAILURE = fg("red_3a") + attr("bold")

def parse_arguments():
    parser = argparse.ArgumentParser(description='Automatic network scanner with nplan for network graphs.')
    parser.add_argument('-i', '--ip', type=str, default=None,
                        help='Your local IP address.')
    parser.add_argument('-I', '--iface', metavar='INTERFACE', type=str, required=True,
                        help='The interface that will be used for scanning.')
    parser.add_argument('-s', '--storage-folder', dest='storage', metavar='PATH', type=Path, default="./dist",
                        help='The folder where information about the network will be stored or loaded from.')
    parser.add_argument('--speed', type=str, default='T4',
                        help='An nmap speed argument. Default: T4')
    parser.add_argument('--nplan-path', dest='nplan', metavar='PATH', type=Path, default='nplan',
                        help='The path to the nplan binary. (e.g. /usr/bin/nplan)')
    parser.add_argument('--no-ipv6', action='store_true',
                        help='Do not scan for IPv6 addresses.')
    parser.add_argument('-c', '--cleanup', action='store_true',
                        help='Clear the nplan model and recool save data.')
    parser.add_argument('-u', '--ultra', action='store_true',
                        help='Perform an ULTRA-scan. (ping-scan on /16 subnet)')
    parser.add_argument('--disable-arp-ping', action='store_true',
                        help='Disables ARP-Ping for machines in local network during aggressive scan. (See nmap documentation)')

    args = parser.parse_args()

    # Cleanup
    if args.cleanup:
        cleanup(args)

    # IP check
    if not args.ip:
        args.ip = ip_tools.default_ip(args.iface)
    if not ip_tools.parse_ip(args.ip):
        log.error(f'The IP "{args.ip}" address you provided is not valid.')
    args.ip = ip_tools.parse_ip(args.ip)

    # Create storage folder
    args.storage.mkdir(parents=True, exist_ok=True)

    # Format nmap speed argument
    args.speed = '-' + args.speed

    return args

def cleanup(args):
    # Clean nplan model
    os.system(f'{args.nplan} -json {args.storage}/model.json -fresh > /dev/null')

    # Clean recool save data
    if os.path.exists(f'{args.storage}/recool_save.json'):
        os.remove(f'{args.storage}/recool_save.json')
    if os.path.exists(f'{args.storage}/recool_save_new.json'):
        os.remove(f'{args.storage}/recool_save_new.json')
    if os.path.exists(f'{args.storage}/scan.xml'):
        os.remove(f'{args.storage}/scan.xml')

    log.info(f'Cleanup finished!')
    
    exit(0)

def print_banner(args):
    # Clear terminal
    #os.system('cls' if os.name == 'nt' else 'clear')

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
    
    log.info(f'{stylize("=====WARNING=====", STYLE_HIGHLIGHT)}')
    log.info(f'If recool is not closed properly, {stylize("nmap scans may still continue to run in the background", STYLE_FAILURE)}!')
    log.info(f'To check for running scans, run {stylize("ps aux | grep nmap", STYLE_HIGHLIGHT)}.')
    log.info(f'To kill a running scan, run {stylize("sudo kill PID", STYLE_HIGHLIGHT)}.')
    log.info(f'To {stylize("safely exit", STYLE_HIGHLIGHT)} recool you may press {stylize("CTR+C", STYLE_HIGHLIGHT)} at any time.')
    log.info('')

    log.info(f'{stylize("====ARGUMENTS====", STYLE_HIGHLIGHT)}')
    log.info(f'Interface for scanning: {stylize(args.iface, STYLE_HIGHLIGHT)}')
    log.info(f'IP for scanning: {stylize(args.ip, STYLE_HIGHLIGHT)}')
    log.info(f'Storage folder: {stylize(args.storage, STYLE_HIGHLIGHT)}')
    log.info(f'Speed argument: {stylize(args.speed, STYLE_HIGHLIGHT)}')
    log.info('')

def main():
    log.basicConfig(encoding='utf-8', level=log.DEBUG, format='%(message)s')
    args = parse_arguments()

    # Print the banner and arguments
    print_banner(args)

    # Check if nplan is installed
    if not which(args.nplan):
        if args.nplan == 'nplan':
            log.error(f'{stylize("ERROR!", STYLE_FAILURE)} {stylize("nplan", STYLE_HIGHLIGHT)} is not installed!')
            log.error(f'Visit {stylize("https://github.com/richartkeil/nplan", STYLE_HIGHLIGHT)}')
            log.error(f'Or specify the path to the executable with the {stylize("--nplan-path", STYLE_HIGHLIGHT)} argument.')
        else:
            log.error(f'{stylize("ERROR!", STYLE_FAILURE)} Could not find nplan at {stylize(args.nplan, STYLE_HIGHLIGHT)}!')
        exit(1)

    # Check if scan6 is installed
    if not which('scan6') and not args.no_ipv6:
        log.error(f'{stylize("ERROR!", STYLE_FAILURE)} {stylize("scan6", STYLE_HIGHLIGHT)} is not installed!')
        log.error(f'Run {stylize("sudo apt install ipv6-toolkit", STYLE_HIGHLIGHT)} to install it.')
        log.error(f'Or disable IPv6 scanning with the {stylize("--no-ipv6", STYLE_HIGHLIGHT)} argument.')
        exit(1)

    # Check if run as sudo
    if os.geteuid() != 0:
        log.error(f'{stylize("ERROR!", STYLE_FAILURE)} Please start Recool with {stylize("sudo", STYLE_HIGHLIGHT)}!')
        exit(1)

    with kbi_safe_yaspin(text="Initializing recool", color="yellow") as spinner:
        ns = ip_tools.NetworkScanner(args, spinner)
        #ns.test()
        #return
        ns.load_devices()
        ns.ping_scan_subnet('24')
        ns.full_scan_up()
        
        ns.aggressive_scan_subnet('24')
        ns.full_scan_up()
        
        if not args.no_ipv6:
            ns.ipv6_scan()
        
        ns.router_scan()
        ns.ping_scan()
        ns.full_scan_up()

        if args.ultra:
            ns.ultra_scan()
            ns.full_scan_up()

if __name__ == '__main__':
    main()
