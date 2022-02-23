import socket
import ipaddress
from tkinter.ttk import Style
import nmap
from pwn import log
from colored import fg, bg, attr, stylize
import recool

def parse_ip(ip):
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return False

def default_ip():
    return socket.gethostbyname(socket.gethostname())

def paint_number(number):
    if number == '0':
        return stylize(number, recool.STYLE_FAILURE)
    return stylize(number, recool.STYLE_SUCCESS)

class NetworkScanner:
    def __init__(self, ip, storage, speed=None):
        self.nmap = nmap.PortScanner()
        self.ip = ip
        self.storage = storage
        self.speed = speed
        
        if not self.speed:
            self.speed = '-T4'
        
    def ping_scan_subnet(self, subnet):
        iface = ipaddress.ip_interface(self.ip + '/' + subnet)
        with log.progress(f'Ping-Scanning subnet {stylize(iface.network, recool.STYLE_HIGHLIGHT)}') as p:
            result = self.nmap.scan(hosts=str(iface.network), arguments=f'-sn -n {self.speed}')
            p.success(f'Found {paint_number(result["nmap"]["scanstats"]["uphosts"])} hosts.')