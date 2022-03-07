from imp import is_builtin
import socket
import ipaddress
from telnetlib import NOP
from typing import List, Set
import nmap
import json
from json import JSONEncoder
import logging as log
from colored import fg, bg, attr, stylize
import recool

def parse_ip(ip):
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return False

def default_ip():
    #return socket.gethostbyname(socket.gethostname())
    return "192.168.188.10"

def keys_exists(element, *keys):
    '''
    Check if *keys (nested) exists in `element` (dict).
    '''
    if not isinstance(element, dict):
        raise AttributeError('keys_exists() expects dict as first argument.')
    if len(keys) == 0:
        raise AttributeError('keys_exists() expects at least two arguments, one given.')

    _element = element
    for key in keys:
        try:
            _element = _element[key]
        except KeyError:
            return False
    return True

class NetworkDevice():
    done_ping_scan: bool
    done_scan: bool
    is_up: bool
    name: str
    ipv4: Set[str]
    ipv6: Set[str]

    def __init__(self, **kv):
        self.done_ping_scan = False
        self.done_scan = False
        self.is_up = False
        self.name = ""
        self.ipv4 = set()
        self.ipv6 = set()
        self.__dict__.update(kv)

class NetworkEncoder(JSONEncoder):
    def default(self, o):
        if isinstance(o, set):
            return list(o)

        return o.__dict__

class NetworkScanner:
    def __init__(self, args, devices, spinner):
        self.nmap = nmap.PortScanner()
        self.args = args
        self.devices: List[NetworkDevice] = devices
        self.spinner = spinner
    
    def find_by_address(self, address):
        for d in self.devices:
            if address in d.ipv4:
                return d

        device = NetworkDevice()
        self.devices.append(device)
        return device


    def parse_device_data(self, address, data):
        device: NetworkDevice = self.find_by_address(address)

        # Hostname
        if (keys_exists(data, 'hostnames', 0, 'name') and 
                data['hostnames'][0]['name']):
            device.name = data['hostnames'][0]['name']
        
        # IPv6
        if keys_exists(data, 'addresses', 'ipv6'):
            device.ipv6.add(data['addresses']['ipv6'])
        
        return device

    def ping_scan_subnet(self, subnet: str):
        iface = ipaddress.ip_interface(self.args.ip + '/' + subnet)
        self.spinner.text = f'Performing ping-scan on subnet {stylize(str(iface.network), recool.STYLE_HIGHLIGHT)}'
        
        # Collect hosts
        hosts = []
        for host in iface.network.hosts():
            device: NetworkDevice = self.find_by_address(str(host))
            device.ipv4.add(str(host))
            if not device.done_ping_scan and not device.is_up:
                hosts.append(str(host))
        
        if not hosts:
            return

        # Perform scan and collect data
        result = self.nmap.scan(hosts=' '.join(hosts), arguments=f'-sn -n {self.args.speed}')["scan"]
        for ip, data in result.items():
            device = self.parse_device_data(ip, data)
            device.is_up = True
        
        # Update done_ping_scan
        for host in iface.network.hosts():
            device = self.find_by_address(str(host))
            device.done_ping_scan = True

    def full_scan_up(self):
        for device in self.devices:
            if not device.is_up or device.done_scan:
                continue
        
            self.spinner.text = f'Performing full-scan for: {stylize(next(iter(device.ipv4)), recool.STYLE_HIGHLIGHT)}'
            result = self.nmap.scan(hosts=next(iter(device.ipv4)), arguments=f'-A -p- {self.args.speed}')["scan"]
            for ip, data in result.items():
                device = self.parse_device_data(ip, data)
                device.done_scan = True

        self.spinner.write(json.dumps(self.devices, cls=NetworkEncoder))