from http import server
import socket
import ipaddress
from telnetlib import NOP
from typing import Dict, List, Set
import nmap
import os
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
    #return "172.22.3.170"
    return "10.129.0.217"

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
    done_full_scan: bool
    is_up: bool
    name: str
    ip: str
    services: Dict[str, str]

    def __init__(self, **kv):
        self.done_ping_scan = False
        self.done_full_scan = False
        self.is_up = False
        self.name = ""
        self.ip = ""
        self.services = {}
        self.__dict__.update(kv)

    def __str__(self) -> str:
        string = ""

        # Name and IP
        if self.name:
            string += f'==={stylize(self.name, recool.STYLE_HIGHLIGHT)}===\n'
        else:
            string += f'==={stylize(self.ip, recool.STYLE_HIGHLIGHT)}===\n'
        string += f'{stylize("IP:", recool.STYLE_HIGHLIGHT)} {self.ip}\n'

        # Services
        print_services = False
        ports = self.services.keys()
        for port in sorted(ports):
            portInfo = self.services[port]
            if portInfo["state"] == "open":
                print_services = True
                break

        if print_services:
            string += f'Open {stylize("TCP", recool.STYLE_HIGHLIGHT)}-Ports:\n'
            for port in sorted(ports):
                portInfo = self.services[port]
                if portInfo["state"] != "open":
                    continue
                
                portName = portInfo["name"]
                portProd = portInfo["product"]
                portVer = portInfo["version"]

                if portName == "":
                    string += f' - {stylize(port, recool.STYLE_HIGHLIGHT)}\n'
                elif portProd == "":
                    string += f' - {stylize(port, recool.STYLE_HIGHLIGHT)} ({portName})\n'
                elif portVer == "":
                    string += f' - {stylize(port, recool.STYLE_HIGHLIGHT)} ({portName} - {portProd})\n'
                else:
                    string += f' - {stylize(port, recool.STYLE_HIGHLIGHT)} ({portName} - {portProd}, {portVer})\n'

        return string

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

    def scan(self, hosts: List[str], args: str):
        os.system(f'sudo nmap -oX ./{self.args.storage}/scan.xml {args} {self.args.speed} {" ".join(hosts)} > /dev/null')
        with open(f'./{self.args.storage}/scan.xml',mode='r') as scan_file:
            result = self.nmap.analyse_nmap_xml_scan(nmap_xml_output=scan_file.read())

        return result["scan"]
    
    def find_by_ip(self, ip, create=True):
        for d in self.devices:
            if ip == d.ip:
                return d

        if create:
            device = NetworkDevice(ip=ip)
            self.devices.append(device)
            return device
        return None

    def parse_device_data(self, ip, data):
        device: NetworkDevice = self.find_by_ip(ip)

        # Hostname
        if (keys_exists(data, 'hostnames', 0, 'name') and 
                data['hostnames'][0]['name']):
            device.name = data['hostnames'][0]['name']
        
        if (keys_exists(data, 'tcp')):
            for port, info in data['tcp'].items():
                device.services[port] = info

        return device

    def ping_scan_subnet(self, subnet: str):
        iface = ipaddress.ip_interface(self.args.ip + '/' + subnet)
        self.spinner.text = f'Performing ping-scan on subnet {stylize(str(iface.network), recool.STYLE_HIGHLIGHT)}'
        
        # Collect hosts
        hosts = []
        for host in iface.network.hosts():
            device: NetworkDevice = self.find_by_ip(str(host))
            if not device.done_ping_scan and not device.is_up:
                hosts.append(str(host))
        
        if not hosts:
            return

        # Perform scan and collect data
        result = self.scan(hosts, '-sn -n')
        for ip, data in result.items():
            device = self.parse_device_data(ip, data)
            device.is_up = True
        
        # Update done_ping_scan
        for host in iface.network.hosts():
            device = self.find_by_ip(str(host))
            device.done_ping_scan = True

        #self.spinner.write(json.dumps(self.devices, cls=NetworkEncoder))

    def full_scan_up(self, devices=None):
        if not devices:
            devices = self.devices

        for device in devices:
            if not device.is_up or device.done_full_scan:
                continue
        
            self.spinner.text = f'Performing full-scan for: {stylize(device.ip, recool.STYLE_HIGHLIGHT)}'
            result = self.scan([device.ip], '-A -p- -sV')
            for ip, data in result.items():
                device = self.parse_device_data(ip, data)
                device.done_full_scan = True
                self.spinner.write(str(device))

            #self.spinner.write(json.dumps(self.devices, cls=NetworkEncoder))

    def test(self):
        result = self.nmap.scan(hosts="10.129.0.2", arguments=f'{self.args.speed}')["scan"]
        #self.spinner.write(self.nmap.)