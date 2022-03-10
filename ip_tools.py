#! /usr/bin/env python3

from cmath import exp
from http import server
from pathlib import Path
import signal
import socket
import ipaddress
import subprocess
from telnetlib import NOP
import threading
import time
from typing import Dict, List, Set
import nmap
import os
import json
from json import JSONEncoder
from colored import fg, bg, attr, stylize
import inquirer
import netifaces as ni
import recool

def parse_ip(ip):
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return False

def default_ip(iface: str):
    ni.ifaddresses(iface)
    return ni.ifaddresses(iface)[ni.AF_INET][0]['addr']
    
    #return socket.gethostbyname(socket.gethostname())
    #return "172.22.3.170"
    #return "192.168.188.10"
    #return "10.129.0.217"

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

def delete_old_saves(path, min=20):
    '''
    Delete files in `path` older than `min` minutes.
    '''
    for file in Path(path).glob('*'):
        if time.time() - file.stat().st_mtime > min * 60:
            file.unlink()

class NetworkDevice():
    done_ping_scan: bool
    done_full_scan: bool
    done_agg_scan: bool
    is_up: bool
    name: str
    ip: str
    services: Dict[str, str]

    def __init__(self, **kv):
        self.ip = ""
        self.__dict__.update(kv)

    def __getattr__(self, item):
        return None

    def add_service(self, port, info):
        if not self.services:
            self.services = {}
        self.services[port] = info

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
        if self.services:
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
        if isinstance(o, NetworkDevice):
            parsed = dict(o.__dict__)
            if 'ip' in parsed:
                del parsed['ip']
            return parsed

        return o.__dict__

class NmapProgressUpdater(threading.Thread):
    abort: bool
    spinner: any
    stats_path: str
    prefix: str

    def __init__(self, **kv):
        threading.Thread.__init__(self)
        self.abort = False
        self.__dict__.update(kv)

    def run(self):
        self.prefix = self.spinner.text
        self.spinner.text += ' - Starting nmap...'
        time.sleep(2)
        while not self.abort:
            stats = ''
            hosts = '(0, 0)'
            if os.path.exists(self.stats_path):
                with open(self.stats_path, mode='r') as stats_f:
                    for line in stats_f:
                        if '%' in line:
                            stats = line.rstrip("\n")
                        if 'hosts completed' in line:
                            completed = line.split(',')[0].split('; ')[1].split(' ')[0]
                            undergoing = line.split(', ')[1].split(' ')[0]
                            hosts = f'(C: {completed}, U:{undergoing})'
                            if undergoing == '1':
                                hosts = ''
                if stats:
                    self.spinner.text = f'{self.prefix} - {stats.split(";")[0]} {hosts}'
            time.sleep(1)

class NetworkScanner:
    INT_SKIP = "skip"
    INT_RESTART = "restart"
    INT_SKIP_HOST = "skip_host"
    INT_SKIP_HOST_SCANNED = "skip_host_scanned"
    INT_SKIP_QUEUED = "skip_queued"
    INT_SKIP_QUEUED_SCANNED = "skip_queued_scanned"

    def __init__(self, args, spinner):
        self.nmap = nmap.PortScanner()
        self.args = args
        self.devices: Dict[str, NetworkDevice] = {}
        self.spinner = spinner
        self.scan_proc = None
        self.interrupt_msg = ""
        self.interrupt_action = None
        self.handling_interrupt = False

    def scan(self, hosts: List[str], args: List[str], sig_handler):
        original_sigint_handler = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, sig_handler)

        # Start nmap scan
        thread = NmapProgressUpdater(spinner=self.spinner, stats_path=f'{self.args.storage}/nmap.log')
        thread.daemon = True
        thread.start()
        with open(f'{self.args.storage}/nmap.log', 'w') as log, open(f'{self.args.storage}/nmap.error', 'w') as err:
            try:
                self.scan_proc = subprocess.Popen(
                    ['sudo', 'nmap', '-e', self.args.iface, '-oX', f'{self.args.storage}/scan.xml', '--stats-every', '3s', *args, self.args.speed, *hosts], 
                    stdout=log, stderr=err, 
                    start_new_session=True)
                self.scan_proc.wait()
            finally:
                if self.scan_proc:
                    self.scan_proc.kill()
                self.scan_proc = None
        thread.abort = True
        while self.handling_interrupt:
            time.sleep(0.3)
        signal.signal(signal.SIGINT, original_sigint_handler)

        # Parse scan results
        try:
            with open(f'{self.args.storage}/scan.xml',mode='r') as scan_file:
                result = self.nmap.analyse_nmap_xml_scan(nmap_xml_output=scan_file.read())
        except (nmap.PortScannerError, FileNotFoundError):
            return None

        return result["scan"]

    def find_by_ip(self, ip, create=True):
        if keys_exists(self.devices, ip):
            return self.devices[ip]

        if create:
            device = NetworkDevice(ip=ip)
            self.devices[ip] = device
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
                device.add_service(port, info)

        return device

    #region Export, save and load
    def update_model(self, export=True):
        # Export
        if export:
            self.spinner.text = f'Updating the nplan model...'
            os.popen(f'{self.args.nplan} -nmap {self.args.storage}/scan.xml -json {self.args.storage}/model.json > /dev/null').read()
            os.popen(f'{self.args.nplan} -export -json {self.args.storage}/model.json -drawio {self.args.storage}/drawio.xml > /dev/null').read()
            os.system(f'chmod 666 -R {self.args.storage}')

        # Save current state
        self.spinner.text = f'Saving the current state... (DO NOT EXIT)'
        with open(f'{self.args.storage}/recool_save_new.json', 'w') as outfile:
            json.dump(self.devices, outfile, cls=NetworkEncoder)
        
        # Archive old save file
        if os.path.exists(f'{self.args.storage}/recool_save.json'):
            if not os.path.exists(f'{self.args.storage}/old_saves/'):
                Path(f'{self.args.storage}/old_saves/').mkdir(parents=True, exist_ok=True)
            count = 1
            while os.path.exists(f'{self.args.storage}/old_saves/recool_save_{count}.json'):
                count += 1
            os.rename(f'{self.args.storage}/recool_save.json', f'{self.args.storage}/old_saves/recool_save_{count}.json')
            delete_old_saves(f'{self.args.storage}/old_saves/', min=1)
        # Move new save to current save
        os.rename(f'{self.args.storage}/recool_save_new.json', f'{self.args.storage}/recool_save.json')

    def load_devices(self):
        if not os.path.exists(f'{self.args.storage}/recool_save.json'):
            return
        
        storage = {}
        with open(f'{self.args.storage}/recool_save.json', 'r') as f:
            storage = json.load(f)

        for ip, device in storage.items():
            self.devices[ip] = NetworkDevice(**device)
            self.devices[ip].ip = ip
    #endregion

    #region ping scan
    def ping_scan_sh(self, sig, frame):
        self.handling_interrupt = True
        questions = [
            inquirer.List('action',
                            message=self.interrupt_msg,
                            carousel=True,
                            choices=[
                                'Continue scanning',
                                'Restart scan',
                                'Skip ping-scan',
                                'Skip ping-scan and mark all hosts as ping-scanned',
                                stylize("Exit recool", recool.STYLE_FAILURE)],
                        ),
        ]
        with self.spinner.hidden():
            answer = inquirer.prompt(questions)['action']
        if self.scan_proc and answer != 'Continue scanning':
            self.scan_proc.send_signal(signal.SIGINT)
        if answer == 'Restart scan':
            self.interrupt_action = NetworkScanner.INT_RESTART
        if answer == 'Skip ping-scan':
            self.interrupt_action = NetworkScanner.INT_SKIP
        if answer == 'Skip ping-scan and mark all hosts as ping-scanned':
            self.interrupt_action = NetworkScanner.INT_SKIP_QUEUED_SCANNED
        if 'Exit recool' in answer:
            self.spinner.fail(f'User interrupt! Last state:')
            exit(0)
        self.handling_interrupt = False

    def ping_scan(self, devices: List[NetworkDevice]=[]):
        self.interrupt_action = None

        # Collect hosts if no one specified
        if not devices:
            for ip, device in self.devices.items():
                if not device.done_ping_scan and not device.is_up:
                    devices.append(device)
        hosts = []
        for device in devices:
            hosts.append(device.ip)

        if not hosts:
            return

        self.spinner.text = f'Ping-scan for {stylize(str(len(hosts)), recool.STYLE_HIGHLIGHT)} hosts'
        self.interrupt_msg = f'Ping-scan for {stylize(str(len(hosts)), recool.STYLE_HIGHLIGHT)} hosts'

        # Perform scan and collect data
        result = self.scan(hosts, ['-sn', '-n'], self.ping_scan_sh)
        if self.interrupt_action == NetworkScanner.INT_SKIP:
            return
        if self.interrupt_action == NetworkScanner.INT_SKIP_QUEUED_SCANNED:
            for device in devices:
                device.done_ping_scan = True
            self.update_model(export=False)
            return
        if self.interrupt_action == NetworkScanner.INT_RESTART:
            self.ping_scan(devices)
            return
        
        for ip, data in result.items():
            device = self.parse_device_data(ip, data)
            device.is_up = True
        
        # Update done_ping_scan
        for device in devices:
            device.done_ping_scan = True

        self.update_model()

        #self.spinner.write(json.dumps(self.devices, cls=NetworkEncoder))

    def ping_scan_subnet(self, subnet: str):
        iface = ipaddress.ip_interface(self.args.ip + '/' + subnet)
        devices = [self.find_by_ip(str(host)) for host in iface.network.hosts()]
        devices.append(self.find_by_ip('.'.join(self.args.ip.split('.')[:2]) + '.0.0'))
        devices = list(filter(lambda device: not device.done_ping_scan and not device.is_up, devices))
        self.ping_scan(devices)
    #endregion
    
    #region full scan
    def full_scan_sh(self, sig, frame):
        self.interrupt_action = None
        self.handling_interrupt = True
        questions = [
            inquirer.List('action',
                            message=self.interrupt_msg,
                            carousel=True,
                            choices=[
                                'Continue scanning', 
                                'Restart scan',
                                'Skip full-scan for this host', 
                                'Skip full-scan for this host and mark as scanned',
                                'Skip full-scan for queued hosts',
                                'Skip full-scan for queued host and mark them as scanned',
                                stylize("Exit recool", recool.STYLE_FAILURE)],
                        ),
        ]
        with self.spinner.hidden():
            answer = inquirer.prompt(questions)['action']
        if self.scan_proc and answer != 'Continue scanning':
            self.scan_proc.send_signal(signal.SIGINT)
        if answer == 'Restart scan':
            self.interrupt_action = NetworkScanner.INT_RESTART
        if answer == 'Skip full-scan for this host':
            self.interrupt_action = NetworkScanner.INT_SKIP_HOST
        if answer == 'Skip full-scan for this host and mark as scanned':
            self.interrupt_action = NetworkScanner.INT_SKIP_HOST_SCANNED
        if answer == 'Skip full-scan for queued hosts':
            self.interrupt_action = NetworkScanner.INT_SKIP_QUEUED
        if answer == 'Skip full-scan for queued host and mark them as scanned':
            self.interrupt_action = NetworkScanner.INT_SKIP_QUEUED_SCANNED
        if 'Exit recool' in answer:
            self.spinner.fail(f'User interrupt! Last state:')
            exit(0)
        self.handling_interrupt = False

    def full_scan_up(self, devices=None):
        if not devices:
            devices = self.devices

        queue = devices.items()
        queue = list(filter(lambda item: item[1].is_up and not item[1].done_full_scan, queue))
        count = len(queue)
        while queue:
            self.interrupt_action = None
            ip, device = queue.pop(0)
        
            self.spinner.text = f'Full-scan on {stylize(device.ip, recool.STYLE_HIGHLIGHT)} ({count - len(queue)}/{count})'
            self.interrupt_msg = f'Full-scan on {stylize(device.ip, recool.STYLE_HIGHLIGHT)} ({count - len(queue)}/{count})'
            result = self.scan([device.ip], ['-A', '-p-', '-sV', '-Pn'], self.full_scan_sh)
            if self.interrupt_action == NetworkScanner.INT_SKIP_HOST:
                continue
            if self.interrupt_action == NetworkScanner.INT_SKIP_HOST_SCANNED:
                device.done_full_scan = True
                self.update_model()
                continue
            if self.interrupt_action == NetworkScanner.INT_SKIP_QUEUED:
                return
            if self.interrupt_action == NetworkScanner.INT_SKIP_QUEUED_SCANNED:
                device.done_full_scan = True
                while queue:
                    ip, device = queue.pop(0)
                    device.done_full_scan = True
                self.update_model(export=False)
                return
            if self.interrupt_action == NetworkScanner.INT_RESTART:
                queue.insert(0, (ip, device))
                continue

            for ip, data in result.items():
                device = self.parse_device_data(ip, data)
                device.is_up = True
                device.done_full_scan = True
                self.spinner.write(str(device))

            self.update_model()

            #self.spinner.write(json.dumps(self.devices, cls=NetworkEncoder))
    #endregion

    #region aggressive scan
    def aggressive_scan_subnet_sh(self, sig, frame):
        self.handling_interrupt = True
        questions = [
            inquirer.List('action',
                            message=self.interrupt_msg,
                            carousel=True,
                            choices=[
                                'Continue scanning',
                                'Restart scan',
                                'Skip aggressive-scan',
                                'Skip aggressive-scan and mark all hosts as aggressive-scanned',
                                stylize("Exit recool", recool.STYLE_FAILURE)],
                        ),
        ]
        with self.spinner.hidden():
            answer = inquirer.prompt(questions)['action']
        if self.scan_proc and answer != 'Continue scanning':
            self.scan_proc.send_signal(signal.SIGINT)
        if answer == 'Restart scan':
            self.interrupt_action = NetworkScanner.INT_RESTART
        if answer == 'Skip aggressive-scan':
            self.interrupt_action = NetworkScanner.INT_SKIP
        if answer == 'Skip aggressive-scan and mark all hosts as aggressive-scanned':
            self.interrupt_action = NetworkScanner.INT_SKIP_QUEUED_SCANNED
        if 'Exit recool' in answer:
            self.spinner.fail(f'User interrupt! Last state:')
            exit(0)
        self.handling_interrupt = False

    def aggressive_scan_subnet(self, subnet: str):
        self.interrupt_action = None
        iface = ipaddress.ip_interface(self.args.ip + '/' + subnet)
        self.spinner.text = f'Aggressive-scan on subnet {stylize(str(iface.network), recool.STYLE_HIGHLIGHT)}'
        self.interrupt_msg = f'Aggressive-scan on subnet {stylize(str(iface.network), recool.STYLE_HIGHLIGHT)}'

        # Collect hosts
        devices = []
        hosts = []
        for host in iface.network.hosts():
            device: NetworkDevice = self.find_by_ip(str(host))
            if not device.is_up and not device.done_agg_scan:
                devices.append(device)
                hosts.append(str(host))
        
        if not hosts:
            return

        # Perform scan and collect data
        result = self.scan(hosts, ['-Pn', '-n', '-F', '-d'], self.aggressive_scan_subnet_sh)
        if self.interrupt_action == NetworkScanner.INT_SKIP:
            return
        if self.interrupt_action == NetworkScanner.INT_SKIP_QUEUED_SCANNED:
            for device in devices:
                device.done_agg_scan = True
            self.update_model(export=False)
            return
        if self.interrupt_action == NetworkScanner.INT_RESTART:
            self.aggressive_scan_subnet(subnet)
            return
        
        # Check if hosts have send a response
        for ip, data in result.items():
            if (keys_exists(data, 'tcp')):
                for port, info in data['tcp'].items():
                    if info['state'] != 'filtered':
                        device = self.find_by_ip(ip)
                        device.is_up = True
                        break
        
        # Update done_ping_scan
        for device in devices:
            device.done_agg_scan = True

        self.update_model(export=False)
    #endregion

    #region ipv6 scan
    def ipv6_scan_sh(self, sig, frame):
        self.handling_interrupt = True
        questions = [
            inquirer.List('action',
                            message=self.interrupt_msg,
                            carousel=True,
                            choices=[
                                'Continue scanning',
                                'Restart scan',
                                'Skip IPv6-scan',
                                stylize("Exit recool", recool.STYLE_FAILURE)],
                        ),
        ]
        with self.spinner.hidden():
            answer = inquirer.prompt(questions)['action']
        if self.scan_proc and answer != 'Continue scanning':
            self.scan_proc.send_signal(signal.SIGINT)
        if answer == 'Restart scan':
            self.interrupt_action = NetworkScanner.INT_RESTART
        if answer == 'Skip IPv6-scan':
            self.interrupt_action = NetworkScanner.INT_SKIP
        if 'Exit recool' in answer:
            self.spinner.fail(f'User interrupt! Last state:')
            exit(0)
        self.handling_interrupt = False

    def ipv6_scan(self):
        self.interrupt_action = None
        original_sigint_handler = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, self.ipv6_scan_sh)

        for i in range(1, 6):
            self.spinner.text = f'IPv6 scan {i}/5'
            self.interrupt_msg = f'IPv6 scan {i}/5'

            with open(f'{self.args.storage}/ipv6_scan.txt', 'w') as out, open(f'{self.args.storage}/scan6.error', 'w') as err:
                try:
                    self.scan_proc = subprocess.Popen(
                            ['sudo', 'scan6', '-i', self.args.iface, '-L', '-e', '-v'], 
                            stdout=out, stderr=err, 
                            start_new_session=True)
                    self.scan_proc.wait()
                finally:
                    if self.scan_proc:
                        self.scan_proc.kill()
                    self.scan_proc = None

            while self.handling_interrupt:
                time.sleep(0.3)
            
            if self.interrupt_action == NetworkScanner.INT_SKIP:
                signal.signal(signal.SIGINT, original_sigint_handler)
                return
            if self.interrupt_action == NetworkScanner.INT_RESTART:
                signal.signal(signal.SIGINT, original_sigint_handler)
                self.ipv6_scan()
                return

            os.popen(f'{self.args.nplan} -scan6 {self.args.storage}/ipv6_scan.txt -json {self.args.storage}/model.json > /dev/null').read()
            os.popen(f'{self.args.nplan} -export -json {self.args.storage}/model.json -drawio {self.args.storage}/drawio.xml > /dev/null').read()

        signal.signal(signal.SIGINT, original_sigint_handler)
    #endregion

    #region router scan
    def router_scan_subnet_sh(self, sig, frame):
        self.handling_interrupt = True
        questions = [
            inquirer.List('action',
                            message=self.interrupt_msg,
                            carousel=True,
                            choices=[
                                'Continue scanning',
                                'Restart scan',
                                'Skip router-scan',
                                'Skip router-scan and mark all routers as scanned',
                                stylize("Exit recool", recool.STYLE_FAILURE)],
                        ),
        ]
        with self.spinner.hidden():
            answer = inquirer.prompt(questions)['action']
        if self.scan_proc and answer != 'Continue scanning':
            self.scan_proc.send_signal(signal.SIGINT)
        if answer == 'Restart scan':
            self.interrupt_action = NetworkScanner.INT_RESTART
        if answer == 'Skip router-scan':
            self.interrupt_action = NetworkScanner.INT_SKIP
        if answer == 'Skip router-scan and mark all routers as scanned':
            self.interrupt_action = NetworkScanner.INT_SKIP_QUEUED_SCANNED
        if 'Exit recool' in answer:
            self.spinner.fail(f'User interrupt! Last state:')
            exit(0)
        self.handling_interrupt = False

    def router_scan(self):
        self.interrupt_action = None
        router_pattern = '.'.join(self.args.ip.split('.')[:2]) + '.*.1'
        self.spinner.text = f'Router-scan on {stylize(router_pattern, recool.STYLE_HIGHLIGHT)}'
        self.interrupt_msg = f'Router-scan on {stylize(router_pattern, recool.STYLE_HIGHLIGHT)}'

        # Collect hosts
        devices = []
        hosts = []
        for i in range(0, 255):
            ip = router_pattern.replace('*', str(i))
            device: NetworkDevice = self.find_by_ip(ip)
            if not device.done_ping_scan and not device.is_up:
                devices.append(device)
                hosts.append(ip)
        
        if not hosts:
            return

        # Perform scan
        result = self.scan(hosts, ['-sn', '-n'], self.router_scan_subnet_sh)
        if self.interrupt_action == NetworkScanner.INT_SKIP:
            return
        if self.interrupt_action == NetworkScanner.INT_SKIP_QUEUED_SCANNED:
            for device in devices:
                device.done_ping_scan = True
            self.update_model(export=False)
            return
        if self.interrupt_action == NetworkScanner.INT_RESTART:
            self.router_scan()
            return

        # Create unscanned devices in discovered subnets
        for ip, data in result.items():
            device = self.parse_device_data(ip, data)
            device.is_up = True
            for i in range(1, 255):
                self.find_by_ip('.'.join(ip.split('.')[:3]) + '.' + str(i))
        
        # Update done_ping_scan
        for device in devices:
            device.done_ping_scan = True

        self.update_model()
    #endregion

    #region ultra scan
    def ultra_scan_sh(self, sig, frame):
        self.handling_interrupt = True
        questions = [
            inquirer.List('action',
                            message=self.interrupt_msg,
                            carousel=True,
                            choices=[
                                'Continue scanning',
                                'Restart scan',
                                'Skip ULTRA-scan',
                                'Skip ULTRA-scan and mark all hosts as ping-scanned',
                                stylize("Exit recool", recool.STYLE_FAILURE)],
                        ),
        ]
        with self.spinner.hidden():
            answer = inquirer.prompt(questions)['action']
        if self.scan_proc and answer != 'Continue scanning':
            self.scan_proc.send_signal(signal.SIGINT)
        if answer == 'Restart scan':
            self.interrupt_action = NetworkScanner.INT_RESTART
        if answer == 'Skip big-scan':
            self.interrupt_action = NetworkScanner.INT_SKIP
        if answer == 'Skip big-scan and mark all hosts as ping-scanned':
            self.interrupt_action = NetworkScanner.INT_SKIP_QUEUED_SCANNED
        if 'Exit recool' in answer:
            self.spinner.fail(f'User interrupt! Last state:')
            exit(0)
        self.handling_interrupt = False

    def ultra_scan(self):
        self.interrupt_action = None

        # Collect hosts
        iface = ipaddress.ip_interface(self.args.ip + '/16')
        devices = [self.find_by_ip(str(host)) for host in iface.network.hosts()]
        devices = list(filter(lambda device: not device.done_ping_scan and not device.is_up, devices))

        if not devices:
            return

        self.spinner.text = f'ULTRA-scan on {stylize(str(iface.network), recool.STYLE_HIGHLIGHT)} subnet'
        self.interrupt_msg = f'ULTRA-scan on {stylize(str(iface.network), recool.STYLE_HIGHLIGHT)} subnet'

        # Perform scan and collect data
        result = self.scan([str(iface.network)], ['-sn', '-n'], self.ultra_scan_sh)
        if self.interrupt_action == NetworkScanner.INT_SKIP:
            return
        if self.interrupt_action == NetworkScanner.INT_SKIP_QUEUED_SCANNED:
            for device in devices:
                device.done_ping_scan = True
            self.update_model(export=False)
            return
        if self.interrupt_action == NetworkScanner.INT_RESTART:
            self.ultra_scan(devices)
            return
        
        for ip, data in result.items():
            device = self.parse_device_data(ip, data)
            device.is_up = True
        
        # Update done_ping_scan
        for device in devices:
            device.done_ping_scan = True

        self.update_model()
    #endregion
    

    def test(self):
        result = self.scan(['192.168.188.1'], ['-A'], self.aggressive_scan_subnet_sh)
        #result = self.nmap.scan(hosts="10.129.0.2", arguments=f'{self.args.speed}')["scan"]
        self.spinner.write(json.dumps(result))