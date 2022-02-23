import socket
import ipaddress

def ParseIP(ip):
    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        return False

def DefaultIP():
    return socket.gethostbyname(socket.gethostname())