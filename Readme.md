# Recool

## Procedure

1. Ping scan on /24 subnet
2. Perform the following for each discovered device
    1. Complete port scan with services and versions
    2. Vulnerability scan
3. Perform a complete port scan for all other devices in /24 subnet (if the device has an open port, perform scan with services and versions and vulnerability scan)
4. Ping scan for routers (devices with .1 ip-ending) in /16 subnet
5. For each discovered router scan /24 subnet of router like step 2 and 3
6. Ping scan all unscanned /16 subnets and perform step 2 and 3 if there is a device
