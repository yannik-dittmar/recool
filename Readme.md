# Recool
A python script for automatically scanning a network with nmap/scan6 and creating a draw.io export with the help of [nplan](https://github.com/richartkeil/nplan).

## Requirements

- Python3.9 (might work with earlier versions)
- [nplan](https://github.com/richartkeil/nplan)
- nmap
- scan6 (`sudo apt install ipv6-toolkit`)

## Installation

1. Clone the repository
    ```sh
    git clone https://github.com/Kryptolyser/I-Sec-Recool
    ```
2. Go into the repository folder
    ```sh
    cd I-Sec-Recool
    ```
3. Install python requirements
    ```sh
    sudo python3 -m pip install -r requirements.txt
    ```
4. Done

## Usage

To start scanning simply type the following:
```sh
sudo python3 recool.py -I eth0
```

If recool can't find the nplan binary (because it isn't in your path variable) simply add the `~/go/bin` folder to the path variable or specifify it when you run recool like:
```sh
sudo python3 recool.py -I eth0 --nplan-path ~/go/bin/nplan
```

By default recool will store its saves and output in the `./dist` folder. (You can change this location with the `--storage-folder PATH` flag)

Recool saves the current progress! Therefore, you can safely exit the program and when you restart it, it will continue where it left off.

## Procedure

1. Ping scan on /24 subnet
2. Full scan for all discovered hosts (All ports, service informations, os identification)
3. Aggressive scan on /24 subnet (Fast nmap scan without host discovery)
4. IPv6 scan with scan6
5. Ping scan for routers (devices with .1 ip-ending) in /16 subnet
6. For each discovered router scan /24 subnet of router like step 2 and 3

## Advantages

- Everything is automated!
- A nice interface with a menu for every scan
- Recool directly outputs full scanned hosts, so you can immediately start hacking!
