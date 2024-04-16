# Copyright 2023 Elijah Gordon (NitrixXero) <nitrixxero@gmail.com>

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

from sys import exit
from os import system
from argparse import ArgumentParser, ArgumentTypeError
from requests import get, RequestException
from time import sleep
from scapy.all import *
from datetime import datetime

VERSION = '1.0'


def get_mac_vendor(mac_address):
    url = 'https://api.macvendors.com/' + mac_address
    response = get(url)
    if response.status_code == 200:
        return response.text.strip()
    else:
        return 'MAC vendor information not found'


def scan_ip_range(ip_range, network_device=None, suppress_sleep=False, filter_expr=None, sleep_time=100, arp_request_count=1, last_octet=None, print_results=False, ignore_home_config=False, fast_mode=False, passive_mode=False, continue_listening=False):
    hosts = {}

    try:
        if last_octet is not None:
            if int(last_octet) < 2 or int(last_octet) > 253:
                print('Error: Invalid last octet. It should be between 2 and 253.')
                return

        if '/' not in ip_range:
            ip_range += '/32'
        if not passive_mode:
            if network_device:
                arpRequest = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip_range)
            else:
                arpRequest = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip_range)

            if fast_mode:
                arpResponse, _ = srp(arpRequest, timeout=1, verbose=0, iface=network_device, filter=filter_expr, retry=0)
            else:
                arpResponse, _ = srp(arpRequest, timeout=1, verbose=0, iface=network_device, filter=filter_expr, retry=arp_request_count)

            captured_packets = 0

            print(f'Currently scanning: {ip_range}\t||\tScreen View: Unique Hosts\n')
            now = datetime.now()
            formatted_date_time = now.strftime("%Y-%m-%d %H:%M:%S")
            print('Starting at: {0}\n'.format(formatted_date_time))
            print('IP\t\tMAC Address\t\tCount\tLen\tMAC Vendor / Hostname')
            print('------------------------------------------------------------------------------')

            total_packets = len(arpResponse)

            for idx, (_, packet) in enumerate(arpResponse):
                if packet[ARP].op == 2:
                    mac_address = packet[ARP].hwsrc
                    mac_vendor = get_mac_vendor(mac_address)
                    ip_address = packet[ARP].psrc

                    if ip_address not in hosts:
                        hosts[ip_address] = [1, mac_address, len(packet), mac_vendor]

                    if not suppress_sleep:
                        sleep(sleep_time / 1000.0)

                progress = int(50 * (idx + 1) / total_packets)
                print(f'\rProgress: [{"=" * progress}{" " * (50 - progress)}] {progress * 2}% ', end='')

            print()
            print()

            total_size = sum(length for _, _, length, _ in hosts.values())

            for ip_address, (count, mac_address, length, mac_vendor) in hosts.items():
                print(f'{ip_address}\t{mac_address}\t{count}\t{length}\t{mac_vendor} ')

            print('------------------------------------------------------------------------------')
            print(f'\n{total_packets} Captured ARP Req/Rep packets, from {len(hosts)} hosts.   Total size: {total_size}')
            print('------------------------------------------------------------------------------')

            if print_results:
                print(f'Active scan completed, {len(hosts)} Hosts found.')
                return
        else:
            now = datetime.now()
            formatted_date_time = now.strftime("%Y-%m-%d %H:%M:%S")
            print('Starting at: {0}\n'.format(formatted_date_time))
            print('Passive mode: Sniffing ARP packets...')
            print('------------------------------------------------------------------------------')
            sniff(filter=filter_expr, prn=lambda x: handle_sniffed_packet(x, hosts, suppress_sleep), store=0)

            if continue_listening:
                print('Passive mode: Continue listening...')
                sniff(filter=filter_expr, prn=lambda x: handle_sniffed_packet(x, hosts, suppress_sleep), store=0)

    except PermissionError:
        print('You must be root to run this.')


def handle_sniffed_packet(packet, hosts, suppress_sleep=False):
    if ARP in packet and packet[ARP].op == 2:
        mac_address = packet[ARP].hwsrc
        mac_vendor = get_mac_vendor(mac_address)
        ip_address = packet[ARP].psrc

        if ip_address not in hosts:
            hosts[ip_address] = [1, mac_address, len(packet), mac_vendor]
            print(f'{ip_address}\t{mac_address}\t1\t{len(packet)}\t{mac_vendor}')

        if not suppress_sleep:
            sleep(0.1)


def scan_ranges_from_file(file_path, network_device=None, suppress_sleep=False, filter_expr=None, arp_request_count=1, print_results=False, ignore_home_config=False, fast_mode=False, passive_mode=False):
    try:
        with open(file_path, 'r') as file:
            ranges = file.readlines()

        ranges = [range.strip() for range in ranges]

        for range in ranges:
            scan_ip_range(range, network_device, suppress_sleep, filter_expr, arp_request_count, print_results=print_results, ignore_home_config=ignore_home_config, fast_mode=fast_mode, passive_mode=passive_mode)

            if passive_mode and continue_listening:
                print(f'Continuing listening on range: {range}')
                scan_ip_range(range, network_device, suppress_sleep, filter_expr, arp_request_count, passive_mode=True, continue_listening=True)

    except FileNotFoundError:
        print(f'Error: File not found: {file_path}')


def scan_mac_list(mac_list_file):
    try:
        with open(mac_list_file, 'r') as file:
            macs = file.readlines()

        macs = [mac.strip() for mac in macs]

        now = datetime.now()
        formatted_date_time = now.strftime("%Y-%m-%d %H:%M:%S")

        print('Starting at: {0}\n'.format(formatted_date_time))
        print('MAC Address\t\tMAC Vendor / Hostname')
        print('------------------------------------------------------------------------------')

        for mac in macs:
            mac_vendor = get_mac_vendor(mac)
            print(f'{mac}\t{mac_vendor}')

        print('------------------------------------------------------------------------------')

    except FileNotFoundError:
        print(f'Error: File not found: {mac_list_file}')


def clear_screen():
    system('clear')


def main():
    clear_screen()
    parser = ArgumentParser(description='ARP Scanner Tool')
    parser.add_argument('-i', '--device', help='Network device to use for scanning')
    parser.add_argument('-r', '--range', help='IP range to scan (e.g., 192.168.1.0/24)')
    parser.add_argument('-l', '--file', help='Scan the list of ranges contained into the given file')
    parser.add_argument('-p', '--passive-mode', action='store_true', help='Enable passive mode, only sniff ARP packets')
    parser.add_argument('-m', '--mac', help='Scan a list of known MACs and host names')
    parser.add_argument('-F', '--filter', help='Customize pcap filter expression (default: "arp")')
    parser.add_argument('-s', '--sleep-time', type=int, default=100, help='Time to sleep between each ARP request (milliseconds)')
    parser.add_argument('-c', '--arp-request-count', type=int, default=1, help='Number of times to send each ARP request (for nets with packet loss)')
    parser.add_argument('-n', '--last-octet', type=int, help='Last source IP octet used for scanning (from 2 to 253)')
    parser.add_argument('-d', '--ignore-home-config', action='store_true', help='Ignore home config files for autoscan and fast mode')
    parser.add_argument('-f', '--fast-mode', action='store_true', help='Enable fast mode scan, saves a lot of time, recommended for auto')
    parser.add_argument('-P', '--print-results', action='store_true', help='Print results in a format suitable for parsing by another program and stop after active scan')
    parser.add_argument('-S', '--suppress-sleep', action='store_true', help='Enable sleep time suppression between each request (hardcore mode)')

    parser.add_argument('-V', '--version', action='version', version='%(prog)s ' + VERSION)
    args = parser.parse_args()

    args = parser.parse_args()
    try:
        args = parser.parse_args()

        if args.range:
            scan_ip_range(args.range, args.device, args.suppress_sleep, args.filter, args.sleep_time, args.arp_request_count, args.last_octet, args.print_results, args.ignore_home_config, args.fast_mode, args.passive_mode)

        if args.file:
            scan_ranges_from_file(args.file, args.device, args.suppress_sleep, args.filter, args.arp_request_count, args.print_results, args.ignore_home_config, args.fast_mode, args.passive_mode)

        if args.mac:
            scan_mac_list(args.mac)

        if not args.range and not args.file and not args.mac:
            parser.print_help()

        now = datetime.now()
        formatted_date_time = now.strftime("%Y-%m-%d %H:%M:%S")

        print('\nExiting at: {0}'.format(formatted_date_time), end='')

    except OSError as e:
        if e.errno == 19:
            print("Error: The specified network device does not exist.")
        else:
            print(f"An OSError occurred with error number {e.errno}: {e.strerror}")
            exit(1)

    except ArgumentTypeError as e:
        print(f"Error: {e}")
        parser.print_usage()
        exit(1)

    except RequestException as e:
        print(f"Error: Failed to retrieve MAC vendor information. {e}")
        exit(1)

    except Scapy_Exception as e:
        print(f"Error: Scapy exception occurred. {e}")
        exit(1)


if __name__ == '__main__':
        main()
