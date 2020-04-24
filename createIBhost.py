#!/usr/bin/env python3
# encoding: utf-8
# Written 2019 by Sebastian Metzner
# To be used with Infoblox NIOS WAPI Version 2.7
# Main Task: Script creates or syncs Infoblox Hosts with Fixed Address objects
# The script does the following actions to the Host record
#  - copy the mac address from the Fixed Address to the Host record
#  - copy the comment from the Fixed Address to the Host record
#  - enable the DHCP function of the Host record
#  - delete the Fixed Address with the same IP address of the Host record

import json
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from tkinter import *
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class APIError(Exception):

    def __init__(self, status):
        self.status = status

    def __str__(self):
        return "APIError: status={}".format(self.status)


def show():
    print("Network: %s\nNetmask: %s" % (e1.get(), e2.get()))
    network = e1.get()
    mask = e2.get()
    GM = e3.get()

    # Part 2: Fixed Parameters
    # Infoblox Gridmaster access credentials
    user = 'admin'
    password = 'infoblox'

    # Internal DNS View name
    #vintern = 'DNSinternal'
    vintern = 'internal DNS-View'
    # Return fields
    fields_fixaddr = 'name,ipv4addr,comment,mac'
    # URL to get all Fixed Addresses in the Network
    urlnetwork = 'https://' + GM + '/wapi/v2.7/fixedaddress?' + 'network=' + network + '/' + mask \
                 + '&_return_fields=' + fields_fixaddr

    # Get all associated zones of the DHCP network
    # Step 1: Get reference of network
    urlnetwork_reference_helper = 'https://' + GM + '/wapi/v2.7/network?' + 'network=' + network + '/' + mask \
                                  + '/defualt' + '?&_return_as_object=1'
    network_info = requests.get(urlnetwork_reference_helper, auth=(user, password), verify=False,
                                headers={'Accept': 'application/json'})
    if network_info.status_code != 200:
        print(network_info.text)
        raise APIError('Fehler {}'.format(network_info.status_code))
    list_network_info = json.loads(network_info.text)
    list_network_info_helper = list_network_info['result']
    list_network_info_helper2 = list_network_info_helper[0]
    network_reference = list_network_info_helper2['_ref']

    # Step 2: Get associated zones of the referenced network
    urlnetwork_ass_zones = 'https://' + GM + '/wapi/v2.7/' + network_reference \
                           + '?_return_fields%2B=zone_associations&_return_as_object=1'
    network_info_wref = requests.get(urlnetwork_ass_zones, auth=(user, password), verify=False,
                                     headers={'Accept': 'application/json'})
    if network_info_wref.status_code != 200:
        print(network_info_wref.text)
        raise APIError('Fehler {}'.format(network_info_wref.status_code))
    dict_dns_zone = json.loads(network_info_wref.text)
    dns_zone_helper = dict_dns_zone['result']
    dns_zone_helper = dns_zone_helper['zone_associations']
    if len(dns_zone_helper) > 1:
        print('Mehrere DNS Zone associations definiert')
        raise APIError('Fehler {}'.format('Two many zone associations'))
    if len(dns_zone_helper) != 0:
        dns_zone_assoc = dns_zone_helper[0].get('fqdn')

    # WAPI request to get Fixed Address records from investigated network
    resp_fix_addr = requests.get(urlnetwork, auth=(user, password), verify=False, headers={'Accept': 'application/json'})
    if resp_fix_addr.status_code != 200:
        print('Netz existiert nicht')
        Label(master, text='Error: ', bg='red', fg='white').grid(row=3, column=1)
        Label(master, text='The Network does not exist!').grid(row=3, column=2)
        return()
        raise APIError('Fehler {}'.format(resp_fix_addr.status_code))
    # Json File with all Fixed Addresses in the investigated network
    list_fix_addr = json.loads(resp_fix_addr.text)

    # Check, if Fixed Addresses exists in this network
    if not list_fix_addr:
        print('The network does not contain any Fixed Addresses.')
        Label(master, text="Error: ", bg='red', fg='white').grid(row=3, column=1)
        Label(master, text="The network does not contain any Fixed Addresses.").grid(row=3, column=2)
        return ()

    # Iterate over every Fixed Address from list_fix_addr
    # Working Steps:
    # Step 1. Search Host record with same IP Address as Fixed Address
    # Step 2. Check, if Host record exists and create new Host record if necessary
    # Step 3. Add comment to Host record
    # Step 4. Add MAC address to Host record
    # Step 5. Delete Fixed Address
    # Step 6. Enable Host record IP Address for DHCP
    for loopnumber, FA in enumerate(list_fix_addr, start=1):
        fix_add_dict = {}
        fix_add_dict.update(FA)

        loop_info = 'Loop' + str(loopnumber) + ': ' + FA['name'] + ', mac: ' + FA['mac']
        print(loop_info)

        # Step 1: Search HOST record with ipv4addr and get reference for this loop iteration
        fields_host = 'name,ipv4addrs,comment'
        url_host_record = 'https://' + GM + '/wapi/v2.7/record:host?ipv4addr=' + fix_add_dict['ipv4addr'] \
                          + '&view=' + vintern + '&_return_fields=' + fields_host
        jhost = requests.get(url_host_record, auth=(user, password), verify=False,
                             headers={'Accept': 'application/json'})
        if jhost.status_code != 200:
            raise APIError('Fehler {}'.format(jhost.status_code))
        host = json.loads(jhost.text)

        # Create a new Host record for this Fixed Address exists, if no Host record exist
        if len(host) == 0:
            # 1. if no Host exists, create a new Host record
            # Quit, if FA has no zone information and network has no associated zone
            if zone not in FA['name'] and len(dns_zone_helper) == 0:
                print('No zone information for host - set zone associations or define name of Fixed Address')
                raise APIError('Failure {}'.format('No zone information for host'))
            # Check, if the name of the Fixed Address includes the subzone
            if len(dns_zone_helper) != 0:
                if dns_zone_assoc not in FA['name']:
                    FA['name'] = FA['name'] + '.' + dns_zone_assoc

            host_create_new = {}
            host_create_new.update({'name': FA['name'], 'view': vintern, 'ipv4addrs': [{'ipv4addr': FA['ipv4addr']}]})
            host_post = requests.post(
                'https://' + GM + '/wapi/v2.7/record:host?_return_fields%2B=name,ipv4addrs&_return_as_object=1',
                data=json.dumps(host_create_new), auth=(user, password),
                verify=False, headers={'Accept': 'application/json'})
            print(host_post.text)
            if host_post.status_code != 201:
                raise APIError('Failure {}'.format(host_post.status_code))

            # 2. Get reference of the new Host record
            url_host_record = 'https://' + GM + '/wapi/v2.7/record:host?ipv4addr=' + fix_add_dict['ipv4addr'] \
                              + '&view=' + vintern + '&_return_fields=' + fields_host
            jhost = requests.get(url_host_record, auth=(user, password), verify=False,
                                 headers={'Accept': 'application/json'})
            if jhost.status_code != 200:
                raise APIError('Failure {}'.format(jhost.status_code))
            host = json.loads(jhost.text)

        host = host[0]
        host_reference = host.get('_ref')

        # Get reference of Fixed Address element in Host object
        url_host_record_fixaddr = 'https://' + GM + '/wapi/v2.7/record:host_ipv4addr?ipv4addr=' + fix_add_dict[
            'ipv4addr'] + '&_return_as_object=1'
        jhost_fixaddr = requests.get(url_host_record_fixaddr, auth=(user, password), verify=False,
                                     headers={'Accept': 'application/json'})
        if jhost_fixaddr.status_code != 200:
            print('Error: ' + jhost_fixaddr.text)
            raise APIError('Failure {}'.format(jhost_fixaddr.status_code))
        host_fixaddr = json.loads(jhost_fixaddr.text)
        host_fixaddr = host_fixaddr['result']
        for counter, value in enumerate(host_fixaddr):
            if 'internal%20DNS-View' in host_fixaddr[counter].get('_ref'):
                host_fixaddr = host_fixaddr[counter]
                host_ipv4_reference = host_fixaddr['_ref']
            elif counter == len(host_fixaddr):
                print('Error: No Host in the internal DNS View')
                raise APIError('Failure {}'.format('No Host in the internal DNS View'))

        # Add IPv4 address and comment to host record
        # Put comment to host record
        host_new = {}
        if FA.get('comment', ''):
            # First check if Host record has also a comment
            if host.get('comment') is not None:
                comm_host = host.get('comment')
                # Combine the comments from Host record and Fixed Address
                new_comm_host = FA['comment'] + ';' + comm_host
            else:
                new_comm_host = FA['comment']
            host_new.update({'comment': new_comm_host})
            host_post = requests.put('https://' + GM + '/wapi/v2.7/' + host_reference, data=json.dumps(host_new),
                                     auth=(user, password), verify=False, headers={'Accept': 'application/json'})
            if host_post.status_code != 200:
                print('Error: ' + host_post.text)
                raise APIError('Failure {}'.format(host_post.status_code))
            else:
                print('No comment transfered')

        # Put mac address to host record
        host_new2 = {}
        host_new2.update({'mac': FA['mac']})
        host_post = requests.put('https://' + GM + '/wapi/v2.7/' + host_ipv4_reference
                                 + '?_return_fields%2B=ipv4addr&_return_as_object=1', data=json.dumps(host_new2),
                                 auth=(user, password), verify=False, headers={'Accept': 'application/json'})
        if host_post.status_code != 200:
            print('Error: ' + host_post.text)
            raise APIError('Failure {}'.format(host_post.status_code))

        # Disable FixedAddress
        url_fix_addr = 'https://' + GM + '/wapi/v2.7/' + fix_add_dict['_ref'] + '&_return_as_object=1'
        host_post = requests.delete(url_fix_addr, data=json.dumps(host_new2),
                                    auth=(user, password), verify=False, headers={'Accept': 'application/json'})
        print('Delete: ' + host_post.text)
        if host_post.status_code != 200:
            print('Error: ' + host_post.text)
            raise APIError('Failure {}'.format(host_post.status_code))

        # Enable DHCP for host record
        host_new = {}
        host_new.update({'configure_for_dhcp': True})

        host_post = requests.put('https://' + GM + '/wapi/v2.7/' + host_ipv4_reference
                                 + '?_return_fields%2B=ipv4addr&_return_as_object=1',
                                 data=json.dumps(host_new), auth=(user, password), verify=False,
                                 headers={'Accept': 'application/json'})
        if host_post.status_code != 200:
            print('Error: ' + host_post.text)
            raise APIError('Failure {}'.format(host_post.status_code))
    raise SystemExit


# Part 1: Defining Parameters
# DNS Zone Name to look for records
zone = 'example.com'
# Searched Network
# variant a: defined Network
network = '192.168.0.0'
mask = '24'
# variant b: input dialog for network-
# Window
master = Tk()
master.geometry('500x150')
master.wm_title('Define Network Parameters')
Label(master, text="Grid-Master   ").grid(row=0)
Label(master, text="Network   ").grid(row=1)
Label(master, text="Netmask   ").grid(row=2)
Label(master, text="Username    ").grid(row=3)
Label(master, text="Password    ").grid(row=4)

# Label for error-messages
Label(master, text="").grid(row=5)

e1 = Entry(master)
e2 = Entry(master)
e3 = Entry(master)
e4 = Entry(master)
e5 = Entry(master)
e1.insert(10, "192.168.0.0")
e2.insert(10, "24")
e3.insert(10, '172.30.10.1')
e4.insert(10, '')
e5.insert(10, '')

e1.grid(row=1, column=1)
e2.grid(row=2, column=1)
e3.grid(row=0, column=1)
e4.grid(row=3, column=1)
e5.grid(row=4, column=1)

Button(master, text='Quit', command=master.quit).grid(row=5, column=1, sticky=W, pady=4)
Button(master, text='Ok', command=show).grid(row=5, column=2, sticky=W, pady=4)

mainloop()
