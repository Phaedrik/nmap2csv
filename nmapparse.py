## NMAP Parse
## Author: Jon Wilson


import xml.etree.ElementTree as etree
import csv
import sys

def help():
    print("Usage -- python3 nmap_parse.py <xmlfiletobeparsed.xml> <outputfile.csv>")
    exit(1)




nmapxml = sys.argv[1]

#Try to create the parsed object. If the scan didn't finish or complete successfully, it will be missing a </nmapscan> tag, which will prevent the xml to be parsed.
#User is warned that the scan did not complete and will appened </nmapscan> to the bottom of the xml file and parse what results were found
try:
    tree = etree.parse(nmapxml)
except etree.ParseError:
    print("WARNING: The scan is currently not finished or did not complete successfully. This parser will retrieve data that was discovered but is will not contain ALL possible results.")
    input("Press Any Key to continue...")
    xml = open(sys.argv[1], 'a')
    xml.write("\n</nmaprun>")
    xml.close()
    tree = etree.parse(nmapxml)

    
root = tree.getroot()
muhDNS = []

#Parsing the NMAP args so we can check what kind of scan was performed
scan_args = root.attrib['args']
icmp_scan = "nmap -sn -PE"
msql_scan = "script ms-sql-info"

csvname = sys.argv[1].strip('.xml')
csvname = csvname + ".csv"
print(csvname)

#Open our csv file to write
with open(csvname, 'w', newline = '', encoding = 'utf-8' ) as host_files:
    writer = csv.writer(host_files)
    first_write = ['Address', 'Port', 'Protocol', 'Service', 'Hostname', 'BannerGrab', 'SSLCert']
    writer.writerow(first_write)
    #Parse icmp scans
    if icmp_scan in scan_args:
        for hosts in root.findall('host'):
            state = hosts.findall('status')[0].attrib['state']
            if state == "down":
                pass
            else:  
                address = hosts.findall('address')[0].attrib['addr']
                host_write = [address, "icmp", "icmp"]
                writer.writerow(host_write)
    #Parse NSE msql scans
    elif msql_scan in scan_args:
        for hosts in root.findall("host"):
            address = hosts.findall('address')[0].attrib['addr']
            try:
                hostname = hosts.findall('hostnames')[0].findall('hostname')[0].attrib['name']
            except IndexError:
                hostname = ''
            hostscript = hosts.findall('hostscript')
            if len(hostscript) > 0:
                script_tag = hostscript[0].findall('script')
                script_elem = script_tag[0].findall('elem')
                if len(script_elem) > 0:
                    script_elem_hostname = script_tag[0].findall('./elem')[0].text
                    if hostname == '':
                        try:
                            hostname = script_elem_hostname
                        except:
                            hostname = ''
                first_table = script_tag[0].findall('table')
                for tables in first_table:
                    table_elems = first_table[0].findall('elem')
                    tabledict = {}
                    for elem in table_elems:
                        tabledict[elem.attrib.get('key')] = elem.text
                    if 'TCP port' in tabledict:
                        port = tabledict['TCP port']
                    else:
                        port = ''
                    second_table = first_table[0].findall('table')
                    second_table_elem = second_table[0].findall('elem')
                    elemdict = {}
                    for s_elems in second_table_elem:
                        elemdict[s_elems.attrib.get('key')] = s_elems.text
                    if 'name' in elemdict:
                        product = elemdict['name']
                    host_write = [address, port, 'tcp', 'ms-sql', hostname, product]
                    writer.writerow(host_write)
    #Parse regular TCP, UDP, Lights, etc scans
    else:
        for hosts in root.findall("host"):
            address = hosts.findall('address')[0].attrib['addr']
            try:
                hostname = hosts.findall('hostnames')[0].findall('hostname')[0].attrib['name']
            except IndexError:
                hostname = ''
            port_element = hosts.findall('ports')
            try:
                ports = port_element[0].findall('port')
                for port in ports:
                    state = port.findall('state')[0].attrib['state']
                    if state == 'open':
                        protocol = port.attrib['protocol']
                        port_id = port.attrib['portid']
                        scripts = port.findall('script')
                        for script in scripts:
                            id = script.attrib['id']
                            if id == 'ssl-cert':
                                table = script.findall('table')
                                elems = table[0].findall('elem')
                                for elem in elems:
                                    text = elem.attrib.get('key')
                                    if text == 'commonName':
                                        thecert = elem.text
                                try:
                                    moretable = table[3].findall('table')
                                    for thetable in moretable:
                                        elems = thetable.findall('elem')
                                        for elem1 in elems:
                                            if 'DNS' in elem1.text:
                                                subDNS = elem1.text.split(',')
                                                for things in subDNS:
                                                    muhDNS.append(things)                 
                                except:
                                    pass
                        try:
                            service = port.findall('service')[0].attrib['name']
                        except:
                            service = ''
                        try:
                            product = port.findall('service')[0].attrib['product']
                        except:
                            product = ''
                        try:
                            product_verison = port.findall('service')[0].attrib['version']
                        except:
                            product_verison = ''
                        try:
                            extra_info = port.findall('service')[0].attrib['extrainfo']
                        except:
                            extra_info = ''
                        try:
                            sslcert = thecert
                        except:
                            sslcert = ''
                        allservice_info = '{} {} {}'.format(product, product_verison, extra_info)
                        if service != 'tcpwrapped' and service != 'udpwrapped':
                            host_write = [address, port_id, protocol, service, hostname, allservice_info, sslcert]
                            writer.writerow(host_write)
            except IndexError:
                pass


newDNS = []

for entry in muhDNS:
    if entry not in newDNS:
        newDNS.append(entry)

DNStext = open('dns.txt', 'w')

for dns in newDNS:
    dns1 = dns.strip()
    dns2 = dns1.strip('DNS:')
    DNStext.write('https://{}\n'.format(dns2))

DNStext.close()





    