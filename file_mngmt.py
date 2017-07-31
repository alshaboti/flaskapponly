import os
import re
#import paramiko

from yaml import load, dump, YAMLError
from  protocol_translation import proto_trans
import requests
import json
#not used anymore, I used ssh key between the devices, such that 
# I don't need to provide username password
def reset_faucet_config():
    os.system("ssh moh@192.168.5.8 cp etc/ryu/faucet/faucet-def.yaml etc/ryu/faucet/faucet.yaml")

def get_dhcp_leases():

   #os.system("scp pi@192.168.10.254:/var/lib/misc/dnsmasq.leases dnsmasq.leases")
   with open('dnsmasq.leases', 'r') as file_stream:
     leases = file_stream.read()

   lines = leases.split('\n')

   dhcp_leases = {}
   for line in lines:
     cols = line.split()
     if(len(cols)>3):
        dhcp_leases[cols[1].upper()] = {'ip':cols[2],'hostname': cols[3]}
   # add dhcp server ip, mac
   dhcp_leases['B8:27:EB:E6:70:F1'] =  {'ip': '192.168.10.254','hostname': 'piDHCPServer'}
   return dhcp_leases
   
# get faucet yaml file using ssh client 
def get_faucet_yaml():
   #os.system("scp moh@192.168.5.8:/home/moh/etc/ryu/faucet/faucet.yaml faucet.yaml")

   with open('faucet.yaml', 'r') as file_stream:
     try:
       faucet_conf =  load(file_stream)
     except YAMLError as exc:
        print(exc)

   return faucet_conf


# write faucet yaml file and restart fuacet using ssh
def set_faucet_yaml(faucet_yaml):
    
    wifi_acl_list = faucet_yaml['acls']['wifi_acl']
    for i in range(0, len(wifi_acl_list) ) :
        if 'rule_id' in faucet_yaml['acls']['wifi_acl'][i]['rule']:
           del faucet_yaml['acls']['wifi_acl'][i]['rule']['rule_id']

    with open("faucet.yaml", "w") as fd:
        dump(faucet_yaml, fd, default_flow_style=False)
    # it works as long as you set ssh key between the two hosts
    #os.system("scp faucet.yaml moh@192.168.5.8:/home/moh/etc/ryu/faucet/faucet.yaml")
    #os.system("ssh root@192.168.5.8 docker exec reannz_faucet pkill -HUP -f faucet.faucet") #pkill -HUP -f faucet.faucet")


def get_blocked_devs(joined_dev_macs):
    #Src dst proto from mirror port, sniffed by sniffed_macs.py
    with open('sniffed_macs.json','r') as fp:
      sniffed_macs = json.load(fp)

    # sniffed_macs - joined_dev = blocked_dev (i.e.new devices)
    blocked_macs = []
    for mac in sniffed_macs.keys():
       notfound=True
       for dev in joined_dev_macs:
          if mac == dev:
             notfound=False
             break
       if notfound:
           blocked_macs.append(mac)

    return  blocked_macs  

#request faucet status through promethous 
def get_faucet_macs():
    # resp= requests.get('http://192.168.5.8:9244').content
    # faucet_resp = str(resp)
    # learned_macs = re.findall(r'learned_macs{[\w+,\=,\",},\s]+\d{1,}',faucet_resp)
    # mac_pad = '00:00:00:00:00:00'
    # faucet_learned_macs = []
    # for line in learned_macs:
    #    mac = line.split()[-1]
    #    if mac != '0':
    #       mac = hex(int(mac))
    #       mac =  mac[2:] # remove 0x
    #       mac =  ':'.join(format(s, '02x') for s in bytes.fromhex(mac))
    #       mac = mac_pad[:17-len(mac)] + mac
    #       faucet_learned_macs.append(mac)
    faucet_learned_macs = ['28:ba:b5:de:64:e7', 'b8:27:eb:d3:f8:8c',
    '34:8a:7b:72:8d:bc', '00:1b:21:d3:1f:62']
    return  faucet_learned_macs    

def get_dev_info(dev_mac, dev_info):

    dev_macs = dev_mac
    if not isinstance(dev_mac, list):
       dev_macs = [dev_mac]

    dev_macs_info = []
    for mac in dev_macs:
       mac = mac.upper()
       if mac in dev_info.keys():
          name = dev_info[mac]['hostname']
          ip = dev_info[mac]['ip']
          dev_macs_info.append({'name':name,'ip':ip,'mac':mac,'desc': None})
       else:
          dev_macs_info.append({'name': None,'ip': None,'mac':mac,'desc': None })

    if not isinstance(dev_mac, list):
       return dev_macs_info[0]

    return dev_macs_info    