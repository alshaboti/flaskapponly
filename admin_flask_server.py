# HTTP server for HNCP
import json
from flask import Flask, render_template, request, redirect, send_from_directory

from  protocol_translation import proto_trans
import sys



#for login after: pip3 install flask-login flask-sqlalchemy
#from flask_sqlalchemy import SQLAlchemy
#from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
#from flask_login import current_user

import file_mngmt as fm
import rule_managment as rule_mngmt 
from rule_managment import default_rule



app = Flask(__name__, static_url_path='')
#openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
#if __name__ == "__main__":
#    app.run(ssl_context=('cert.pem', 'key.pem'))

servers = {'http_server':'00:1b:21:d3:1f:62','gW_Server': 'b8:27:eb:e6:70:f1'}
ignored_mac = ['ff:ff:ff:ff:ff:ff']
def net_topology():
  home_net_topo = {
    "type": "NetworkGraph",
    "label": "Home Network",
    "protocol": "OpenFlow",
    "version": "1.3",
     "nodes": [],
     "links": []

  }

  nodes = []
  for dev in joined_dev_info:
    node = {
            "id": dev['mac'].lower(),
            "label": dev['name'],
            "properties": {
              "ip": dev['ip'],
              "gateway": False
            }
        }
    nodes.append(node)

  links = []
  for policy in net_policy:
    if not(policy['from_mac'].lower() in joined_dev_macs and \
       policy['to_mac'].lower() in joined_dev_macs): 
      continue
    print("source ", policy['from_mac'])
    print("target", policy['to_mac'])
    
    link = {
            "source": policy['from_mac'].lower(),
            "target": policy['to_mac'].lower(),
            "cost": 1,
            "properties": {
                "tx": 0.900,
                "rx": 0.497,
                "bitrate": "100 mbit/s",
                "type": "ethernet",
                "protocols": policy['service']['service_name']
            }
        }
    links.append(link)
  print(links)    

  home_net_topo['nodes'] = nodes
  home_net_topo['links'] = links
  with open('static/home_net.json','w') as fd:
    json.dump(home_net_topo, fd)

@app.route('/')
def root():
  return 'hellow world!'

@app.route('/home')
#@login_required
def home():
    global dev_info
    dev_info = fm.get_dhcp_leases()


    # request learned mac from faucet promethous 192.168.5.8:9244
    global joined_dev_macs
    joined_dev_macs = fm.get_faucet_macs()
    print('joined_dev_macs OK')

    #  add dev IP and hostname
    global joined_dev_info    
    joined_dev_info = fm.get_dev_info(joined_dev_macs, dev_info)
    print('joined_dev_info OK')

    # get faucet.yaml file
    global faucet_yaml
    faucet_yaml = fm.get_faucet_yaml()
    print('faucet_yaml OK')

    blocked_dev = fm.get_blocked_devs(joined_dev_macs)
    blocked_dev_info = fm.get_dev_info(blocked_dev, dev_info)


    # get faucet policy
    # let's make it static at first 
    global net_policy
    net_policy = get_faucet_policy(faucet_yaml['acls']['wifi_acl'])

    return render_template('index.html', joined_dev=joined_dev_info, 
      blocked_dev=blocked_dev_info, net_policy= net_policy )

#Allow DHCP service for this device
@app.route('/join', methods=['post'])
#@login_required
def join():
    rule_mngmt.add_join_rules(request.form['mac'], faucet_yaml['acls']['wifi_acl'])

    fm.set_faucet_yaml(faucet_yaml)

    return redirect('/home')


@app.route('/delete_policy', methods=['POST'])
#@login_required
def network_policy():
    delete_faucet_rule( int(request.form['rule_id']) )
    fm.set_faucet_yaml(faucet_yaml)
#   return 'Rule is deleted successfully!'
    args={"parag":"Rule is deleted successfully!","link":"http://192.168.5.3:5000/home", "btn_value":"Home"} 
    return render_template('done.html', args=args )


@app.route('/new_policy', methods=['GET'])
#@login_required
def new_policy():
    args = {}
    args['local_devs_list'] = joined_dev_info
    args['services_dict'] = proto_trans['tp_proto']

    return render_template('new_policy.html', args = args)


@app.route('/add_policy', methods=['POST'])
#@login_required
def add_policy():
  acl_to = acl_from = faucet_yaml['acls']['wifi_acl']  
  port_no = int(request.form['service'])

  if(port_no not in proto_trans['tp_proto'].keys()):
    args={"parag":"Service is not supported.",
         "link":"http://192.168.5.3:5000/home", "btn_value":"Home"} 
    return render_template('done.html', args=args )

  if request.form['to_entity'].lower() == servers['http_server']:
     acl_to = faucet_yaml['acls']['port3_acl']

  rule_mngmt.add_rule(request.form['from_entity'], 
         request.form['to_entity'], port_no, 
         acl_from, acl_to)
  fm.set_faucet_yaml(faucet_yaml)

  args={"parag":"Rule is added successfully!","link":"http://192.168.5.3:5000/home", "btn_value":"Home"} 
  return render_template('done.html', args=args )


@app.route('/reset', methods=['GET'])
#@login_required
def reset_faucet_config():
  fm.reset_faucet_config()
  return redirect('/home')

@app.route('/show_topo', methods=['GET'])
#@login_required
def show_topology():
  net_topology()
  return render_template('home_net_topo.html')

@app.route('/static/<path:path>')
#@login_required
def static_files(path):
  return send_from_directory('static',path)


@app.errorhandler(404)
def not_found(error):
    return 'Try again, error!'


def delete_faucet_rule(rule_id):

    wifi_acl_list = faucet_yaml['acls']['wifi_acl']
    copy_acl_list = []
    for i in range(0, len(wifi_acl_list) ) :
        rule = wifi_acl_list[i]['rule']
        if rule['rule_id'] == rule_id:        
           continue        
        copy_acl_list.append(wifi_acl_list[i])

    faucet_yaml['acls']['wifi_acl'] = copy_acl_list




def check_rev_rule(srcs, dsts, protos, rule):
    # check if rule is rev of an existing one
    is_dhcp, is_rev = rule_mngmt.is_dhcp_rule(rule)
    for idx in range(0, len(srcs['dl_src'])):
      if srcs['dl_src'][idx] == rule['dl_dst'] and \
         ( is_dhcp or dsts['dl_dst'][idx] == rule['dl_src']) and \
         protos['dl_type'][idx] == rule['dl_type'] and \
         protos['nw_proto'][idx] == rule['nw_proto'] and \
         srcs['tp_src'][idx] == rule['tp_dst'] and \
         dsts['tp_dst'][idx] == rule['tp_src']:
         return True, idx
    return False, -1


def get_faucet_policy(acl_list):

   policy = []
   srcs = {'dl_src':[], 'nw_src':[], 'tp_src':[]}
   dsts = {'dl_dst':[],'nw_dst':[], 'tp_dst':[]}
   protos = {'dl_type':[], 'nw_proto':[]}
   
   for idx in range(0, len(acl_list)):      
       
       rule = rule_mngmt.update_rule(acl_list[idx]['rule'])            
 
       is_reverse, r_id = check_rev_rule(srcs,dsts,protos, rule)      
       rule_id = idx if r_id == -1 else r_id          
       
       acl_list[idx]['rule']['rule_id'] = rule_id

       srcs['dl_src'].append(rule['dl_src'])
       dsts['dl_dst'].append(rule['dl_dst'])
       srcs['tp_src'].append(rule['tp_src']) 
       dsts['tp_dst'].append(rule['tp_dst'])
       protos['dl_type'].append(rule['dl_type'])
       protos['nw_proto'].append(rule['nw_proto'])
       
       if is_reverse:
          continue

       from_host = fm.get_dev_info(rule['dl_src'], dev_info)['name']
       to_host = fm.get_dev_info(rule['dl_dst'], dev_info)['name']

       service = {'service_name': rule_mngmt.get_rule_service_name(rule), 
                  'actions': rule['actions']['allow']}
       new_policy = {'from_mac': rule['dl_src'],
                     'from_host': from_host,
                     'to_mac': rule['dl_dst'],
                     'to_host': to_host,
                     'from_ip': rule ['nw_src'],
                     'to_ip': rule['nw_dst'],
                     'service': service, 
                     'idx': rule_id,
                     'is_rev': is_reverse 
                    }
       policy.append(new_policy)
   return policy




