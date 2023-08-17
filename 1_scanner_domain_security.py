# LICENSE GPLv3
# Copyright to Salko Korac
from re import sub
from select import select
import subprocess
import whois
import sys
import json
import io

opts = [opt for opt in sys.argv[1:] if opt.startswith("-")]
args = [arg for arg in sys.argv[1:] if not arg.startswith("-")]

website="error"

if "-orderfile" in opts:
    orderfile="".join(arg for arg in args[0])
    print("ODERFILE: " + orderfile)
if "-timestamp" in opts:
    timestamp="".join(arg for arg in args[1])
    print("timestamp: " + timestamp)
if "-basedir" in opts:
    basedir="".join(arg for arg in args[2])
else:
    raise SystemExit(f"Usage: "+ {sys.argv[0]} + " (-orderfile customer_order.json). All arguments necessary in the mentioned order.")

# open configuration file
customers_orderfile = open(orderfile, "r")
customers_orderfile_json = json.load(customers_orderfile)
website=customers_orderfile_json["securityaudit_domain_main"]
print("WEBSITE: "+ website)

# find out IP Address of main domain
cmd_maindomain_ip_ping = "ping -c1 "+website+" | sed -nE 's/^PING[^(]+\(([^)]+)\).*/\\1/p'"
result_maindomain_ip_ping = subprocess.Popen(cmd_maindomain_ip_ping, shell=True, stdout=subprocess.PIPE)
result_maindomain_ip_ping.wait()
result_maindomain_ip_ping_text = result_maindomain_ip_ping.stdout.read()
result_maindomain_ip_ping_text = result_maindomain_ip_ping_text[:-1] # remove last character which is \n

# find out MX records of main domain
cmd_maindomain_mx = "dig "+website+" mx +short" 
cmd_maindomain_mx = subprocess.Popen(cmd_maindomain_mx, shell=True, stdout=subprocess.PIPE)
cmd_maindomain_mx.wait()
result_maindomain_mx_text = cmd_maindomain_mx.stdout.read()
result_maindomain_mx_text = result_maindomain_mx_text[:-2]
result_mx_list_bytes = result_maindomain_mx_text.split(b'\n')
result_mx_list_strings = [x.decode('utf-8') for x in result_mx_list_bytes]

# Check DMARC status
cmd_dig_dmarc = "dig TXT +short _dmarc."+website 
result_dmarc = subprocess.Popen(cmd_dig_dmarc, shell=True, stdout=subprocess.PIPE)
result_dmarc.wait()
result_dmarc_text = result_dmarc.stdout.read()

# Check RAW SPF Status
cmd_spf = "dig TXT +short "+website + " | grep -i spf" 
result_spf = subprocess.Popen(cmd_spf, shell=True, stdout=subprocess.PIPE)
result_spf.wait()
result_spf_text = result_spf.stdout.read()

#Check RAW DKIM Status: Not implemented! To be implemented in later version. 
selectors = ["google", "default", "mail", "s2048gl", "s2048g1", "selector1", "selector2", "everlytickey1", "everlytickey2", "eversrv", "k1", "mxvault", "dkim", website]
result_dkim_found = []
result_dkim_not_found = []

result_dkim_json  = '{'
for selector in selectors:
        cmd_dkim="dig +short "+selector+"._domainkey."+website+" TXT" 
        result_dkim = subprocess.Popen(cmd_dkim, shell=True, stdout=subprocess.PIPE)
        result_dkim.wait()
        result_dkim_text = result_dkim.stdout.read()

        if result_dkim_text.find(b'k=') >= 0:
                result_selector_found = True
                result_dkim_json =result_dkim_json + '"'+str(selector)+'" : "'+str(result_dkim_text.replace(b'\n',b'').replace(b'\"',b'')).replace("b'","").replace("'","")+'"'
                result_dkim_json =result_dkim_json + ', '
                result_dkim_found.append(selector)
        else:
                #result_dkim_json =result_dkim_json + '"'+str(selector)+'" : "NOT FOUND"'
                result_dkim_not_found.append(selector)
        #if selector!=website:
        #        result_dkim_json =result_dkim_json + ', '

result_dkim_json = result_dkim_json+ '"DKIM_NOTFOUND": '+str(result_dkim_not_found).replace("'","\"")+','
result_dkim_json = result_dkim_json+ '"DKIM_FOUND": '+str(result_dkim_found).replace("'","\"")+''
result_dkim_json = result_dkim_json+'}'
print(result_dkim_json)
#print(result_dkim_json)
# Scan whoIS information to verify correct ownership
result_whois = whois.whois(website)

domain_json = {
        "ipv4" : result_maindomain_ip_ping_text.decode(),
        "mx" : result_mx_list_strings,
        "dmarc" : result_dmarc_text.decode("utf8").replace("\"","").replace("\n",""),
        "spf" : result_spf_text.decode("utf8").replace("\"","").replace("\n",""),
        "dkim" : json.loads(result_dkim_json),
        "whois" : result_whois,
        "general_execution_timestamp" : timestamp
        }
print("TIMESTAMP GIVEN IN PTYHON: "+timestamp)
with io.open(basedir+"/results/"+website+'/'+timestamp+'/scanresults/domain.audit.'+website+'.'+timestamp+'.json', 'w', encoding='utf-8') as f:
        f.write(json.dumps(domain_json, indent=4, sort_keys=True, default=str))
