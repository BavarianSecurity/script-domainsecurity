# LICENSE GPVv3
# Copyright to Salko Korac
import sys
import json
import io
import subprocess
from fuzzywuzzy import fuzz
import traceback
import logging


opts = [opt for opt in sys.argv[1:] if opt.startswith("-")]
args = [arg for arg in sys.argv[1:] if not arg.startswith("-")]

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

domain_critical = []
domain_major = []
domain_minor = []
domain_hints = []
domain_positive = []

# open configuration file
customers_orderfile = open(orderfile, "r")
customers_orderfile_json = json.load(customers_orderfile)
website=customers_orderfile_json["securityaudit_domain_main"]
print("WEBSITE: "+ website)

domain_result = open(basedir+"/results/"+website+"/"+timestamp+"/scanresults/domain.audit."+website+"."+timestamp+".json", "r")
domain_json_input = json.load(domain_result)

spf=domain_json_input["spf"]
mx=domain_json_input["mx"]
dmarc=domain_json_input["dmarc"]
dkim=domain_json_input["dkim"]
whois=domain_json_input["whois"]
try:
    whois_owner_org=domain_json_input["whois"]["org"]
except Exception as e:
    whois_owner_org = None
    
############## SPF
if len(spf) < 5:
    domain_critical.append("domain_finding_spf_missing")
else:
    domain_positive.append("domain_finding_spf_exist")
    if spf.find("~all") >= 0:
        domain_positive.append("domain_finding_spf_softfail")

    if spf.find("-all") >= 0:
        domain_positive.append("domain_finding_spf_hardfail")

    if spf.find("?all") >= 0:
        domain_positive.append("domain_finding_spf_neutral")

    if spf.find("v=spf1 +all") >= 0:
        domain_critical.append("domain_finding_spf_all_allowed")

    if spf.find("v=spf1 ~all") >= 0:
        domain_positive.append("domain_finding_spf_emails_disallowed")

    if spf.find("/16") >= 0:
        domain_hints.append("domain_finding_spf_netmask_configured")

    if spf.find("mx") >= 0:
        domain_hints.append("domain_finding_spf_mx_configured")

############## DMARC
if dmarc.find("DMARC") < 0:
        domain_major.append("domain_finding_dmarc_missing")
elif dmarc.find("DMARC") >= 0:  
    if dmarc.find("v=DMARC") >= 0:
        domain_positive.append("domain_finding_dmarc_configured")
    #else:
    #    domain_major.append("domain_finding_dmarc_wrong")

    if dmarc.find("ruf=mailto:") >= 0:
        domain_positive.append("domain_finding_dmarc_ruf_configured")
    else:
        domain_minor.append("domain_finding_dmarc_ruf_missing")

    if dmarc.find("rua=mailto:") >= 0:
        domain_positive.append("domain_finding_dmarc_rua_configured")
    else:
        domain_major.append("domain_finding_dmarc_rua_missing")

    if dmarc.find("p=quarantine;") >= 0:
        domain_positive.append("domain_finding_dmarc_policy_quarantaine")
    elif dmarc.find("p=reject;") >= 0:
        domain_positive.append("domain_finding_dmarc_policy_reject")
    elif dmarc.find("p=none;") >= 0:
        domain_minor.append("domain_finding_dmarc_policy_none")
    elif dmarc.find("p=") < 0:
        domain_major.append("domain_finding_dmarc_policy_notexistent")
    else:
        domain_major.append("domain_finding_dmarc_policy_misconfigured")
else:
    domain_hints.append("domain_hint_dmarc_not_auditable")
  
############## Check MX
if len(mx) == 0:
        domain_hints.append("domain_finding_mx_missing")
elif len(mx) == 1:
        domain_minor.append("domain_finding_mx_only_once")
elif len(mx) > 1:
        domain_positive.append("domain_finding_mx_two_available")

############## Check DKIM
print("DKIM found"+str(dkim["DKIM_FOUND"]))
print("DKIM NOT found"+str(dkim["DKIM_NOTFOUND"]))

if len(dkim["DKIM_FOUND"]) > 0:
    domain_positive.append("domain_finding_dkim_existent")
else:
    domain_minor.append("domain_finding_dkim_not_existent")

############## Check Domain Owner
#print("INHABER: "+ str(whois["org"]))
customer_company=customers_orderfile_json["customer_company"].lower()
customer_contactperson=customers_orderfile_json["securityaudit_contact_name"].lower()
customer_contactproxy=customers_orderfile_json["securityaudit_proxy_email"].lower()


fuzzy_score_company = 0
fuzzy_score_contatperson = 0
fuzzy_score_contactproxy = 0
owner_entry_counter = 0

if whois_owner_org != None:
    for owner_entry in whois_owner_org:
        temp_whois_owner_org_lower=whois_owner_org[owner_entry_counter].lower()

        temp_fuzzy_score_company=fuzz.token_set_ratio(customer_company,temp_whois_owner_org_lower)
        temp_fuzzy_score_contatperson=fuzz.token_set_ratio(customer_contactperson,temp_whois_owner_org_lower)
        temp_fuzzy_score_contactproxy=fuzz.token_set_ratio(customer_contactproxy,temp_whois_owner_org_lower)

        if temp_fuzzy_score_company > fuzzy_score_company:
            fuzzy_score_company = temp_fuzzy_score_company
        
        if temp_fuzzy_score_contactproxy > fuzzy_score_contactproxy:
            fuzzy_score_contactproxy = temp_fuzzy_score_contactproxy

        if temp_fuzzy_score_contatperson > fuzzy_score_contatperson:
            fuzzy_score_contatperson = temp_fuzzy_score_contatperson

        print("Customer Company:" + str(customer_company) + "SCORE: " + str(temp_fuzzy_score_company))
        print("Customer Contact Person:" + str(customer_contactperson)+ "SCORE: " + str(temp_fuzzy_score_contatperson))
        print("Customer Contact Proxy:" + str(customer_contactproxy)+ "SCORE: " + str(temp_fuzzy_score_contactproxy))
        print("ORG OWNER:" + temp_whois_owner_org_lower)
        owner_entry_counter =+ 1
    if fuzzy_score_company >= 80 or fuzzy_score_contatperson >= 80 or fuzzy_score_contactproxy >= 80:
        print("CLEAR Ownership>80")
        domain_positive.append("domain_finding_whois_clear_owner")
    elif fuzzy_score_company < 60 and fuzzy_score_contatperson < 60 and fuzzy_score_contactproxy < 60:
        print("UNCLEAR OWNERSHIP60")
        domain_major.append("domain_finding_whois_critical_owner")
    elif fuzzy_score_company < 80 and fuzzy_score_contatperson < 80 and fuzzy_score_contactproxy < 80:
        print("UNCLEAR OWNERSHIP80")
        domain_major.append("domain_finding_whois_unclear_owner")
else:
    domain_hints.append("domain_finding_whois_impossible")

##################### FINALIZATION
print("Critical: "+ str(domain_critical))
print("major: "+ str(domain_major))
print("minor: "+ str(domain_minor))
print("Informative: "+ str(domain_hints))
print("positive: "+ str(domain_positive))

weight_critical = 20
weight_major = 6
weight_minor = 2

rating = (weight_critical * len(domain_critical)) + (weight_major * len(domain_major)) + (weight_minor * len(domain_minor))
print (rating)

if rating >= 20:
    rating_result = "red"
if rating >= 7 and rating <= 19:
    rating_result = "yellow"
if rating <= 6:
    rating_result = "lightgreen"   
if rating <= 2:
    rating_result = "green"       

if "customer_company_industry_tags" in  customers_orderfile_json:
    customer_company_industry_tags  = customers_orderfile_json["customer_company_industry_tags"] 
else:
    customer_company_industry_tags = "empty"

domain_json_Findings =  {
    "domain" : website,
    "domain_endpointname" : "-",
    "domain_endpointip" : "-",
    "domain_risk_factor" : rating,
    "domain_security_rating" : rating_result,
    "domain_positive" : domain_positive,
    "domain_critical" : domain_critical,
    "domain_major" : domain_major,
    "domain_minor" : domain_minor,
    "domain_hints" : domain_hints,
    "general_execution_timestamp" : timestamp,
    "customer_company_industry_tags": customers_orderfile_json["customer_company_industry_tags"] 

}

with io.open(basedir+"/results/"+website+'/'+timestamp+'/raw_findings/domain.findings.'+website+'.'+timestamp+'.json', 'w', encoding='utf-8') as f:
        f.write(json.dumps(domain_json_Findings, indent=4, sort_keys=True, default=str))
