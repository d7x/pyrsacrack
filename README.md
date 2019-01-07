# pyrsacrack
python rsa crack tool by d7x  
based on Bernie Lim's walkthrough and several other references which use weak randomizing of keys in order to generate a private key, uses rsatool by ius to generate the PEM keys by passing p and q  

I couldn't come up with a fancier name so I  just called it rsacrack even though it sounds a bit too almighty for such a small script. I do not get credit for the methods used in this script as I just packed it from the references to automatize the process of cracking weak ssh keys. I haven't had the time to refactor the code yet so don't look at it as something official  

It uses ius' rsatool in itself to generate the PEM keys, which is included as a submodule thus you would need to include the --recursive option when cloning.  

references:  
https://hackso.me/rsa-1-walkthrough/ - Hand over the Keys by Bernie Lim  
https://factorable.net/weakkeys12.conference.pdf - Mining Your Ps and Qs: Detection of Widespread Weak Keys in Network Devices  
https://github.com/ius/rsatool - rsatool can be used to calculate RSA and RSA-CRT parameters  
https://medium.com/asecuritysite-when-bob-met-alice/cracking-rsa-a-challenge-generator-2b64c4edb3e7 - Cracking RSA - A Challenge Generator by Prof Bill Buchanan  

extracted from rsatool:  
Efficiently recover non-trivial factors of n  
See: Handbook of Applied Cryptography  
8.2.2 Security of RSA -> (i) Relation to factoring (p.287)  
http://www.cacr.math.uwaterloo.ca/hac/  

# Setup: 
git clone --recursive https://github.com/d-7-x/pyrsacrack  
cd pyrsacrack  
touch rsatool/\_\_init\_\_.py # required in order to be able to include rsatool as a module  

# Usage:

python pyrsacrack.py
