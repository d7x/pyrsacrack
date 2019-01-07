# rsacrack
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


Setup: 
git clone --recursive https://github.com/d-7-x/rsacrack
touch rsatool/__init__.py

Usage:
python rsacrack.py
