import csv

def load_whitelist(path='whitelist.csv'):
    whitelist= {}
    with open(path, mode='r', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            ip = row['ip']
            country = row['country']
            whitelist[ip] = country
    return whitelist

def is_whitelisted(ip, country, whitelist):
    if ip in whitelist:
        expected_country = whitelist[ip]
        if country and expected_country and country == expected_country:
            return True
        else:
            print(f"[!] WHITELISTED IP {ip}, but country mismatch: expected {expected_country}, got {country}")
            return False
    return False