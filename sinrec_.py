import urllib.request
from colorama import init, Fore
import requests
import optparse
import paramiko
from time import sleep
import os
import socket
import pyfiglet
from datetime import datetime
from threading import Thread, Lock
from queue import Queue
import ftplib
import time
import smtplib
import webtech
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin, urlparse
import hashlib
from tqdm import tqdm
from requests_html import HTMLSession
from bs4 import BeautifulSoup
import re
from pprint import pprint
#impoer files
import hiden_dir


init()

GREEN = Fore.GREEN
RED   = Fore.RED
YELLOW = Fore.YELLOW
RESET = Fore.RESET
BLUE  = Fore.BLUE
b = "\033[1;34m"
w = "\033[0m"


def banner(url):
    print("=" * 50)
    ascii_banner = pyfiglet.figlet_format("SinRec")
    print(f"{b}{ascii_banner}{w}")
    print(f"{BLUE}Github : https://github.com/0xsincode{RESET}")
    print(f"{RED}Scanning Target:{GREEN} {url}{RESET}")
    print(f"{RED}Scanning started at: {GREEN}{str(datetime.now())}{RESET}")
    print("=" * 50)


def arg():

    parser = optparse.OptionParser()
    parser.add_option("-u", "--url", dest="url", help="Target WebSite EX:example.com")
    parser.add_option("-t", "--user", dest="user", help="Target User")
    parser.add_option("-p", "--phone", dest="phone", help="Target Phone Number")
    parser.add_option("-m", "--mac", dest="mac", help="Target Mac Adress")
    parser.add_option("-a", "--hash", dest="hash", help="hash")
    parser.add_option("-f", "--file", dest="file", help="file")
    (options, arg) = parser.parse_args()
    if options.url:
        if options.url[0:4] == "http":
            print("delet http/https and try again")
        elif options.url == "":
            exit(0)
            print("Enter the link ")
    try:
        if options.phone[0:1] != "+":
            print("Use phone number country code")
            exit(0)
    except:
        pass
    return options
options = arg()
target = options.url
user = options.user
phone = options.phone
mac = options.mac
hash = options.hash
file = options.file
banner(target)

q = Queue()
list_lock = Lock()
discovered_domains = []
def get_sub(target):
    def scan_subdomains(domain):
        try:
            global q
            while True:
                subdomain = q.get()
                url = f"http://{subdomain}.{domain}"
                try:
                    requests.get(url)
                except requests.ConnectionError:
                    pass
                else:
                    print(f"{GREEN}[+] Discovered subdomain:{RESET}", url)
                    with list_lock:
                        discovered_domains.append(url)
                q.task_done()
        except:
            pass
    def main(domain, n_threads, subdomains):
        try:
            global q
            for subdomain in subdomains:
                q.put(subdomain)
            for t in range(n_threads):
                worker = Thread(target=scan_subdomains, args=(domain,))
                worker.daemon = True
                worker.start()
        except:
            pass
    domain = target
    wordlist = input("subdomain worlist >> ")
    num_threads = int(input("Threads Number >> "))
    output_file = input("Output File >> ")
    main(domain=domain, n_threads=num_threads, subdomains=open(wordlist).read().splitlines())
    q.join()
    with open(output_file, "w") as f:
        for url in discovered_domains:
            print(url, file=f)



def ftp_bruteforcer():
    host = input(f"{GREEN}Host >> {RESET}")
    user = input(f"{GREEN}User >> {RESET}")
    port = 21
    wordlist = input("Password wordlist-> ")

    def is_valid(password):
        server = ftplib.FTP()
        print(f"{Fore.GREEN}Trying{Fore.RESET}", password)
        try:
            server.connect(host, port, timeout=4)
            server.login(user, password)
        except ftplib.error_perm:
            return False
        else:
            print(f"{Fore.GREEN}[+] Founded:", password, Fore.RESET)
            return True

    passwords = open(wordlist).read().split("\n")
    print(f"{Fore.BLUE}Lenght Of Password To Try :{Fore.RESET}", len(passwords))
    for password in passwords:
        if is_valid(password):
            break


def hiden_directory():
    hiden_dir.dir_hiden(target)

def ip_info(domain):
    ip = socket.gethostbyname(domain)
    url = f"http://ip-api.com/json/{ip}?"
    ip_info = requests.get(url).json()

    country = ip_info["country"]
    countryCode = ip_info["countryCode"]
    regionName = ip_info["regionName"]
    city = ip_info["city"]
    lat = ip_info["lat"]
    lon = ip_info["lon"]
    google_map_link = f"https://maps.google.com/?q={lat},{lon}"
    isp = ip_info["isp"]
    org = ip_info["org"]
    As = ip_info["as"]
    query = ip_info["query"]
    print(YELLOW,"#"*10,RESET,"IP INFO",YELLOW,"#"*10,RESET)
    print(f"{GREEN}country:{RESET}", country)
    print(f"{GREEN}countryCode:{RESET}", countryCode)
    print(f"{GREEN}regionName:{RESET}", regionName)
    print(f"{GREEN}City:{RESET}", city)
    print(f"{GREEN}Goole Map Link :{RESET}", google_map_link)
    print(f"{GREEN}ISP:{RESET}", isp)
    print(f"{GREEN}Org:{RESET}", org)
    print(f"{GREEN}AS:{RESET}", As)
    print(f"{GREEN}Query:{RESET}", query)
    print(YELLOW,"#"*10,RESET,"REVERSE IP",YELLOW,"#"*10,RESET)


def checkRobots(url):
    request = requests.get(f"http://{url}/robots.txt")
    print("-------Checking /robots.txt-------\n")
    if request.status_code == 200:
        print(f"{GREEN}[+] http://{url}/robots.txt Found{RESET}\n")
        print("**** trying reading content ****\n")
        try:
            print(f"{request.text}")
        except:
            print(f"{RED}[-] can't reading the content of robots.txt{RESET}")
    else:
        print(f"{RED}[-] robots.txt Not Exist{RESET}")




def user_recon(user):

    links = {
        'instagram' :f'https://www.instagram.com/{user}',
        'facebook'  :f'https://www.facebook.com/{user}',
        'twitter'   :f'https://www.twitter.com/{user}',
        'youtube'   :f'https://www.youtube.com/{user}',
        'blogger'   :f'https://{user}.blogspot.com',
        'reddit'    :f'https://www.reddit.com/user/{user}',
        'pinterest' :f'https://www.pinterest.com/{user}',
        'github'    :f'https://www.github.com/{user}',
        'tumblr'    :f'https://{user}.tumblr.com',
        'flickr'    :f'https://www.flickr.com/people/{user}',
        'vimeo'     :f'https://vimeo.com/{user}',
        'soundcloud':f'https://soundcloud.com/{user}',
        'disqus'    :f'https://disqus.com/{user}',
        'medium'    :f'https://medium.com/@{user}',
        'devianart' :f'https://{user}.deviantart.com',
        'vk'        :f'https://vk.com/{user}',
        'about.me'  :f'https://about.me/{user}',
        'imgur'     :f'https://imgur.com/user/{user}',
        'slideshare':f'https://slideshare.net/{user}',
        'spotify'   :f'https://open.spotify.com/user/{user}',
        'scribd'    :f'https://www.scribd.com/{user}',
        'badoo'     :f'https://www.badoo.com/en/{user}',
        'patreon'   :f'https://www.patreon.com/{user}',
        'bitbucket' :f'https://bitbucket.org/{user}',
        'dailymotion':f'https://www.dailymotion.com/{user}',
        'etsy'      :f'https://www.etsy.com/shop/{user}',
        'cashme'    :f'https://cash.me/{user}',
        'behance'   :f'https://www.behance.net/{user}',
        'goodreads' :f'https://www.goodreads.com/{user}',
        'instructables':f'https://www.instructables.com/member/{user}',
        'keybase'   :f'https://keybase.io/{user}',
        'kongregate':f'https://kongregate.com/accounts/{user}',
        'livejournal':f'https://{user}.livejournal.com',
        'angellist' :f'https://angel.co/{user}',
        'last.fm'   :f'https://last.fm/user/{user}',
        'dribbble'  :f'https://dribbble.com/{user}',
        'codeacademy':f'https://www.codecademy.com/{user}',
        'gravatar'  :f'https://en.gravatar.com/{user}',
        'foursquare':f'https://foursquare.com/{user}',
        'gumroad'   :f'https://www.gumroad.com/{user}',
        'newgrounds':f'https://{user}.newgrounds.com',
        'wattpad'   :f'https://www.wattpad.com/user/{user}',
        'canva'     :f'https://www.canva.com/{user}',
        'creativemarket':f'https://creativemarket.com/{user}',
        'trakt'     :f'https://www.trakt.tv/users/{user}',
        '500px'     :f'https://500px.com/{user}',
        'buzzfeed'  :f'https://buzzfeed.com/{user}',
        'tripadvisor':f'https://tripadvisor.com/members/{user}',
        'hubpages'  :f'https://{user}.hubpages.com',
        'contently' :f'https://{user}.contently.com',
        'houzz'     :f'https://houzz.com/user/{user}',
        'blip.fm'   :f'https://blip.fm/{user}',
        'wikipedia' :f'https://www.wikipedia.org/wiki/User:{user}',
        'codementor':f'https://www.codementor.io/{user}',
        'reverbnation':f'https://www.reverbnation.com/{user}',
        'designspiration65':f'https://www.designspiration.net/{user}',
        'bandcamp'  :f'https://www.bandcamp.com/{user}',
        'colourlovers':f'https://www.colourlovers.com/love/{user}',
        'ifttt'     :f'https://www.ifttt.com/p/{user}',
        'slack'     :f'https://{user}.slack.com',
        'okcupid'   :f'https://www.okcupid.com/profile/{user}',
        'trip'      :f'https://www.trip.skyscanner.com/user/{user}',
        'ello'      :f'https://ello.co/{user}',
        'hackerone' :f'https://hackerone.com/{user}',
        'freelancer':f'https://www.freelancer.com/u/{user}'
    }
    for social, url in links.items():
        request = requests.get(f"{url}")
        if request.status_code == 200:
            print(f"{GREEN}[+]Found{RESET}  {social} : {url}")


def phone_number(phone):
    api_key = "44FC54E527444DF0B584B4E09574097D"
    url = f"https://api.veriphone.io/v2/verify?phone={phone}&key={api_key}"
    data = requests.get(url).json()
    list = [  "status","phone","phone_valid","phone_type","phone_region","country","country_code","country_prefix","international_number","local_number","e164","carrier"]
    for x in list:
        print(f"{GREEN}{x}{RESET} : {data[x]}")

def remove_Brackets(list1):
    try:
        return str(list1).replace('[','').replace(']','').replace("'","").replace(",",f"{GREEN} | {RESET}")
    except:
        pass



def mac_remove_Brackets(list1):
    try:
        return str(list1).replace('[','').replace(']','').replace("'","").replace(",",f"{GREEN} | {RESET}").replace('{',"").replace('}',"")
    except:
        pass
def mac_info(mac):
    api_key = "at_SgI1zp6ydVxyMWWyhcmMfj2eYN7N8"
    url = f"https://mac-address.whoisxmlapi.com/api/v1?apiKey={api_key}&macAddress={mac}"
    data = requests.get(url).json()
    print(BLUE,"#"*20,"MAC ADDRESS INFO","#"*20,RESET)
    print(f"{GREEN}Vendor Detail{RESET} : ",mac_remove_Brackets(data["vendorDetails"]))
    print(f"\n{GREEN}block Details{RESET} : ",mac_remove_Brackets(data["blockDetails"]))
    print(f"\n{GREEN}Mac Address Details{RESET} : ",mac_remove_Brackets(data["macAddressDetails"]))




def tech(domain):
    wt = webtech.WebTech()
    results = wt.start_from_url(f"https://{domain}", timeout=3)
    print(results)


def crack_hash(hash):

    print(f"""{BLUE}
                            --> blake2s
                            --> sha512
                            --> sha384
                            --> sha224
                            --> blake2b
                            --> sha3_512
                            --> sha1
                            --> sha256
                            --> md5
                            {RESET}                           {RED}This is Type Of hash Available To crack it :)
    {RESET}""")



    hash_type = input("Name Of hash >> ")
    hash = hash
    wordlist = str(urllib.request.urlopen('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou-50.txt').read(), 'utf-8')







    if hash_type == "blake2s":
        for x in wordlist.split('\n'):
            hash_ = hashlib.blake2s(bytes(x, 'utf-8')).hexdigest()
            if hash_ == hash:
                password = str(x)
                print(f"{GREEN}Found : {password}{RESET}")
                exit()
            else:
                password = str(x)
                print(f'{RED}Invalid Password : {password}{RESET}')


        print(f"{RED}Password Not Found{RESET}")
    if hash_type == "sha512":
        for x in wordlist.split('\n'):
            hash_ = hashlib.sha512(bytes(x, 'utf-8')).hexdigest()
            if hash_ == hash:
                password = str(x)
                print(f"{GREEN}Found : {password}{RESET}")
                exit()
            else:
                password = str(x)
                print(f'{RED}Invalid Password : {password}{RESET}')


        print(f"{RED}Password Not Found{RESET}")
    if hash_type == "sha384":
        for x in wordlist.split('\n'):
            hash_ = hashlib.sha384(bytes(x, 'utf-8')).hexdigest()
            if hash_ == hash:
                password = str(x)
                print(f"{GREEN}Found : {password}{RESET}")
                exit()
            else:
                password = str(x)
                print(f'{RED}Invalid Password : {password}{RESET}')

        print(f"{RED}Password Not Found{RESET}")
    if hash_type == "sha224":
        for x in wordlist.split('\n'):
            hash_ = hashlib.sha224(bytes(x, 'utf-8')).hexdigest()
            if hash_ == hash:
                password = str(x)
                print(f"{GREEN}Found : {password}{RESET}")
                exit()
            else:
                password = str(x)
                print(f'{RED}Invalid Password : {password}{RESET}')

        print(f"{RED}Password Not Found{RESET}")
    if hash_type == "blake2b":
        for x in wordlist.split('\n'):
            hash_ = hashlib.blake2b(bytes(x, 'utf-8')).hexdigest()
            if hash_ == hash:
                password = str(x)
                print(f"{GREEN}Found : {password}{RESET}")
                exit()
            else:
                password = str(x)
                print(f'{RED}Invalid Password : {password}{RESET}')

        print(f"{RED}Password Not Found{RESET}")
    if hash_type == "sha3_512":
        for x in wordlist.split('\n'):
            hash_ = hashlib.sha3_512(bytes(x, 'utf-8')).hexdigest()
            if hash_ == hash:
                password = str(x)
                print(f"{GREEN}Found : {password}{RESET}")
                exit()
            else:
                password = str(x)
                print(f'{RED}Invalid Password : {password}{RESET}')

        print(f"{RED}Password Not Found{RESET}")
    if hash_type == "sha1":
        for x in wordlist.split('\n'):
            hash_ = hashlib.sha1(bytes(x, 'utf-8')).hexdigest()
            if hash_ == hash:
                password = str(x)
                print(f"{GREEN}Found : {password}{RESET}")
                exit()
            else:
                password = str(x)
                print(f'{RED}Invalid Password : {password}{RESET}')

        print(f"{RED}Password Not Found{RESET}")
    if hash_type == "sha256":
        for x in wordlist.split('\n'):
            hash_ = hashlib.sha256(bytes(x, 'utf-8')).hexdigest()
            if hash_ == hash:
                password = str(x)
                print(f"{GREEN}Found : {password}{RESET}")
                exit()
            else:
                password = str(x)
                print(f'{RED}Invalid Password : {password}{RESET}')

        print(f"{RED}Password Not Found{RESET}")
    if hash_type == "md5":
        for x in wordlist.split('\n'):
            hash_ = hashlib.md5(bytes(x, 'utf-8')).hexdigest()
            if hash_ == hash:
                password = str(x)
                print(f"{GREEN}Found : {password}{RESET}")
                exit()
            else:
                password = str(x)
                print(f'{RED}Invalid Password : {password}{RESET}')

        print(f"{RED}Password Not Found{RESET}")


def scaning(domain):
    N_THREADS = 200
    # thread queue
    q = Queue()
    print_lock = Lock()

    def port_scan(port):
        """
        Scan a port on the global variable `host`
        """
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((host, port))
        except:
            with print_lock:
                print(f"{RED}{host:15}:{port:5} is closed  {RESET}", end='\r')
        else:
            with print_lock:
                print(f"{GREEN}{host:15}:{port:5} is open    {RESET}")
        finally:
            s.close()


    def scan_thread():
        global q
        while True:

            worker = q.get()

            port_scan(worker)

            q.task_done()


    def main(host, ports):
        global q
        for t in range(N_THREADS):

            t = Thread(target=scan_thread)

            t.daemon = True

            t.start()

        for worker in ports:

            q.put(worker)


        q.join()


    if __name__ == "__main__":
        port_range = input("Ex: 1-1024\nEnter The Port >> ")
        host, port_range = domain, port_range

        start_port, end_port = port_range.split("-")
        start_port, end_port = int(start_port), int(end_port)

        ports = [ p for p in range(start_port, end_port)]

        main(host, ports)


def js_file(domain):
    domain = f"https://{domain}"
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36"
    html = session.get(domain).content
    soup = bs(html, "html.parser")
    script_files = []
    for script in soup.find_all("script"):
        if script.attrs.get("src"):
            # if the tag has the attribute 'src'
            script_url = urljoin(domain, script.attrs.get("src"))
            script_files.append(script_url)
    print("Total script files in the page:", len(script_files))
    with open("javascript_files.txt", "w") as f:
        for js_file in script_files:
            print(js_file, file=f)
    print(f"{GREEN}Result Saved in javascript_files.txt{RESET}")


def all_image(domain):
    def is_valid(url):
        parsed = urlparse(url)
        return bool(parsed.netloc) and bool(parsed.scheme)


    def get_all_images(url):
        soup = bs(requests.get(url).content, "html.parser")
        urls = []
        for img in tqdm(soup.find_all("img"), "Extracting images"):
            img_url = img.attrs.get("src")
            if not img_url:
                continue
            img_url = urljoin(url, img_url)
            try:
                pos = img_url.index("?")
                img_url = img_url[:pos]
            except ValueError:
                pass
            if is_valid(img_url):
                urls.append(img_url)
        return urls


    def download(url, pathname):
        if not os.path.isdir(pathname):
            os.makedirs(pathname)
        response = requests.get(url, stream=True)
        file_size = int(response.headers.get("Content-Length", 0))
        filename = os.path.join(pathname, url.split("/")[-1])
        progress = tqdm(response.iter_content(1024), f"{GREEN}Downloading {filename}{RESET}", total=file_size, unit="B", unit_scale=True, unit_divisor=1024)
        with open(filename, "wb") as f:
            for data in progress.iterable:
                f.write(data)
                progress.update(len(data))
    def main(url, path):
        imgs = get_all_images(url)
        for img in imgs:
            download(img, path)



    if __name__ == "__main__":
        url = f"https://{domain}"
        path = input("path to save images >> ")

        if not path:
            path = urlparse(url).netloc

        main(url, path)



def email_extractor(domain):
    print(GREEN,"#"*20,RESET,"EMAIL EXTRACTOR", GREEN,"#"*20,RESET)
    url = f"https://{domain}"
    EMAIL_REGEX = r"""\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"""
    session = HTMLSession()
    r = session.get(url)
    r.html.render()
    for re_match in re.finditer(EMAIL_REGEX, r.html.raw_html.decode()):
        print(re_match.group())

internal_urls = set()
external_urls = set()
total_urls_visited = 0

def all_links(domain):
    # internal_urls = set()
    # external_urls = set()
    # total_urls_visited = 0
    def is_valid(url):
        parsed = urlparse(url)
        return bool(parsed.netloc) and bool(parsed.scheme)

    def get_all_website_links(url):
        urls = set()
        domain_name = urlparse(url).netloc
        soup = BeautifulSoup(requests.get(url).content, "html.parser")
        for a_tag in soup.findAll("a"):
            href = a_tag.attrs.get("href")
            if href == "" or href is None:
                continue

            href = urljoin(url, href)
            parsed_href = urlparse(href)

            href = parsed_href.scheme + "://" + parsed_href.netloc + parsed_href.path
            if not is_valid(href):
                continue
            if href in internal_urls:
                continue
            if domain_name not in href:
                if href not in external_urls:
                    print(f"{YELLOW}[!] External link: {href}{RESET}")
                    external_urls.add(href)
                continue
            print(f"{GREEN}[*] Internal link: {href}{RESET}")
            urls.add(href)
            internal_urls.add(href)
        return urls


    def crawl(url, max_urls=30):
        global total_urls_visited
        total_urls_visited += 1
        print(f"{YELLOW}[*] Crawling: {url}{RESET}")
        links = get_all_website_links(url)
        for link in links:
            if total_urls_visited > max_urls:
                break
            crawl(link, max_urls=max_urls)


    if __name__ == "__main__":
        url = f"https://{domain}"
        max_urls = int(input(f"\ndefault:30\nmax urls to crawl >> "))

        crawl(url, max_urls=max_urls)

        print("[+] Total Internal links:", len(internal_urls))
        print("[+] Total External links:", len(external_urls))
        print("[+] Total URLs:", len(external_urls) + len(internal_urls))
        print("[+] Total crawled URLs:", max_urls)

        domain_name = urlparse(url).netloc


        with open(f"{domain_name}_internal_links.txt", "w") as f:
            for internal_link in internal_urls:
                print(internal_link.strip(), file=f)

        with open(f"{domain_name}_external_links.txt", "w") as f:
            for external_link in external_urls:
                print(external_link.strip(), file=f)



def domain_info(domain):
    def Reverse_Analytics_Search(domain):
        url = f"https://api.hackertarget.com/analyticslookup/?q={domain}"
        data = requests.get(url)
        print(data.text)
    def asn(domain):
        ip = socket.gethostbyname(domain)
        url = f"https://api.hackertarget.com/aslookup/?q={ip}"
        data = requests.get(url)
        print(data.text.replace('"',"").replace(","," | "))


    def dnslookup(domain):
        url = f"https://api.hackertarget.com/dnslookup/?q={domain}"
        data = requests.get(url)
        print(data.text)

    def reversedn(domain):
        ip = socket.gethostbyname(domain)
        url = f"https://api.hackertarget.com/reversedns/?q={ip}"
        data = requests.get(url)
        print(data.text)

    def findshareddns(domain):
        url = f"https://api.hackertarget.com/findshareddns/?q={domain}"
        data = requests.get(url)
        print(data.text)


    def reverseiplookup(domain):
        ip = socket.gethostbyname(domain)
        url = f'https://api.hackertarget.com/reverseiplookup/?q={ip}'
        data = requests.get(url)
        print(data.text)

    def subnetcalc(domain):
        ip = socket.gethostbyname(domain)
        url = f"https://api.hackertarget.com/subnetcalc/?q={ip}"
        data = requests.get(url)
        print(data.text)
    def main():
        print(YELLOW,"#"*15,RESET,GREEN,"Reverse Analytics Search",RESET,YELLOW,"#"*15,RESET)
        Reverse_Analytics_Search(domain)
        print(YELLOW,"#"*58,RESET)
        print("\n")
        print(YELLOW,"#"*15,RESET,GREEN,"ASN lookup",RESET,YELLOW,"#"*15,RESET)
        asn(domain)
        print(YELLOW,"#"*58,RESET)
        print("\n")
        print(YELLOW,"#"*15,RESET,GREEN,"DNS lookup",RESET,YELLOW,"#"*15,RESET)
        dnslookup(domain)
        print(YELLOW,"#"*58,RESET)
        print("\n")
        print(YELLOW,"#"*15,RESET,GREEN,"Reverse DNS",RESET,YELLOW,"#"*15,RESET)
        reversedn(domain)
        print(YELLOW,"#"*58,RESET)
        print("\n")
        print(YELLOW,"#"*15,RESET,GREEN,"Shared DNS",RESET,YELLOW,"#"*15,RESET)
        findshareddns(domain)
        print(YELLOW,"#"*58,RESET)
        print("\n")
        print(YELLOW,"#"*15,RESET,GREEN,"Reverse Ip lookup",RESET,YELLOW,"#"*15,RESET)
        reverseiplookup(domain)
        print(YELLOW,"#"*58,RESET)
        print("\n")
        print(YELLOW,"#"*15,RESET,GREEN,"Subnet Calc",RESET,YELLOW,"#"*15,RESET)
        subnetcalc(domain)
        print(YELLOW,"#"*58,RESET)

    main()


def extarct_email_from_file(file):
    import re

    try:
        def email_extractor(file):
            output_file = open("Emails_Extracted_from_" + file, "a")
            email_count = 0
            with open(file) as f:
                lines = f.readlines()
                for line in lines:
                    pattern = re.compile(r'([a-zA-Z0-9_.+%$-]+@[a-zA-Z0-9_.-]+\.[a-zA-Z]+)')
                    matches = pattern.finditer(line)
                    for match in matches:
                        email_count += 1
                        output_file.write("Email-"+ str(email_count) + ": " + match.group() + "\n")
            output_file.close()
            print(YELLOW,email_count, f"[+] emails found.\nResult Saved In Emails_Extracted_from_{file}",RESET)

    except Exception as e:
        print("Invalid contents in file. Please check text file.")


    email_extractor(file)


def options():
    while True:
        user_options = f"""
        {YELLOW}[1]{RESET}{GREEN} Subdomain Enumeration{RESET}
        {YELLOW}[2]{RESET}{GREEN} FTP Bruteforcer{RESET}
        {YELLOW}[3]{RESET}{GREEN} Hiden Directory Discovering{RESET}
        {YELLOW}[4]{RESET}{GREEN} Robots Page Scan{RESET}
        {YELLOW}[5]{RESET}{GREEN} Ip Info{RESET}
        {YELLOW}[6]{RESET}{GREEN} User Recon{RESET}
        {YELLOW}[7]{RESET}{GREEN} Phone Number Validation{RESET}
        {YELLOW}[8]{RESET}{GREEN} Mac Address Info{RESET}
        {YELLOW}[9]{RESET}{GREEN} Get Web Application Technology{RESET}
        {YELLOW}[10]{RESET}{GREEN} Domain Info{RESET}
        {YELLOW}[11]{RESET}{GREEN} Hash Crack{RESET}
        {YELLOW}[12]{RESET}{GREEN} Web Application Scaning Port{RESET}
        {YELLOW}[13]{RESET}{GREEN} Get All Js File From Web Application{RESET}
        {YELLOW}[14]{RESET}{GREEN} Get All Image From Web Application{RESET}
        {YELLOW}[15]{RESET}{GREEN} Extract Emails From Web Page{RESET}
        {YELLOW}[16]{RESET}{GREEN} Extract All Links From Web Page{RESET}
        {YELLOW}[17]{RESET}{GREEN} Extract All Emails From Document{RESET}
        {YELLOW}[0]{RESET}{GREEN} Exit{RESET}
        """
        try:
            print(user_options)
            choice = int(input(">> "))
        except Exception:
            print(f"{RED}Option Not Valid :({RESET}")
        choices = list(range(0, 18))
        if choice in choices:
            if choice == 1:
                get_sub(target)
            elif choice == 2:
                ftp_bruteforcer()
            elif choice == 3:
                hiden_directory()
            elif choice == 4:
                checkRobots(target)
            elif choice == 5:
                ip_info(target)
            elif choice == 6:
                user_recon(user)
            elif choice == 7:
                phone_number(phone)
            elif choice == 8:
                mac_info(mac)
            elif choice == 9:
                tech(target)
            elif choice == 10:
                domain_info(target)
            elif choice == 11:
                crack_hash(hash)
            elif choice == 12:
                scaning(target)
            elif choice == 13:
                js_file(target)
            elif choice == 14:
                all_image(target)
            elif choice == 15:
                email_extractor(target)
            elif choice == 16:
                all_links(target)
            elif choice == 17:
                extarct_email_from_file(file)
            elif choice == 0:
                break
                exit(0)
        else:
            print(f"{RED}Option Not Valid{RESET}")
            print(user_options)

try:
    options()
except Exception:
    pass
