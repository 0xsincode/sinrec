import requests
from colorama import init, Fore

init()

GREEN = Fore.GREEN
RED   = Fore.RED
RESET = Fore.RESET
BLUE  = Fore.BLUE


def request(url):
    try:
        return requests.get(f"http://{url}")
    except requests.exceptions.ConnectionError:
        pass



def dir_hiden(target):
    # domain_name = input("target Domain >>")
    domain_name = target
    dir_list = input("Directory List >>")
    dir_list = open(dir_list, "r")

    for dir in dir_list:
        directory = dir.strip()
        url = f"{domain_name}/{directory}"
        resp = request(url)
        if resp:
            print(f"{GREEN}Found:{RESET}{url}")
