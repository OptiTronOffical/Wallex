import re
import docx
import docx2txt
import fitz

from mnemonic import Mnemonic
from eth_account import Account

from pycoin.symbols.btc import network as btc_network
from pycoin.symbols.doge import network as doge_network
from pycoin.symbols.ltc import network as ltc_network
from pycoin.symbols.dash import network as dash_network


def parse(data):
    try:
        path_file, mode = data
        path_file_lower = path_file.lower()

        if path_file_lower.endswith((".txt", ".json", ".html")):
            with open(path_file, "r", encoding="utf8") as f:
                content = f.read()

        elif path_file_lower.endswith(".pdf"):
            with fitz.open(path_file) as doc:
                content = ""
                for page in doc:
                    content += page.get_text()

        elif path_file_lower.endswith(".doc"):
            content = docx2txt.process(path_file)

        elif path_file_lower.endswith(".docx"):
            doc = docx.Document(path_file)
            full_text = []
            for para in doc.paragraphs:
                full_text.append(para.text)
            content = "\n".join(full_text)

        # mnemonics
        if mode == "seeds":
            pattern_seed_12 = r"[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+"
            pattern_seed_24 = r"[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+[\s\,\.\d]{1,3}[a-z]+"

            mnemo_validator = Mnemonic("english")

            mnemonics = set()

            re_mnemonics = re.findall(pattern_seed_12, content)
            re_mnemonics += re.findall(pattern_seed_24, content)
            for mnemonic in re_mnemonics:
                mnemonic = re.sub(r"[^a-z]", " ", mnemonic)
                mnemonic = re.sub(r"\s+", " ", mnemonic)
                mnemonic_len = len(mnemonic.split())
                if mnemonic_len == 12 or mnemonic_len == 24:
                    if mnemo_validator.check(mnemonic):
                        mnemonics.add(mnemonic)

            return {
                "path": path_file,
                "mnemonics": mnemonics,
            }

        # privkeys
        elif mode == "privkeys":
            privkeys_eth = set()
            privkeys_btc = set()
            privkeys_ltc = set()
            privkeys_doge = set()
            privkeys_dash = set()

            pattern_privkey = "[0-9a-f]{64}"
            pattern_privkey_0x = "0x[0-9a-fA-F]{64}"
            pattern_privkey_core_prefixes = {
                "L1": "BTC",
                "L2": "BTC",
                "L3": "BTC",
                "L4": "BTC",
                "L5": "BTC",
                "T": "LTC",
                "Q": "DOGE",
                "X": "DASH",
                "S": "XLM",
            }

            # eth
            content = content.replace("\n", "")
            for privkey in set(re.findall(pattern_privkey, content)):
                try:
                    address = Account.from_key(privkey).address
                    privkeys_eth.add(f"{privkey}:{address}")
                except:
                    pass

            for privkey in set(re.findall(pattern_privkey_0x, content)):
                try:
                    address = Account.from_key(privkey).address
                    privkeys_eth.add(f"{privkey}:{address}")
                except:
                    pass

            # core
            for letter, coin in pattern_privkey_core_prefixes.items():
                pattern_privkey_core = "^%(letter)s[A-Za-z0-9].{40,60}$" % {"letter": letter}

                if coin == "BTC":
                    for privkey in set(re.findall(pattern_privkey_core, content)):
                        try:
                            address = btc_network.address.for_p2pkh_wit(btc_network.parse.wif(privkey).hash160())
                            privkeys_btc.add(f"{privkey}:{address}")
                        except Exception as e:
                            pass
                elif coin == "LTC":
                    for privkey in set(re.findall(pattern_privkey_core, content)):
                        try:
                            address = ltc_network.address.for_p2pkh_wit(ltc_network.parse.wif(privkey).hash160())
                            privkeys_ltc.add(f"{privkey}:{address}")
                        except Exception as e:
                            pass
                if coin == "DOGE":
                    for privkey in set(re.findall(pattern_privkey_core, content)):
                        try:
                            address = doge_network.parse.wif(privkey).address()
                            privkeys_doge.add(f"{privkey}:{address}")
                        except Exception as e:
                            pass
                elif coin == "DASH":
                    for privkey in set(re.findall(pattern_privkey_core, content)):
                        try:
                            address = dash_network.parse.wif(privkey).address()
                            privkeys_dash.add(f"{privkey}:{address}")
                        except Exception as e:
                            pass

            return {
                "path": path_file,
                "privkeys_eth": privkeys_eth,
                "privkeys_btc": privkeys_btc,
                "privkeys_ltc": privkeys_ltc,
                "privkeys_doge": privkeys_doge,
                "privkeys_dash": privkeys_dash,
            }
    except:
        pass
