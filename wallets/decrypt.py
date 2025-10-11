import utils
from wallets import wallet


def try_wallet(my_wallet, passwords, path_wallet):
    wallet_hash = False
    correct_password = False
    addresses = set()
    mnemonics = set()

    try:
        addresses = my_wallet.extract_adresses()
    except:
        pass

    is_encrypted = True
    try:
        is_encrypted = my_wallet.is_encrypted()
    except:
        pass

    if is_encrypted:
        try:
            wallet_hash = my_wallet.extract_hashcat()
        except:
            pass

        try:
            correct_password = my_wallet.try_passwords(passwords)
        except:
            pass

    try:
        wal_data = my_wallet.extract_wallet_data()
        for data in wal_data:
            mnemonics.add(data.data)
        mnemonics = list(mnemonics)
    except:
        pass

    try:
        addresses.union(my_wallet.extract_adresses_after_decrypt())
        addresses = list(addresses)
    except:
        pass

    return {
        "path": path_wallet,
        "wallet_hash": wallet_hash,
        "correct_password": correct_password,
        "addresses": addresses,
        "mnemonics": mnemonics,
        "passwords": passwords,
    }


def proc_wallet(data, correct_password=False):
    path_wallet, wallet_type, wallet_params, path_antipublic, passwords_dictionary, toggle_case, add_specials, add_numbers, timeout = data
    path_log = utils.get_path_log(path_wallet)

    if not correct_password:
        passwords = utils.process_passwords(path_wallet, path_log, path_antipublic, passwords_dictionary, toggle_case, add_specials, add_numbers, timeout)
    else:
        passwords = [correct_password]

    wallets_metamask_like = [
        wallet.WalletType.METAMASK,
        wallet.WalletType.BNB_CHAIN,
        wallet.WalletType.RONIN,
        wallet.WalletType.SUI,
        wallet.WalletType.BRAVE,
        wallet.WalletType.KARDIA_CHAIN,
        wallet.WalletType.RONIN,
        wallet.WalletType.CLOVER,
    ]

    try:
        with wallet.new_wallet(path_wallet, wallet_type, wallet_params) as my_wallet:
            return try_wallet(my_wallet, passwords, path_wallet)
    except Exception as e:
        if wallet_type in wallets_metamask_like:
            if wallet_type == wallet.WalletType.METAMASK:
                wallet_params = {"wallet_type": "metamask"}
            elif wallet_type == wallet.WalletType.BNB_CHAIN:
                wallet_params = {"wallet_type": "bnb_chain"}
            elif wallet_type == wallet.WalletType.RONIN:
                wallet_params = {"wallet_type": "ronin"}
            elif wallet_type == wallet.WalletType.SUI:
                wallet_params = {"wallet_type": "sui"}
            elif wallet_type == wallet.WalletType.BRAVE:
                wallet_params = {"wallet_type": "brave"}
            elif wallet_type == wallet.WalletType.KARDIA_CHAIN:
                wallet_params = {"wallet_type": "kardia_chain"}
            elif wallet_type == wallet.WalletType.RONIN:
                wallet_params = {"wallet_type": "ronin"}
            elif wallet_type == wallet.WalletType.CLOVER:
                wallet_params = {"wallet_type": "clover"}

            try:
                with wallet.new_wallet(path_wallet, wallet.WalletType.METAMASK_LIKE, wallet_params) as my_wallet:
                    return try_wallet(my_wallet, passwords, path_wallet)
            except:
                pass

        return False
