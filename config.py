# main settings choose TRUE/FALSE
path_logs = "input"
path_antipublic = False
path_dictionary = False
scanner_mode = False # waiting for new logs without closing
skip_checked = False
copy_failed_logs = False
timeout = 5000

# parser from logs
parse_seeds = True
parse_privkeys = False

# hashcat
path_binary = ""
path_rules = ""
enable_rules = False

# generate passwords
toggle_case = False
add_specials = False
add_numbers = False

# include wallets
# browser
check_metamask = True
check_bnb_chain = True
check_ronin = True
check_tronlink = True
check_sui = True
check_brave = True
check_brave_extension = True
check_kardia_chain = True
check_keplr = True
check_petra = True
check_martian = True
check_trust = True
check_phantom = True
check_atomic = True
check_coin98 = True
check_okx = True
check_math = True
check_unisat = True
check_exodus_extension = True
check_coinbase = True
check_braavos = True
check_rabby = True
check_terra = True
check_safepal = True
check_cryptocom = True
check_clover = True
check_energy8 = True
check_pontem_aptos = True
check_spika = True
check_finx = True
check_token_pocket = True
check_zeon = True
check_pantograph = True
check_starmask = True
check_monsta = True

# include desktop wallets
check_btc = True
check_ltc = True
check_doge = True
check_dash = True
check_guarda = True
check_exodus_desktop = True
check_electrum = True
check_coinomi = True
check_daedalus = True
check_mymonero = True
check_myetherwallet = True

# hardware wallets
skip_ledger = True
skip_trezor = True
