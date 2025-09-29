from argparse import ArgumentParser, Namespace
from nixtools.gpg import (
    GPG_Key,
    get_card_info,
    get_gpg_keys,
    get_signing_keys,
    get_best_key,
)
from dataclasses import fields
from re import search
from sys import exit

parser = ArgumentParser(description="GPG CLI tools")
group = parser.add_mutually_exclusive_group()

# parser.add_argument("card", "-c", "--card", type=int, default=0, help="Get card info")
group.add_argument("-c", "--card", action="store_true")
group.add_argument("-k", "--keys", action="store_true")
group.add_argument("-s", "--signing", action="store_true")
group.add_argument("-x", "--exact", action="store_true")
args: Namespace = parser.parse_args()

if args.card:
    # return the keys on the card
    print(get_card_info())

elif args.keys:
    print(get_gpg_keys())
elif args.signing:
    signing_keys = get_signing_keys()
    max_len = max(len(key.algorithm) for key in signing_keys)
    for key in signing_keys:
        print(key.algorithm.ljust(max_len), "--", key.subkey)

elif args.exact:
    """
    Finds the best signing subkey.
    Search pattern is smart cards > TPM > Any remaining present key;
    From those, Ed25519 > NIST* > RSA*
    * Each family will be assessed internally from high- to low-bit counts
    """
    signing_keys = get_signing_keys()
    signing_subkey_ids = [x.subkey for x in signing_keys]

    keys_dict: dict[str, GPG_Key] = {x.subkey: x for x in signing_keys}

    # Card slots may hold multi-functional keys
    filter = ["card_signature_key", "card_encryption_key", "card_authentication_key"]

    if card_info := get_card_info():
        raw_keys: list[str] = [
            getattr(card_info, x.name) for x in fields(card_info) if x.name in filter
        ]
        card_subkeys: list[str] = [x.replace(" ", "") for x in raw_keys]

        # find which of these is a signing key
        card_signing_key_ids = [x for x in card_subkeys if x in signing_subkey_ids]
        card_signing_keys: list[GPG_Key] = [keys_dict[x] for x in card_signing_key_ids]

        if not (best_card_key := get_best_key(card_signing_keys)):
            best_card_key = []

    tpm_keys = [x for x in signing_keys if search(r"(?i)tpm", x.card_no)]

    if tpm_keys or card_info:
        hardware_keys = tpm_keys + [best_card_key]
        print(get_best_key(hardware_keys).subkey)
        exit(0)

    # ADD FALLTHROUGH PRESENT LOGIC
    remaining_keys = [x for x in signing_keys if x.presence == " "]
    print(get_best_key(remaining_keys).subkey)
    exit(0)
