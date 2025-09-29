from argparse import ArgumentParser, Namespace
from nixtools.gpg import get_card_info, get_gpg_keys, get_signing_keys, GPG_Key
from dataclasses import fields
from re import match

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

    def assess_algorithms(keys: list[GPG_Key]) -> list[GPG_Key] | None:
        """"""
        ed_keys: list[GPG_Key] = []
        nist_keys: list[GPG_Key] = []
        rsa_keys: list[GPG_Key] = []

        for key in keys:
            if match(r"ed", key.algorithm):
                ed_keys.append(key)
            elif match(r"nistp", key.algorithm):
                nist_keys.append(key)
            elif match(r"rsa", key.algorithm):
                rsa_keys.append(key)

        if ed_keys:
            return ed_keys
        if nist_keys:
            max_len: int = max(
                int(key.algorithm.replace("nistp", "")) for key in nist_keys
            )
            return [x for x in nist_keys if x.algorithm == f"nistp{max_len}"]
        if rsa_keys:
            max_len: int = max(
                int(key.algorithm.replace("rsa", "")) for key in nist_keys
            )
            return [x for x in nist_keys if x.algorithm == f"rsa{max_len}"]

    if card_info := get_card_info():
        raw_keys: list[str] = [
            getattr(card_info, x.name) for x in fields(card_info) if x.name in filter
        ]
        card_subkeys: list[str] = [x.replace(" ", "") for x in raw_keys]

        # find which of these is a signing key
        card_signing_key_ids = [x for x in card_subkeys if x in signing_subkey_ids]
        card_signing_keys: list[GPG_Key] = [keys_dict[x] for x in card_signing_key_ids]

        if key_assessment := assess_algorithms(card_signing_keys):
            print(key_assessment[0].subkey)
        else:
            print("")

    # ADD TPM LOGIC
    # ADD FALLTHROUGH PRESENT LOGIC
