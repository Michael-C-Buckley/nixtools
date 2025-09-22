"""
GPG tools for obtaining info about GnuPG keys
"""

# Python Modules
from dataclasses import dataclass

# Third Party Modules
from textfsm import TextFSM
from plumbum import local

# Testing Modules
from icecream import ic


@dataclass
class GPG_Key:
    algorithm: str
    capability: str
    card_no: str
    creation: str
    expiration: str
    keygrip: str
    primary_key: str
    subkey: str


def get_key(primary_key: str = "") -> str:
    """"""
    cmd = local["gpg"]["-K", "--with-keygrip", "--with-subkey-fingerprint"]

    if primary_key:
        cmd = cmd[primary_key]

    return cmd()


def parse_key_info(primary_key: str = "") -> list[GPG_Key]:
    """"""
    output: list[GPG_Key] = []
    keys = get_key(primary_key)

    with open("nixtools/textfsm/gpg-info.txt") as f:
        result = TextFSM(f).ParseTextToDicts(keys)

    for raw_key in result:
        output.append(GPG_Key(**raw_key))

    return output


def get_keys_by_attr(input: list[GPG_Key], attr: str, filter: str) -> list[GPG_Key]:
    """Filters keys to the desired attribute and value"""

    # Capabilities have a custom behavior since keys may have multiple
    behavior = {
        "capability": lambda x: filter in getattr(x, attr),
    }.get(attr, lambda x: getattr(x, attr) == filter)

    return [x for x in input if behavior(x)]


# Testing
if __name__ == "__main__":
    keys = parse_key_info()
    ic(get_keys_by_attr(keys, "capability", "S"))
