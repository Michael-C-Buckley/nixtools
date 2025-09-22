"""
GPG tools for obtaining info about GnuPG keys
"""

# Python Modules
from dataclasses import dataclass

# Third Party Modules
from textfsm import TextFSM
from plumbum import local


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


def get_info_from_shell(primary_key: str = "") -> str:
    """Wrapper for getting the long string from the CLI"""
    cmd = local["gpg"]["-K", "--with-keygrip", "--with-subkey-fingerprint"]

    if primary_key:
        cmd = cmd[primary_key]

    return cmd()


def get_gpg_keys(primary_key: str = "") -> list[GPG_Key]:
    """Fetches key info from the shell of either all private keys or the one specified as the primary key"""
    raw_string = get_info_from_shell(primary_key)

    with open("nixtools/textfsm/gpg-info.txt") as f:
        result = TextFSM(f).ParseTextToDicts(raw_string)

    return [GPG_Key(**raw_key) for raw_key in result]


def get_keys_by_attr(input: list[GPG_Key], attr: str, filter: str) -> list[GPG_Key]:
    """Filters keys to the desired attribute and value"""

    if attr == "capability":
        filter = filter.upper()

    def exact_match(elem):
        """Match the entire term exactly"""
        return getattr(elem, attr) == filter

    def fuzzy_match(elem):
        """Match each item individually, like capabilities"""
        return set(filter) <= set(getattr(elem, attr))

    behavior = {
        "capability": fuzzy_match,
    }.get(attr, exact_match)

    return [x for x in input if behavior(x)]
