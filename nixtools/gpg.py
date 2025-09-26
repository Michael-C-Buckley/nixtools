"""
GPG tools for obtaining info about GnuPG keys
"""

# Python Modules
from dataclasses import dataclass
from shutil import which
from subprocess import run  # nosec B404

# Third Party Modules
from textfsm import TextFSM


@dataclass
class GPG_Key:
    algorithm: str
    capability: str
    card_no: str
    creation: str
    expiration: str
    keygrip: str
    presence: str
    primary_key: str
    subkey: str


@dataclass
class gpg_card:
    reader: str
    application_id: str
    application_type: str
    version: str
    manufacturer: str
    serial_number: str
    cardholder_name: str
    language_prefs: str
    salutation: str
    public_key_url: str
    login_data: str
    signature_pin: str
    key_attributes: str
    max_pin_lengths: str
    pin_retry_counter: str
    signature_counter: str
    kdf_setting: str
    uif_sign: str
    uif_decrypt: str
    uif_auth: str
    card_signature_key: str
    card_signature_key_creation: str
    card_encryption_key: str
    card_encryption_key_creation: str
    card_authentication_key: str
    card_authentication_key_creation: str
    primary_key: GPG_Key
    subkeys: dict[str, GPG_Key]


def command_runner(command_args: list[str]):
    """Wrapper for GPG commands"""
    if not (gpg := which("gpg")):
        raise RuntimeError("No GPG binary detected, unable to continue")

    command_args = [gpg] + command_args

    return run(command_args, capture_output=True, text=True).stdout  # nosec B603


def get_key_info_from_shell(primary_key: str = "") -> str:
    """Wrapper for getting the long string from the CLI"""
    command_args = ["-K", "--with-keygrip", "--with-subkey-fingerprint"]

    if primary_key:
        command_args.append(primary_key)

    return command_runner(command_args)


def get_gpg_keys(primary_key: str = "") -> list[GPG_Key]:
    """Fetches key info from the shell of either all private keys or the one specified as the primary key"""
    raw_string = get_key_info_from_shell(primary_key)

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


def get_signing_keys(
    key_list: list[GPG_Key] = [], primary_key: str = ""
) -> list[GPG_Key]:
    """Simple wrapper to get GPG signing keys, will fetch keys if no list is supplied"""
    if key_list == []:
        key_list = get_gpg_keys(primary_key)

    return get_keys_by_attr(key_list, "capability", "S")


def get_card_info():
    """Upcoming feature to implement getting the GPG info from a smart card, like a yubikey"""
    raise NotImplementedError("Upcoming feature")
