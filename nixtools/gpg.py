"""
GPG tools for obtaining info about GnuPG keys
"""

# Python Modules
from dataclasses import dataclass
from io import StringIO
from shutil import which
from re import split, match
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
class GPG_Card:
    primary_key: GPG_Key
    subkeys: list[dict[str, GPG_Key]]
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


def command_runner(command_args: list[str]) -> str:
    """Wrapper for GPG commands"""
    if not (gpg := which("gpg")):
        raise RuntimeError("No GPG binary detected, unable to continue")

    command_args.insert(0, gpg)

    return run(args=command_args, capture_output=True, text=True).stdout  # nosec B603


def get_key_info_from_shell(primary_key: str = "") -> str:
    """Wrapper for getting the long string from the CLI"""
    command_args: list[str] = ["-K", "--with-keygrip", "--with-subkey-fingerprint"]

    if primary_key:
        command_args.append(primary_key)

    return command_runner(command_args)


def get_gpg_keys(primary_key: str = "") -> list[GPG_Key]:
    """Fetches key info from the shell of either all private keys or the one specified as the primary key"""
    raw_string: str = get_key_info_from_shell(primary_key)

    with open(file="nixtools/textfsm/gpg-info.txt") as f:
        result: dict[str, str] = TextFSM(f).ParseTextToDicts(raw_string)

    return [GPG_Key(**raw_key) for raw_key in result]  # pyright: ignore[reportCallIssue]


def get_keys_by_attr(input: list[GPG_Key], attr: str, filter: str) -> list[GPG_Key]:  # pyright: ignore[reportRedeclaration]
    """Filters keys to the desired attribute and value"""

    if attr == "capability":
        filter: str = filter.upper()

    def exact_match(elem: GPG_Key) -> str:
        """Match the entire term exactly"""
        return getattr(elem, attr) == filter  # pyright: ignore[reportAny]

    def fuzzy_match(elem: GPG_Key) -> str:
        """Match each item individually, like capabilities"""
        return set(filter) <= set(getattr(elem, attr))  # pyright: ignore[reportReturnType, reportAny]

    # Additional Behaviors can be added over time
    behavior = {
        "capability": fuzzy_match,
    }.get(attr, exact_match)

    return [x for x in input if behavior(x)]


def get_signing_keys(
    key_list: list[GPG_Key] | None = None,  # pyright: ignore[reportRedeclaration]
    primary_key: str = "",
) -> list[GPG_Key]:
    """Simple wrapper to get GPG signing keys, will fetch keys if no list is supplied"""
    if key_list is None:
        key_list: list[GPG_Key] = get_gpg_keys(primary_key)

    return get_keys_by_attr(key_list, "capability", "S")


def get_card_info() -> GPG_Card:
    """Get the GPG info from a smart card, like a yubikey"""
    card_status: list[str] = split(
        r"\nsec", command_runner(command_args=["--card-status"])
    )

    with open(file="nixtools/textfsm/gpg-card-header.txt") as f:
        header_info: dict[str, str] = TextFSM(template=f).ParseTextToDicts(
            text=card_status[0]
        )

    # Load the contents into a buffer as parsers cannot be reused and to avoid IO
    with open(file="nixtools/textfsm/gpg-card-key.txt") as f:
        buffer: StringIO = StringIO(initial_value=f.read())

    # Manipulate the strings, then feed a template to reduce template logic
    key_info: list[str] = card_status[1].replace("\n", "").split(sep="ssb")

    primary_key: GPG_Key = TextFSM(buffer).ParseTextToDicts(key_info.pop(0))  # pyright: ignore[reportAssignmentType]

    subkeys: list[dict[str, GPG_Key]] = []
    for key in key_info:
        subkeys.append(TextFSM(buffer).ParseTextToDicts(key))  # pyright: ignore[reportArgumentType]

    return GPG_Card(primary_key=primary_key, subkeys=subkeys, **(header_info[0]))  # pyright: ignore[reportCallIssue, reportArgumentType]


def get_best_key(keys: list[GPG_Key]) -> GPG_Key:
    """Simple decider for choosing an algorithm then the best key in it"""
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

    def find_longest_keys(keys: list[GPG_Key], algo: str) -> list[GPG_Key]:
        max_len: int = max(int(key.algorithm.replace(algo, "")) for key in nist_keys)
        return [x for x in nist_keys if x.algorithm == f"{algo}{max_len}"]

    # The list will be collapsed to equal value keys, just return the first available one
    if ed_keys:
        return ed_keys[0]
    if nist_keys:
        return find_longest_keys(nist_keys, "nistp")[0]
    if rsa_keys:
        return find_longest_keys(rsa_keys, "rsa")[0]
