from nixtools import GPG_Key, get_gpg_keys, get_keys_by_attr, get_signing_keys
from nixtools.gpg import get_key_info_from_shell
from pytest import raises

# Sample key generated and used `gpg -K --with-keygrip --with-subkey-fingerprint`
TEST_KEY_OUTPUT = """
sec#  ed25519 2025-09-22 [SC] [expires: 2030-09-21]
      603A72CD92F84EAA35127FB2D1724E537A0844E2
      Keygrip = 5643B43609004D57AF91CCF1FE78E14E166F52DC
uid           [ultimate] Test (Key generated purely for testing purposes) <test@pytest>
ssb   cv25519 2025-09-22 [E] [expires: 2030-09-21]
      31F5A7299414BD57611F2A2A28737947AD89864B
      Keygrip = 772EDDBB1AB8A97872AFF4C4F092BD5239692EF7
ssb>  rsa2048 2025-09-22 [SEA] [expires: 2026-09-22]
      02FA8E12ECFFFA384131F777C39F59AAF4EF1469
      Keygrip = 57A109CD953DEF332E83ECAFD45CA3F3BF355714
ssb   nistp384 2025-09-22 [SA]
      2C7B06B7C632DC195ADE1394949536148C87FE64
      Keygrip = 4C3DC92CA8B036CA6CB39837BBBF6124166D5A83
"""

# The above structure manually parsed into expected and correct format
TEST_STRUCT = [
    GPG_Key(
        algorithm="ed25519",
        capability="SC",
        card_no="",
        creation="2025-09-22",
        expiration="2030-09-21",
        keygrip="5643B43609004D57AF91CCF1FE78E14E166F52DC",
        primary_key="603A72CD92F84EAA35127FB2D1724E537A0844E2",
        presence="#",
        subkey="",
    ),
    GPG_Key(
        algorithm="cv25519",
        capability="E",
        card_no="",
        creation="2025-09-22",
        expiration="2030-09-21",
        keygrip="772EDDBB1AB8A97872AFF4C4F092BD5239692EF7",
        primary_key="603A72CD92F84EAA35127FB2D1724E537A0844E2",
        presence=" ",
        subkey="31F5A7299414BD57611F2A2A28737947AD89864B",
    ),
    GPG_Key(
        algorithm="rsa2048",
        capability="SEA",
        card_no="",
        creation="2025-09-22",
        expiration="2026-09-22",
        keygrip="57A109CD953DEF332E83ECAFD45CA3F3BF355714",
        primary_key="603A72CD92F84EAA35127FB2D1724E537A0844E2",
        presence=">",
        subkey="02FA8E12ECFFFA384131F777C39F59AAF4EF1469",
    ),
    GPG_Key(
        algorithm="nistp384",
        capability="SA",
        card_no="",
        creation="2025-09-22",
        expiration="",
        keygrip="4C3DC92CA8B036CA6CB39837BBBF6124166D5A83",
        primary_key="603A72CD92F84EAA35127FB2D1724E537A0844E2",
        presence=" ",
        subkey="2C7B06B7C632DC195ADE1394949536148C87FE64",
    ),
]


def create_key_list(indices_as_str: str = "") -> list[GPG_Key]:
    """Helper function to create a list of test keys"""
    return [TEST_STRUCT[int(x)] for x in indices_as_str]


def test_gpg_not_detected(monkeypatch):
    def mock_shutil_which(binary_name):
        return None

    monkeypatch.setattr("nixtools.gpg.which", mock_shutil_which)

    with raises(RuntimeError) as output:
        get_key_info_from_shell()

    assert "No GPG binary detected" in str(output.value)
    assert "unable to continue" in str(output.value)


def test_get_gpg_keys(monkeypatch):
    def mocked_gpg_cmd(primary_keys=""):
        return TEST_KEY_OUTPUT

    monkeypatch.setattr("nixtools.gpg.get_key_info_from_shell", mocked_gpg_cmd)

    test_key = get_gpg_keys()

    # They appear in the same order as listed above and should match
    for i, key in enumerate(test_key):
        assert key == TEST_STRUCT[i]


def test_get_keys_by_attr():
    """Simple logic check to test validatity of the mechanisms"""

    SA_keys = get_keys_by_attr(TEST_STRUCT, "capability", "SA")
    assert SA_keys == create_key_list("23")

    E_keys = get_keys_by_attr(TEST_STRUCT, "capability", "E")
    assert E_keys == create_key_list("12")

    specific_key = get_keys_by_attr(
        TEST_STRUCT, "subkey", "31F5A7299414BD57611F2A2A28737947AD89864B"
    )
    assert specific_key == create_key_list("1")

    all_keys = get_keys_by_attr(TEST_STRUCT, "creation", "2025-09-22")
    assert all_keys == TEST_STRUCT


def test_get_signing_keys(monkeypatch):
    # Test logic with supplied keys
    signing_keys = create_key_list("023")
    assert get_signing_keys(TEST_STRUCT) == signing_keys

    # Test logic without supplied keys
    def mocked_gpg_cmd(primary_keys=""):
        return TEST_KEY_OUTPUT

    monkeypatch.setattr("nixtools.gpg.get_key_info_from_shell", mocked_gpg_cmd)

    assert get_signing_keys() == signing_keys
