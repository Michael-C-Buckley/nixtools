from nixtools import GPG_Key, get_gpg_keys

# Sample key generated and used `gpg -K --with-keygrip --with-subkey-fingerprint`
TEST_KEY_OUTPUT = """
sec   ed25519 2025-09-22 [SC] [expires: 2030-09-21]
      603A72CD92F84EAA35127FB2D1724E537A0844E2
      Keygrip = 5643B43609004D57AF91CCF1FE78E14E166F52DC
uid           [ultimate] Test (Key generated purely for testing purposes) <test@pytest>
ssb   cv25519 2025-09-22 [E] [expires: 2030-09-21]
      31F5A7299414BD57611F2A2A28737947AD89864B
      Keygrip = 772EDDBB1AB8A97872AFF4C4F092BD5239692EF7
ssb   rsa2048 2025-09-22 [SEA] [expires: 2026-09-22]
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
        subkey="2C7B06B7C632DC195ADE1394949536148C87FE64",
    ),
]


def test_get_gpg_keys(monkeypatch):
    """"""

    def mocked_gpg_cmd(primary_keys=""):
        return TEST_KEY_OUTPUT

    monkeypatch.setattr("nixtools.gpg.get_info_from_shell", mocked_gpg_cmd)

    test_key = get_gpg_keys()

    # They appear in the same order as listed above and should match
    for i, key in enumerate(test_key):
        assert key == TEST_STRUCT[i]
