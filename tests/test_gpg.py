from nixtools import get_gpg_keys
from plumbum import local
from icecream import ic

# Sample key generated and used `gpg -K --with-keygrip --with-subkey-fingerprint`
TEST_KEY_OUTPUT = """
pub   ed25519 2025-09-22 [SC] [expires: 2030-09-21]
      603A72CD92F84EAA35127FB2D1724E537A0844E2
      Keygrip = 5643B43609004D57AF91CCF1FE78E14E166F52DC
uid           [ultimate] Test (Key generated purely for testing purposes) <test@pytest>
sub   cv25519 2025-09-22 [E] [expires: 2030-09-21]
      31F5A7299414BD57611F2A2A28737947AD89864B
      Keygrip = 772EDDBB1AB8A97872AFF4C4F092BD5239692EF7
sub   rsa2048 2025-09-22 [SEA] [expires: 2026-09-22]
      02FA8E12ECFFFA384131F777C39F59AAF4EF1469
      Keygrip = 57A109CD953DEF332E83ECAFD45CA3F3BF355714
sub   nistp384 2025-09-22 [SA]
      2C7B06B7C632DC195ADE1394949536148C87FE64
      Keygrip = 4C3DC92CA8B036CA6CB39837BBBF6124166D5A83
"""


def test_get_gpg_keys(monkeypatch):
    """"""

    def mocked_gpg_cmd(cmd_name):
        return TEST_KEY_OUTPUT

    monkeypatch.setattr(local, "__getitem__", mocked_gpg_cmd)

    test_key = get_gpg_keys()
    ic(test_key)
    assert isinstance(test_key, list)

    print(test_key)
