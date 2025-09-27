"""
TextFSM - I only parse the result to dictionaries, so I'm updating the incomplete upstream info to match my need
"""
from textfsm import TextFSM as _TextFSM

class TextFSM(_TextFSM):
    def ParseTextToDicts(self, text: str, eof: bool = True) -> dict[str, str]: ...
