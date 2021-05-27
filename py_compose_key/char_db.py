import importlib.resources
from typing import Union, List

import pygtrie
import json


class CharDB:
    NOT_FOUND = 0
    POTENTIAL_MATCH = 1
    MATCH_FOUND = 2

    def __init__(self, trie: pygtrie.CharTrie):
        self.trie = trie

    @classmethod
    def create(cls):
        trie = pygtrie.CharTrie()

        f = importlib.resources.open_text("py_compose_key", "compose_mappings.json", encoding="utf-8")
        # print("type(", type(f))
        # with open("compose_mappings.json", encoding="utf-8") as f:
        #     data = json.load(f)
        data = json.load(f)
        for el in data:
            input_chars, resulting_char = el
            trie[input_chars] = resulting_char

        return cls(trie)

    def lookup(self, chars) -> Union[int, str]:
        result = self.trie.has_node(chars)
        if result == pygtrie.Trie.HAS_SUBTRIE:
            return self.POTENTIAL_MATCH
        elif result == pygtrie.Trie.HAS_VALUE:
            return self.MATCH_FOUND
        else:
            return self.NOT_FOUND

    def get_composed_chars(self, chars) -> str:
        assert self.lookup(chars) == self.MATCH_FOUND
        
        res = self.trie[chars]
        return res

if __name__ == "__main__":
    CharDB.create()