import json
import re

filename = "ext/xorg-proto-x11proto/keysymdef.h"

regexes = [
    re.compile(r"^\#define XK_([a-zA-Z_0-9]+)\s+0x([0-9a-f]+)\s*\/\* U+([0-9A-F]{4,6}) (.*) \*\/\s*$"),
    re.compile(r"^\#define XK_([a-zA-Z_0-9]+)\s+0x([0-9a-f]+)\s*\/\*\(U+([0-9A-F]{4,6}) (.*)\)\*\/\s*$"),
    re.compile(r"^\#define XK_([a-zA-Z_0-9]+)\s+0x([0-9a-f]+)\s*(\/\*\s*(.*)\s*\*\/)?\s*$"),
]

keysym_to_unicode = {}

with open(filename) as f:
    # print("chr(", chr(0x1000174))

    for line in f:
        # print("line", line.strip())
        stripped_line = line.strip()
        for regex in regexes:
            m = regex.match(stripped_line)
            if m is not None:
                key, hex_str = m.groups()[:2]
                if key in ['VoidSymbol']:
                    continue

                # print("m", m.groups())

                unicode_codepoint = None

                # https://www.cl.cam.ac.uk/~mgk25/ucs/keysyms.pdf
                int_value = int(hex_str, 16)
                if 0x0020 <= int_value <= 0x007E or 0x00A0 <= int_value <= 0x00FF:
                    unicode_codepoint = int_value
                elif 0x01000100 <= int_value <= 0x0110FFFF:
                    unicode_codepoint = int_value - 0x01000000
                else:
                    description = m.group(4)
                    if description is not None:
                        splitted = description.split(" ")
                        if splitted[0].startswith("U+"):
                            unicode_codepoint = int(splitted[0][2:], 16)
                            # print("SKIP", m.group(4))
                        elif splitted[0].startswith("(U+"):
                            unicode_codepoint = int(splitted[0][3:], 16)
                        # else:
                        #     continue
                    if unicode_codepoint is None:
                        print("SKIP", m.groups())
                        continue

                    # continue
                    # continue
                # #x01000100

                # print("int(hex_str, 16)", )
                # print("m", int(hex_str, 16), chr(unicode_codepoint))

                # print("key", key, chr(unicode_codepoint))
                keysym_to_unicode[key] = chr(unicode_codepoint)

    ###
    ###

    result_mapping_list = []

    with open('ext/xorg-libX11/nls/en_US.UTF-8/Compose.pre', encoding='utf-8') as f:
        for line in f:
            stripped_line = line.strip()
            if len(stripped_line) == 0:
                continue
            if stripped_line.startswith(("XCOMM", "/*", "*", " *", "*/")):
                continue
            # print("line", line.strip())
            parts = stripped_line.split(":", maxsplit=1)
            # print("parts", len(parts), parts)
            assert len(parts) == 2

            # https://github.com/samhocevar/wincompose/blob/d73c809cbcf62db90dff28856c231161f5ecc6a2/src/wincompose/sequences/SequenceTree.cs#L80
            regex = r'^\s*(<:>|<[^:]*>\s*)*:\s*("(\\"|\\.|[^"])*"|[A-Za-z0-9_]*)[^#]*#?\s*(.*)'
            m = re.compile(regex).match(stripped_line)
            # print("m", m)
            sequence = m.group(1).strip()
            # print("sequence", sequence)
            regex2 = r"(?:^\s*<|>\s*<|>\s*$)"
            m2 = re.compile(regex2).split(sequence)
            # print("m2", list(el for el in m2 if len(el) > 0))
            clean_sequence = list(el for el in m2 if len(el) > 0)
            # print("m", m.group(3))

            resulting_char = m.group(3)
            if clean_sequence[0] == "Multi_key":
                # print("seq", clean_sequence, resulting_char)

                for el in clean_sequence:
                    if el.startswith("dead_"):
                        break
                    if el.startswith("KP_"):
                        break
                else:
                    def ishex(el):
                        try:
                            int(el, 16)
                            return True
                        except ValueError:
                            return False

                    success = True
                    input_sequence = []

                    for el in clean_sequence[1:]:
                        if len(el) == 5 and el[0] == "U" and ishex(el[1:]):
                            res = chr(int(el[1:], 16))
                        elif len(el) == 6 and el[0] == "U" and ishex(el[1:]):
                            res = chr(int(el[1:], 16))
                        else:
                            try:
                                res = keysym_to_unicode[el]
                            except KeyError as e:
                                print("NOT FOUND", el)
                                success = False
                                break
                        input_sequence.append(res)

                    if success:
                        # print("II", resulting_char, "<--", clean_sequence)
                        # print("NN", input_sequence)
                        result_mapping_list.append( (input_sequence, resulting_char) )

    print("result", len(result_mapping_list))
    for line in result_mapping_list:
        print("line", line)

    with open("py_compose_key/compose_mappings.json", "w", encoding="utf-8") as f:
        json.dump(result_mapping_list, fp=f, ensure_ascii=True)