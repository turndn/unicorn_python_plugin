#! /usr/env/bin python
import re


def main():
    re_code = re.compile('^[0-9a-f][0-9a-f]$')
    with open('dump_w_mnemonic.txt') as f:
        while True:
            s = f.readline()
            if not s:
                break
            s = list(filter(lambda x: x, s.split(' ')))
            addr = s[0]
            codes = s[1:]
            formatted_codes = ""
            mnemonic = ""
            for h in codes:
                if re_code.match(h):
                    formatted_codes += '\\x{}'.format(h.strip())
                else:
                    mnemonic += '{} '.format(h.strip())
            print("0x{} '{}',\t# {}".format(addr, formatted_codes, mnemonic))


if __name__ == '__main__':
    main()
