from ast import literal_eval
from base64 import b64encode
from contextlib import suppress
from os import system
from warnings import catch_warnings, simplefilter

# From the Flask-Unsign repo.
def parse(line):
    with suppress(SyntaxError, ValueError):
        with catch_warnings():
            simplefilter('ignore')

            if isinstance(line, bytes):
                line = line.decode()

            return literal_eval((line.strip() or '').strip())

    return line.strip()

out = open("transformed.txt", "a")
entries = {}

with open('input.txt', 'r') as f:
    for line in f.readlines():
        line = b64encode(parse(line).encode('utf-8')).decode('utf-8')
        if entries.get(line):
            continue

        out.write(line + "\n")
        entries[line] = True

out.close()