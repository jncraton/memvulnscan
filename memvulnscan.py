import subprocess
import argparse
import re

parser = argparse.ArgumentParser(description=""" 
Scans process memory using specified parameters. This is useful for
vulnerability scanning.

The default parameters will search for database credentials in the form of
SQL connection strings.
""")

parser.add_argument('process',  help='Name of executable to scan')
parser.add_argument('--start',  default="'", help='Start of string to match')
parser.add_argument('--end',  default="'", help='End of string to match')
parser.add_argument('--contains',  default="pwd=", help='String that must be included in matches')
parser.add_argument('--maxlen',  default="200", help='Max length of matched string')
parser.add_argument('--encoding', default="utf16", help='Encoding of the string')

args = parser.parse_args()

def dump():
    """ Dump process memory using procdump """

    subprocess.call("procdump -o -ma \"%s\" mem" % args.process)

def encode(text):
    """ Encodes text using the specified encoding and removes byte order mark """
    text = text.encode(args.encoding)
    
    if args.encoding == 'utf16':
        # Remove BOM
        text = text[2:]
        
    return text

def scan():
    """ Scans memory dump for matching strings """
    
    with open('mem.dmp', 'rb') as dump_file:
        dump = dump_file.read()
        
        byte_length = 2 if args.encoding == 'utf16' else 1

        # Loop through each matching start string
        for m in re.finditer(encode(args.start), dump):
            end = dump.find(encode(args.end), m.start() + byte_length) + byte_length
             
            length = end - m.start()
             
            if length < int(args.maxlen):
                match = dump[m.start():end]
                
                try:
                    match = match.decode(args.encoding)
                except UnicodeDecodeError:
                    continue
                    
                match = match.lower()
                match = match.encode('utf8')
                
                if args.contains.lower() in match or not args.contains:
                    print match

if __name__ == '__main__':
    dump()
    scan()