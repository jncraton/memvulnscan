# memvulnscan

Scans Windows process memory using specified parameters. This is useful for
vulnerability scanning.

The default parameters will search for database credentials in the form of
SQL connection strings.

# Usage

    usage: memvulnscan.py [-h] [--start START] [--end END] [--contains CONTAINS]
                          [--maxlen MAXLEN] [--encoding ENCODING]
                          process

    positional arguments:
      process              Name of executable to scan

    optional arguments:
      -h, --help           show this help message and exit
      --start START        Start of string to match
      --end END            End of string to match
      --contains CONTAINS  String that must be included in matches
      --maxlen MAXLEN      Max length of matched string
      --encoding ENCODING  Encoding of the string