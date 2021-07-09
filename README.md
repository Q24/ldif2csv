## Converting LDIF/LDAP data into a CSV file

### LDIF to CSV

Based on https://github.com/tachang/ldif2csv.

Changes are:
- python3 compatibility;
- merging of multiple values into one column;
- option to specify the columns to use.

Specifying the columns writes the columns in the specified order. If no columns are specified, the input file is scanned to fetch the column names. 

### Usage

Running `python3 ldif2csv.py` should give you the usage text.
```
usage: ldif2csv.py [options] 

-o <filename>   : File to write output. By default this is set to sys.stdout
-l <filename>   : File to write logging output. By default there is no logging.
-f <char>       : Character to separate the fields by. By default this is a semicolon. i.e. -f ";"
-m <char>       : Character to delimit the multi values text by. By default this is a comma. i.e. -m ","
-d <char>       : Character to delimit the text value by. By default this is a double quote. i.e. -d """
-H <char>       : List of comma separated field names.
```

Here are some common command lines that I use (assuming you have a test.ldif):

Outputs the CSV straight to standard output:

```
python3 ldif2csv.py test.ldif
```

Outputs CSV to standard output with commas as the delimiter:

```
python3 ldif2csv.py -f "," test.ldif
```

Outputs CSV to standard output with pipes as the delimiter and text surrounded by carrots:

```
python3 ldif2csv.py -f "|" -d "^" test.ldif
```

Adding headers that have no value is allowed:

```
python3 ldif2csv.py -H mail,dn,foo test.ldif

"mail";"dn";"foo"
"aabl@m.gov.mu";"uid=aab, cn=m.gov.mu";""
"aabl@m.gov.mu";"uid=owehgwoqeghwqeghweghqwe, cn=m.gov.mu";""
```
