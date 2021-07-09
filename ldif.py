"""
ldif - generate and parse LDIF data (see RFC 2849)

See http://python-ldap.sourceforge.net for details.

$Id: ldif.py,v 1.47 2008/03/10 08:34:29 stroeder Exp $

Python compability note:
Tested with Python 2.0+, but should work with Python 1.5.2+.
"""

__version__ = '0.5.5'

__all__ = [
    # constants
    'ldif_pattern',
    # functions
    # 'AttrTypeandValueLDIF',
    'ParseLDIF',
    # classes
    'LDIFParser',
    'LDIFRecordList',
    # 'LDIFCopy',
]

import base64
import re

# import types
# import urllib

# import urlparse

# try:
#   from cStringIO import StringIO
# except ImportError:
#   from StringIO import StringIO

attrtype_pattern = r'[\w;.]+(;[\w_-]+)*'
attrvalue_pattern = r'(([^,]|\\,)+|".*?")'
rdn_pattern = attrtype_pattern + r'[ ]*=[ ]*' + attrvalue_pattern
dn_pattern = rdn_pattern + r'([ ]*,[ ]*' + rdn_pattern + r')*[ ]*'
dn_regex = re.compile('^%s$' % dn_pattern)

ldif_pattern = '^((dn(:|::) %(dn_pattern)s)|(%(attrtype_pattern)s(:|::) .*)$)+' % vars()

MOD_OP_INTEGER = {
    'add': 0, 'delete': 1, 'replace': 2
}

MOD_OP_STR = {
    0: 'add', 1: 'delete', 2: 'replace'
}

CHANGE_TYPES = ['add', 'delete', 'modify', 'modrdn']
valid_changetype_dict = {}
for c in CHANGE_TYPES:
    valid_changetype_dict[c] = None

SAFE_STRING_PATTERN = '(^(\000|\n|\r| |:|<)|[\000\n\r\200-\377]+|[ ]+$)'
safe_string_re = re.compile(SAFE_STRING_PATTERN)


def is_dn(s):
    """
    returns 1 if s is a LDAP DN
    """
    if s == '':
        return 1
    rm = dn_regex.match(s)
    return rm is not None and rm.group(0) == s


def needs_base64(s):
    """
    returns 1 if s has to be base-64 encoded because of special chars
    """
    return not safe_string_re.search(s) is None


def list_dict(list):
    """
    return a dictionary with all items of l being the keys of the dictionary
    """
    return dict([(i, None) for i in list])


class LDIFParser:
    """
    Base class for a LDIF parser. Applications should sub-class this
    class and override method handle() to implement something meaningful.

    Public class attributes:
    records_read
          Counter for records processed so far
    """

    def _stripLineSep(self, s):
        """
        Strip trailing line separators from s, but no other whitespaces
        """
        if s[-2:] == '\r\n':
            return s[:-2]
        elif s[-1:] == '\n':
            return s[:-1]
        else:
            return s

    def __init__(
            self,
            input_file,
            ignored_attr_types=None,
            max_entries=0,
            process_url_schemes=None,
            line_sep='\n'
    ):
        """
        Parameters:
        input_file
            File-object to read the LDIF input from
        ignored_attr_types
            Attributes with these attribute type names will be ignored.
        max_entries
            If non-zero specifies the maximum number of entries to be
            read from f.
        process_url_schemes
            List containing strings with URLs schemes to process with urllib.
            An empty list turns off all URL processing and the attribute
            is ignored completely.
        line_sep
            String used as line separator
        """
        self._input_file = input_file
        self._max_entries = max_entries
        self._process_url_schemes = list_dict(
            [s.lower() for s in (process_url_schemes or [])])
        self._ignored_attr_types = list_dict(
            [a.lower() for a in (ignored_attr_types or [])])
        self._line_sep = line_sep
        self.records_read = 0

    def handle(self, dn, entry):
        """
        Process a single content LDIF record. This method should be
        implemented by applications using LDIFParser.
        """

    def _unfoldLDIFLine(self):
        """
        Unfold several folded lines with trailing space into one line
        """
        self._line = self._line.decode('utf-8')
        unfolded_lines = [self._stripLineSep(self._line)]
        self._line = self._input_file.readline()
        while self._line and self._line[0] == ' ':
            unfolded_lines.append(self._stripLineSep(self._line[1:]))
            self._line = self._input_file.readline()

        return ''.join(unfolded_lines)

    def _parseAttrTypeandValue(self):
        """
        Parse a single attribute type and value pair from one or
        more lines of LDIF data
        """
        # Reading new attribute line
        unfolded_line = self._unfoldLDIFLine()
        # Ignore comments which can also be folded
        while unfolded_line and unfolded_line[0] == '#':
            unfolded_line = self._unfoldLDIFLine()
        if not unfolded_line or unfolded_line == '\n' or unfolded_line == '\r\n':
            return None, None
        try:
            colon_pos = unfolded_line.index(':')
        except ValueError:
            # Treat malformed lines without colon as non-existent
            return None, None
        attr_type = unfolded_line[0:colon_pos]
        # if needed attribute value is BASE64 decoded
        value_spec = unfolded_line[colon_pos:colon_pos + 2]
        if value_spec == '::':
            # attribute value needs base64-decoding
            attr_value = base64.decodestring(
                unfolded_line[colon_pos + 2:])

            # attr_value = unfolded_line[colon_pos+2:]
        elif value_spec == ':<':
            # fetch attribute value from URL
            # url = unfolded_line[colon_pos + 2:].strip()
            attr_value = None
            # if self._process_url_schemes:
            #   u = urlparse.urlparse(url)
            #   if self._process_url_schemes.has_key(u[0]):
            #     attr_value = urllib.urlopen(url).read()
        elif value_spec == ':\r\n' or value_spec == '\n':
            attr_value = ''
        else:
            attr_value = unfolded_line[colon_pos + 2:].lstrip()
        return attr_type, attr_value

    def parse(self):
        """
        Continuously read and parse LDIF records
        """
        self._line = self._input_file.readline()

        while self._line and \
                (
                        not self._max_entries or self.records_read < self._max_entries):

            # Reset record
            dn = None
            changetype = None
            entry = {}

            attr_type, attr_value = self._parseAttrTypeandValue()

            while attr_type is not None and attr_value is not None:
                if attr_type == 'dn':
                    # attr type and value pair was DN of LDIF record
                    if dn is not None:
                        raise ValueError('Two lines starting with dn: in one record.')
                    if not is_dn(attr_value):
                        raise ValueError(
                            'No valid string-representation of distinguished name %s.' % (repr(attr_value)))
                    dn = attr_value
                elif attr_type == 'changetype':
                    # attr type and value pair was DN of LDIF record
                    if dn is None:
                        raise ValueError('Read changetype: before getting valid dn: line.')
                    if changetype is not None:
                        raise ValueError('Two lines starting with changetype: in one record.')
                    if attr_value not in valid_changetype_dict:
                        raise ValueError('changetype value %s is invalid.' % (repr(attr_value)))
                    changetype = attr_value
                elif attr_value is not None and not attr_type.lower() in self._ignored_attr_types:
                    # Add the attribute to the entry if not ignored attribute
                    if attr_type in entry:
                        entry[attr_type].append(attr_value)
                    else:
                        entry[attr_type] = [attr_value]

                # Read the next line within an entry
                attr_type, attr_value = self._parseAttrTypeandValue()

            if entry:
                # append entry to result list
                self.handle(dn, entry)
                self.records_read = self.records_read + 1


class LDIFRecordList(LDIFParser):
    """
    Collect all records of LDIF input into a single list.
    of 2-tuples (dn,entry). It can be a memory hog!
    """

    def __init__(
            self,
            input_file,
            ignored_attr_types=None, max_entries=0, process_url_schemes=None
    ):
        """
        See LDIFParser.__init__()

        Additional Parameters:
        all_records
            List instance for storing parsed records
        """
        LDIFParser.__init__(self, input_file, ignored_attr_types,
                            max_entries,
                            process_url_schemes)
        self.all_records = []

    def handle(self, dn, entry):
        """
        Append single record to dictionary of all records.
        """
        self.all_records.append((dn, entry))


def ParseLDIF(f, ignore_attrs=None, maxentries=0):
    """
    Parse LDIF records read from file.
    This is a compability function. Use is deprecated!
    """
    ldif_parser = LDIFRecordList(
        f, ignored_attr_types=ignore_attrs, max_entries=maxentries,
        process_url_schemes=0
    )
    ldif_parser.parse()
    return ldif_parser.all_records
