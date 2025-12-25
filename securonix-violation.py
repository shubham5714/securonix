import io
import json
from collections.abc import Callable
import time
from datetime import datetime, timedelta, timezone
from itertools import takewhile
from typing import Any
from zipfile import ZipFile
import dateparser
import urllib3
from dateutil.parser import parse

import re
import ssl
import requests
from requests.adapters import HTTPAdapter
import sys
import traceback
# Supabase imports
try:
    from supabase import create_client, Client
    SUPABASE_AVAILABLE = True
except ImportError:
    SUPABASE_AVAILABLE = False
    print("Warning: Supabase client not available. Install with: pip install supabase")

# Supabase configuration
SUPABASE_URL = os.getenv('SUPABASE_URL', 'https://zhhsijigoupqroztdrdy.supabase.co')
SUPABASE_ANON_KEY = os.getenv('SUPABASE_ANON_KEY', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InpoaHNpamlnb3VwcXJvenRkcmR5Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTcwNjgyODksImV4cCI6MjA3MjY0NDI4OX0.Mxq7DYbKV9OXHS7eE1YpdQ4F8Htld0Vt6FwlfOpX8kQ')


_INTEGRATION_CONTEXT = {}

IS_PY3 = sys.version_info[0] == 3
PY_VER_MINOR = sys.version_info[1]

# Disable insecure warnings
urllib3.disable_warnings()

STRING_TYPES = (str, bytes)
STRING_OBJ_TYPES = (str,)

# These parameters will be used for retry mechanism logging
TOTAL_RETRY_COUNT = 0

FULL_URL = None

# Valid Entity Type for Whitelists
VALID_ENTITY_TYPE = ["Users", "Activityaccount", "Resources", "Activityip"]

# Valid Whitelist Types
VALID_WHITELIST_TYPE = ["Global", "Attribute"]

# Special characters for spotter query
SPOTTER_SPECIAL_CHARACTERS = ["\\", "*", "?"]

# Markdown characters.
MARKDOWN_CHARS = r"\*_{}[]()#+-!"

# Mapping of user input of mirroring direction to XSOAR.
MIRROR_DIRECTION = {"None": None, "Incoming": "In", "Outgoing": "Out", "Incoming And Outgoing": "Both"}

# If any comment is added to the incident, then this will be the action we'll get through incident activity history
# command.
COMMENT_ACTION = "COMMENTS_ADDED"

# If any file is attached to the incident, then this will be the action we'll get through incident activity history
# command.
ATTACHMENT_ACTION = "ATTACHED_FILE"

# This will store the state mapping of XSOAR states with Securonix states.
XSOAR_TO_SECURONIX_STATE_MAPPING: dict = {}

# Policy types for which retry should have end time to the current time.
POLICY_TYPES_TO_RETRY = ["DIRECTIVE", "LAND SPEED", "TIER2", "BEACONING"]

MESSAGE = {
    "INVALID_MAX_VALUE": "Please provide a value for 'max' between 1 and 10,000.",
}

def extract_time_range(solr_query: str):
    pattern = r'between\s+"([^"]+)"\s+"([^"]+)"'
    match = re.search(pattern, solr_query)
    if not match:
        return None, None
    
    from_time = match.group(1)
    to_time = match.group(2)
    
    return from_time, to_time

def stringEscapeMD(st, minimal_escaping=False, escape_multiline=False):
    """
       Escape any chars that might break a markdown string

       :type st: ``str``
       :param st: The string to be modified (required)

       :type minimal_escaping: ``bool``
       :param minimal_escaping: Whether replace all special characters or table format only (optional)

       :type escape_multiline: ``bool``
       :param escape_multiline: Whether convert line-ending characters (optional)

       :return: A modified string
       :rtype: ``str``
    """
    if escape_multiline:
        st = st.replace('\r\n', '<br>')  # Windows
        st = st.replace('\r', '<br>')  # old Mac
        st = st.replace('\n', '<br>')  # Unix

    if minimal_escaping:
        for c in ('|', '`'):
            st = st.replace(c, '\\' + c)
    else:
        st = "".join(["\\" + str(c) if c in MARKDOWN_CHARS else str(c) for c in st])

    return st

def reformat_outputs(text: str) -> str:
    """camelCase -> Camel Case, id -> ID
    Args:
        text: the text to transform
    Returns:
        A Demisto output standard string
    """
    if text.startswith("rg_"):
        return reformat_resource_groups_outputs(text)
    if text == "id":
        return "ID"
    if text in ["lanid", "u_lanid"]:
        return "LanID"
    if text == "jobId":
        return "JobID"
    if text == "eventId":
        return "EventID"
    if text in ["entityId", "entityid"]:
        return "EntityID"
    if text in ["tenantId", "tenantid"]:
        return "TenantID"
    if text == "incidentId":
        return "IncidentID"
    if text == "Datasourceid":
        return "DataSourceID"
    if text in ["employeeId", "employeeid", "u_employeeid"]:
        return "EmployeeID"
    if text == "violatorId":
        return "ViolatorID"
    if text == "threatname":
        return "ThreatName"
    if text == "generationtime":
        return "GenerationTime"
    if text == "generationtime_epoch":
        return "GenerationTime_Epoch"

    if text.startswith(("U_", "u_")):
        text = text[2:]
    return "".join(" " + char if char.isupper() else char.strip() for char in text).strip().title()


def remove_empty_elements(d):
    """
    Recursively remove empty lists, empty dicts, or None elements from a dictionary.
    :param d: Input dictionary.
    :type d: dict
    :return: Dictionary with all empty lists, and empty dictionaries removed.
    :rtype: dict
    """

    def empty(x):
        return x is None or x == {} or x == []

    if not isinstance(d, (dict, list)):
        return d
    elif isinstance(d, list):
        return [v for v in (remove_empty_elements(v) for v in d) if not empty(v)]
    else:
        return {k: v for k, v in ((k, remove_empty_elements(v)) for k, v in d.items()) if not empty(v)}


def formatCell(data, is_pretty=True, json_transform=None):
    """
       Convert a given object to md while decending multiple levels


       :type data: ``str`` or ``list`` or ``dict``
       :param data: The cell content (required)

       :type is_pretty: ``bool``
       :param is_pretty: Should cell content be prettified (default is True)

       :type json_transform: ``JsonTransformer``
       :param json_transform: The Json transform object to transform the data

       :return: The formatted cell content as a string
       :rtype: ``str``
    """
    if json_transform is None:
        json_transform = JsonTransformer(flatten=True)

    return json_transform.json_to_str(data, is_pretty)

def create_clickable_url(url, text=None):
    """
    Make the given url clickable when in markdown format by concatenating itself, with the proper brackets

    :type url: ``Union[List[str], str]``
    :param url: the url of interest or a list of urls

    :type text: ``Union[List[str], str, None]``
    :param text: the text of the url or a list of texts of urls.

    :return: Markdown format for clickable url
    :rtype: ``Union[List[str], str]``

    """
    if not url:
        return None
    elif isinstance(url, list):
        if isinstance(text, list):
            assert len(url) == len(text), 'The URL list and the text list must be the same length.'
            return ['[{}]({})'.format(text, item) for text, item in zip(text, url)]
        return ['[{}]({})'.format(item, item) for item in url]
    return '[{}]({})'.format(text or url, url)


def url_to_clickable_markdown(data, url_keys):
    """
    Turn the given urls fields in to clickable url, used for the markdown table.

    :type data: ``[Union[str, List[Any], Dict[str, Any]]]``
    :param data: a dictionary or a list containing data with some values that are urls

    :type url_keys: ``List[str]``
    :param url_keys: the keys of the url's wished to turn clickable

    :return: markdown format for clickable url
    :rtype: ``[Union[str, List[Any], Dict[str, Any]]]``
    """

    if isinstance(data, list):
        data = [url_to_clickable_markdown(item, url_keys) for item in data]

    elif isinstance(data, dict):
        data = {key: create_clickable_url(value) if key in url_keys else url_to_clickable_markdown(data[key], url_keys)
                for key, value in data.items()}

    return data


def string_escape_MD(data: Any):
    """
    Escape any chars that might break a markdown string.

    :type data: ``Any``
    :param data: The data to be modified (required).

    :return: A modified data.
    :rtype: ``str``
    """
    if isinstance(data, str):
        data = "".join(["\\" + str(c) if c in MARKDOWN_CHARS else str(c) for c in data])
    elif isinstance(data, list):
        new_data = []
        for sub_data in data:
            if isinstance(sub_data, str):
                sub_data = "".join(["\\" + str(c) if c in MARKDOWN_CHARS else str(c) for c in sub_data])
            new_data.append(sub_data)
        data = new_data

    return data

def parse_data_arr(data_arr: Any, fields_to_drop: list = [], fields_to_include: list = []):
    """Parse data as received from Securonix into Demisto's conventions
    Args:
        data_arr: a dictionary containing the data
        fields_to_drop: Fields to drop from the array of the data
        fields_to_include: Fields to include from the array of the data
    Returns:
        A Camel Cased dictionary with the relevant fields.
        readable: for the human readable
        outputs: for the entry context
    """
    if isinstance(data_arr, list):
        readable_arr, outputs_arr = [], []
        for data in data_arr:
            readable = {reformat_outputs(i): j for i, j in data.items() if i not in fields_to_drop}
            if fields_to_include:
                readable = {i: j for i, j in readable.items() if i in fields_to_include}
            readable_arr.append(readable)
            outputs_arr.append({k.replace(" ", ""): v for k, v in readable.copy().items()})
        return readable_arr, outputs_arr

    readable = {reformat_outputs(i): j for i, j in data_arr.items() if i not in fields_to_drop}
    if fields_to_include:
        readable = {i: j for i, j in readable.items() if i in fields_to_include}
    outputs = {k.replace(" ", ""): v for k, v in readable.copy().items()}

    return readable, outputs

def assign_params(keys_to_ignore=None, values_to_ignore=None, **kwargs):
    """Creates a dictionary from given kwargs without empty values.
    empty values are: None, '', [], {}, ()
`   Examples:
        >>> assign_params(a='1', b=True, c=None, d='')
        {'a': '1', 'b': True}

        >>> since_time = 'timestamp'
        >>> assign_params(values_to_ignore=(15, ), sinceTime=since_time, b=15)
        {'sinceTime': 'timestamp'}

        >>> item_id = '1236654'
        >>> assign_params(keys_to_ignore=['rnd'], ID=item_id, rnd=15)
        {'ID': '1236654'}

    :type keys_to_ignore: ``tuple`` or ``list``
    :param keys_to_ignore: Keys to ignore if exists

    :type values_to_ignore: ``tuple`` or ``list``
    :param values_to_ignore: Values to ignore if exists

    :type kwargs: ``kwargs``
    :param kwargs: kwargs to filter

    :return: dict without empty values
    :rtype: ``dict``

    """
    if values_to_ignore is None:
        values_to_ignore = (None, '', [], {}, ())
    if keys_to_ignore is None:
        keys_to_ignore = tuple()
    return {
        key: value for key, value in kwargs.items()
        if value not in values_to_ignore and key not in keys_to_ignore
    }

class ScheduledCommand:
    """
    ScheduledCommand configuration class
    Holds the scheduled command configuration for the command result - managing the way the command should be polled.

    :type command: ``str``
    :param command: The command that'll run after next_run_in_seconds has passed.

    :type next_run_in_seconds: ``int``
    :param next_run_in_seconds: How long to wait before executing the command.

    :type args: ``Optional[Dict[str, Any]]``
    :param args: Arguments to use when executing the command.

    :type timeout_in_seconds: ``Optional[int]``
    :param timeout_in_seconds: Number of seconds until the polling sequence will timeout.

    :type items_remaining: ``Optional[int]``
    :param items_remaining: Number of items that are remaining to be polled.

    :return: None
    :rtype: ``None``
    """
    VERSION_MISMATCH_ERROR = 'This command is not supported by this XSOAR server version. Please update your server ' \
                             'version to 6.2.0 or later.'

    def __init__(
        self,
        command,  # type: str
        next_run_in_seconds,  # type: int
        args=None,  # type: Optional[Dict[str, Any]]
        timeout_in_seconds=None,  # type: Optional[int]
        items_remaining=0,  # type: Optional[int]
    ):
        self.raise_error_if_not_supported()
        self._command = command
        if next_run_in_seconds < 10:
            demisto.info('ScheduledCommandConfiguration provided value for next_run_in_seconds: '
                         '{} is '.format(next_run_in_seconds) + 'too low - minimum interval is 10 seconds. '
                                                                'next_run_in_seconds was set to 10 seconds.')
            next_run_in_seconds = 10
        self._next_run = str(next_run_in_seconds)
        self._args = args
        self._timeout = str(timeout_in_seconds) if timeout_in_seconds else None
        self._items_remaining = items_remaining

    @staticmethod
    def raise_error_if_not_supported():
        return True

    @staticmethod
    def supports_polling():
        """
        Check if the integration supports polling (if server version is greater than 6.2.0).
        Returns: Boolean
        """
        return True

    def to_results(self):
        """
        Returns the result dictionary of the polling command
        """
        return assign_params(
            PollingCommand=self._command,
            NextRun=self._next_run,
            PollingArgs=self._args,
            Timeout=self._timeout,
            PollingItemsRemaining=self._items_remaining
        )

class JsonTransformer:
    """
    A class to transform a json to

    :type flatten: ``bool``
    :param flatten: Should we flatten the json using `flattenCell` (for BC)

    :type keys: ``Set[str]``
    :param keys: Set of keys to keep

    :type is_nested: ``bool``
    :param is_nested: If look for nested

    :type func: ``Callable``
    :param func: A function to parse the json

    :return: None
    :rtype: ``None``
    """

    def __init__(self, flatten=False, keys=None, is_nested=False, func=None):
        """
        Constructor for JsonTransformer

        :type flatten: ``bool``
        :param flatten:  Should we flatten the json using `flattenCell` (for BC)

        :type keys: ``Iterable[str]``
        :param keys: an iterable of relevant keys list from the json. Notice we save it as a set in the class

        :type is_nested: ``bool``
        :param is_nested: Whether to search in nested keys or not

        :type func: ``Callable``
        :param func: A function to parse the json
        """
        if keys is None:
            keys = []
        self.keys = set(keys)
        self.is_nested = is_nested
        self.func = func
        self.flatten = flatten

    def json_to_str(self, json_input, is_pretty=True):
        if self.func:
            return self.func(json_input)
        if isinstance(json_input, STRING_TYPES):
            return json_input
        if self.flatten:
            if not isinstance(json_input, dict):
                return flattenCell(json_input, is_pretty)
            return '\n'.join(
                [u'{key}: {val}'.format(key=k, val=flattenCell(v, is_pretty)) for k, v in json_input.items()])  # for BC

        str_lst = []
        prev_path = []  # type: ignore
        for path, key, val in self.json_to_path_generator(json_input):
            str_path = ''
            full_tabs = '\t' * len(path)
            if path != prev_path:  # need to construct tha `path` string only of it changed from the last one
                common_prefix_index = len(os.path.commonprefix((prev_path, path)))  # type: ignore
                path_suffix = path[common_prefix_index:]

                str_path_lst = []
                for i, p in enumerate(path_suffix):
                    is_list = isinstance(p, int)
                    tabs = (common_prefix_index + i) * '\t'
                    path_value = p if not is_list else '-'
                    delim = ':\n' if not is_list else ''
                    str_path_lst.append('{tabs}**{path_value}**{delim}'.format(tabs=tabs, path_value=path_value, delim=delim))
                str_path = ''.join(str_path_lst)
                prev_path = path
                if path and isinstance(path[-1], int):
                    # if it is a beginning of a list, there is only one tab left
                    full_tabs = '\t'

            str_lst.append(
                '{path}{tabs}***{key}***: {val}'.format(path=str_path, tabs=full_tabs, key=key, val=flattenCell(val, is_pretty)))

        return '\n'.join(str_lst)

    def json_to_path_generator(self, json_input, path=None):
        """
        :type json_input: ``list`` or ``dict``
        :param json_input: The json input to transform
        :type path: ``List[str + int]``
        :param path: The path of the key, value pair inside the json

        :rtype ``Tuple[List[str + int], str, str]``
        :return:  A tuple. the second and third elements are key, values, and the first is their path in the json
        """
        if path is None:
            path = []
        is_in_path = not self.keys or any(p for p in path if p in self.keys)
        if isinstance(json_input, dict):
            for k, v in json_input.items():
                if is_in_path or k in self.keys:  # found data to return
                    # recurse until finding a primitive value
                    if not isinstance(v, dict) and not isinstance(v, list):
                        yield path, k, v
                    else:
                        for res in self.json_to_path_generator(v, path + [k]):  # this is yield from for python2 BC
                            yield res

                elif self.is_nested:
                    # recurse all the json_input to find the relevant data
                    for res in self.json_to_path_generator(v, path + [k]):  # this is yield from for python2 BC
                        yield res

        if isinstance(json_input, list):
            if not json_input or (not isinstance(json_input[0], list) and not isinstance(json_input[0], dict)):
                # if the items of the lists are primitive, put the values in one line
                yield path, 'values', ', '.join(str(x) for x in json_input)

            else:
                for i, item in enumerate(json_input):
                    for res in self.json_to_path_generator(item, path + [i]):  # this is yield from for python2 BC
                        yield res

def tableToMarkdown(name, t, headers=None, headerTransform=None, removeNull=False, metadata=None, url_keys=None,
                    date_fields=None, json_transform_mapping=None, is_auto_json_transform=False, sort_headers=True):
    """
       Converts a demisto table in JSON form to a Markdown table

       :type name: ``str``
       :param name: The name of the table (required)

       :type t: ``dict`` or ``list``
       :param t: The JSON table - List of dictionaries with the same keys or a single dictionary (required)

       :type headers: ``list`` or ``string``
       :param headers: A list of headers to be presented in the output table (by order). If string will be passed
            then table will have single header. Default will include all available headers.

       :type headerTransform: ``function``
       :param headerTransform: A function that formats the original data headers (optional)

       :type removeNull: ``bool``
       :param removeNull: Remove empty columns from the table. Default is False

       :type metadata: ``str``
       :param metadata: Metadata about the table contents

       :type url_keys: ``list``
       :param url_keys: a list of keys in the given JSON table that should be turned in to clickable

       :type date_fields: ``list``
       :param date_fields: A list of date fields to format the value to human-readable output.

        :type json_transform_mapping: ``Dict[str, JsonTransformer]``
        :param json_transform_mapping: A mapping between a header key to corresponding JsonTransformer

        :type is_auto_json_transform: ``bool``
        :param is_auto_json_transform: Boolean to try to auto transform complex json

        :type sort_headers: ``bool``
        :param sort_headers: Sorts the table based on its headers only if the headers parameter is not specified

       :return: A string representation of the markdown table
       :rtype: ``str``
    """
    # Turning the urls in the table to clickable
    if url_keys:
        t = url_to_clickable_markdown(t, url_keys)

    mdResult = ''
    if name:
        mdResult = '### ' + name + '\n'

    if metadata:
        mdResult += metadata + '\n'

    if not t or len(t) == 0:
        mdResult += '**No entries.**\n'
        return mdResult

    if not headers and isinstance(t, dict) and len(t.keys()) == 1:
        # in case of a single key, create a column table where each element is in a different row.
        headers = list(t.keys())
        # if the value of the single key is a list, unpack it for creating a column table.
        if isinstance(list(t.values())[0], list):
            t = list(t.values())[0]

    if not isinstance(t, list):
        t = [t]

    if headers and isinstance(headers, STRING_TYPES):
        headers = [headers]

    if not isinstance(t[0], dict):
        # the table contains only simple objects (strings, numbers)
        # should be only one header
        if headers and len(headers) > 0:
            header = headers[0]
            t = [{header: item} for item in t]
        else:
            raise Exception("Missing headers param for tableToMarkdown. Example: headers=['Some Header']")

    # in case of headers was not provided (backward compatibility)
    if not headers:
        headers = list(t[0].keys())
        if sort_headers or not IS_PY3:
            headers.sort()

    if removeNull:
        headers_aux = headers[:]
        for header in headers:
            if all(obj.get(header) in ('', None, [], {}) for obj in t):
                headers_aux.remove(header)
        headers = headers_aux

    if not json_transform_mapping:
        json_transform_mapping = {header: JsonTransformer(flatten=not is_auto_json_transform) for header in
                                  headers}

    if t and len(headers) > 0:
        newHeaders = []
        if headerTransform is None:  # noqa
            def headerTransform(s): return stringEscapeMD(s, True, True)  # noqa
        for header in headers:
            newHeaders.append(headerTransform(header))
        mdResult += '|'
        if len(newHeaders) == 1:
            mdResult += newHeaders[0]
        else:
            mdResult += '|'.join(newHeaders)
        mdResult += '|\n'
        sep = '---'
        mdResult += '|' + '|'.join([sep] * len(headers)) + '|\n'
        for entry in t:
            entry_copy = entry.copy()
            if date_fields:
                for field in date_fields:
                    try:
                        entry_copy[field] = datetime.fromtimestamp(int(entry_copy[field]) / 1000).strftime('%Y-%m-%d %H:%M:%S')
                    except Exception:
                        pass

            vals = [stringEscapeMD((formatCell(entry_copy.get(h, ''), False,
                                               json_transform_mapping.get(h)) if entry_copy.get(h) is not None else ''),
                                   True, True) for h in headers]

            # this pipe is optional
            mdResult += '| '
            try:
                mdResult += ' | '.join(vals)
            except UnicodeDecodeError:
                vals = [str(v) for v in vals]
                mdResult += ' | '.join(vals)
            mdResult += ' |\n'

    else:
        mdResult += '**No entries.**\n'

    return mdResult

def set_integration_context(context: dict):
    """
    Set integration context using a dictionary.
    """
    if not isinstance(context, dict):
        raise TypeError("Integration context must be a dictionary")

    _INTEGRATION_CONTEXT.update(context)
    print(_INTEGRATION_CONTEXT)
    
def get_integration_context():
    """
    Get integration context.
    """
    return _INTEGRATION_CONTEXT.copy()

def urljoin(url, suffix=""):
    """
        Will join url and its suffix

        Example:
        "https://google.com/", "/"   => "https://google.com/"
        "https://google.com", "/"   => "https://google.com/"
        "https://google.com", "api"   => "https://google.com/api"
        "https://google.com", "/api"  => "https://google.com/api"
        "https://google.com/", "api"  => "https://google.com/api"
        "https://google.com/", "/api" => "https://google.com/api"

        :type url: ``string``
        :param url: URL string (required)

        :type suffix: ``string``
        :param suffix: the second part of the url

        :return: Full joined url
        :rtype: ``string``
    """
    if url[-1:] != "/":
        url = url + "/"

    if suffix.startswith("/"):
        suffix = suffix[1:]
        return url + suffix

    return url + suffix

def get_integration_context():
    """Get integration context - placeholder implementation"""
    return {}

def timestamp_to_datestring(timestamp, date_format="%Y-%m-%dT%H:%M:%S.000Z", is_utc=False):
    """
      Parses timestamp (milliseconds) to a date string in the provided date format (by default: ISO 8601 format)
      Examples: (1541494441222, 1541495441000, etc.)

      :type timestamp: ``int`` or ``str``
      :param timestamp: The timestamp to be parsed (required)

      :type date_format: ``str``
      :param date_format: The date format the timestamp should be parsed to. (optional)

      :type is_utc: ``bool``
      :param is_utc: Should the string representation of the timestamp use UTC time or the local machine time

      :return: The parsed timestamp in the date_format
      :rtype: ``str``
    """
    use_utc_time = is_utc or date_format.endswith('Z')
    if use_utc_time:
        return datetime.utcfromtimestamp(int(timestamp) / 1000.0).strftime(date_format)
    return datetime.fromtimestamp(int(timestamp) / 1000.0).strftime(date_format)


class ErrorTypes(object):
    """
    Enum: contains all the available error types
    :return: None
    :rtype: ``None``
    """
    SUCCESS = 'Successful'
    QUOTA_ERROR = 'QuotaError'
    GENERAL_ERROR = 'GeneralError'
    AUTH_ERROR = 'AuthError'
    SERVICE_ERROR = 'ServiceError'
    CONNECTION_ERROR = 'ConnectionError'
    PROXY_ERROR = 'ProxyError'
    SSL_ERROR = 'SSLError'
    TIMEOUT_ERROR = 'TimeoutError'
    RETRY_ERROR = "RetryError"

class ExecutionMetrics(object):
    """
        ExecutionMetrics is used to collect and format metric data to be reported to the XSOAR server.

        :return: None
        :rtype: ``None``
    """

    def __init__(self, success=0, quota_error=0, general_error=0, auth_error=0, service_error=0, connection_error=0,
                 proxy_error=0, ssl_error=0, timeout_error=0, retry_error=0):
        self._metrics = []
        self.metrics = None
        self.success = success
        self.quota_error = quota_error
        self.general_error = general_error
        self.auth_error = auth_error
        self.service_error = service_error
        self.connection_error = connection_error
        self.proxy_error = proxy_error
        self.ssl_error = ssl_error
        self.timeout_error = timeout_error
        self.retry_error = retry_error
        """
            Initializes an ExecutionMetrics object. Once initialized, you may increment each metric type according to the
            metric you'd like to report. Afterwards, pass the `metrics` value to CommandResults.

            :type success: ``int``
            :param success: Quantity of Successful metrics

            :type quota_error: ``int``
            :param quota_error: Quantity of Quota Error (Rate Limited) metrics

            :type general_error: ``int``
            :param general_error: Quantity of General Error metrics

            :type auth_error: ``int``
            :param auth_error: Quantity of Authentication Error metrics

            :type service_error: ``int``
            :param service_error: Quantity of Service Error metrics

            :type connection_error: ``int``
            :param connection_error: Quantity of Connection Error metrics

            :type proxy_error: ``int``
            :param proxy_error: Quantity of Proxy Error metrics

            :type ssl_error: ``int``
            :param ssl_error: Quantity of SSL Error metrics

            :type timeout_error: ``int``
            :param timeout_error: Quantity of Timeout Error metrics

            :type retry_error: ``int``
            :param retry_error: Quantity of Retry Error metrics

            :type metrics: ``CommandResults``
            :param metrics: Append this value to your CommandResults list to report the metrics to your server.
        """

    @staticmethod
    def is_supported():
        if is_demisto_version_ge('6.8.0'):
            return True
        return False

    @property
    def success(self):
        return self._success

    @success.setter
    def success(self, value):
        self._success = value
        self.update_metrics('Successful', self._success)

    @property
    def quota_error(self):
        return self._quota_error

    @quota_error.setter
    def quota_error(self, value):
        self._quota_error = value
        self.update_metrics(ErrorTypes.QUOTA_ERROR, self._quota_error)

    @property
    def general_error(self):
        return self._general_error

    @general_error.setter
    def general_error(self, value):
        self._general_error = value
        self.update_metrics(ErrorTypes.GENERAL_ERROR, self._general_error)

    @property
    def auth_error(self):
        return self._auth_error

    @auth_error.setter
    def auth_error(self, value):
        self._auth_error = value
        self.update_metrics(ErrorTypes.AUTH_ERROR, self._auth_error)

    @property
    def service_error(self):
        return self._service_error

    @service_error.setter
    def service_error(self, value):
        self._service_error = value
        self.update_metrics(ErrorTypes.SERVICE_ERROR, self._service_error)

    @property
    def connection_error(self):
        return self._connection_error

    @connection_error.setter
    def connection_error(self, value):
        self._connection_error = value
        self.update_metrics(ErrorTypes.CONNECTION_ERROR, self._connection_error)

    @property
    def proxy_error(self):
        return self._proxy_error

    @proxy_error.setter
    def proxy_error(self, value):
        self._proxy_error = value
        self.update_metrics(ErrorTypes.PROXY_ERROR, self._proxy_error)

    @property
    def ssl_error(self):
        return self._ssl_error

    @ssl_error.setter
    def ssl_error(self, value):
        self._ssl_error = value
        self.update_metrics(ErrorTypes.SSL_ERROR, self._ssl_error)

    @property
    def timeout_error(self):
        return self._timeout_error

    @timeout_error.setter
    def timeout_error(self, value):
        self._timeout_error = value
        self.update_metrics(ErrorTypes.TIMEOUT_ERROR, self._timeout_error)

    @property
    def retry_error(self):
        return self._retry_error

    @retry_error.setter
    def retry_error(self, value):
        self._retry_error = value
        self.update_metrics(ErrorTypes.RETRY_ERROR, self._retry_error)

    def get_metric_list(self):
        return self._metrics

    def update_metrics(self, metric_type, metric_value):
        if metric_value > 0:
            if len(self._metrics) == 0:
                self._metrics.append({'Type': metric_type, 'APICallsCount': metric_value})
            else:
                for metric in self._metrics:
                    if metric['Type'] == metric_type:
                        metric['APICallsCount'] = metric_value
                        break
                else:
                    self._metrics.append({'Type': metric_type, 'APICallsCount': metric_value})
            self.metrics = CommandResults(execution_metrics=self._metrics)


def is_time_sensitive():
    """
    Checks if the command reputation (auto-enrichment) is called as auto-extract=inline.
    This function checks if the 'isTimeSensitive' attribute exists in the 'demisto' object and if it's set to True.

        :return: bool
        :rtype: ``bool``
    """
    return False


def get_integration_name():
    """
    Getting calling integration's name
    :return: Calling integration's name
    :rtype: ``str``
    """
    return "securonix"


def skip_proxy():
    """
    The function deletes the proxy environment vars in order to http requests to skip routing through proxy

    :return: None
    :rtype: ``None``
    """
    for k in ('HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy'):
        if k in os.environ:
            del os.environ[k]

def skip_cert_verification():
    """
    The function deletes the self signed certificate env vars in order to http requests to skip certificate validation.

    :return: None
    :rtype: ``None``
    """
    for k in ('REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE'):
        if k in os.environ:
            del os.environ[k]

# Will add only if 'requests' module imported
if 'requests' in sys.modules:
    if IS_PY3 and PY_VER_MINOR >= 10:
        from requests.packages.urllib3.util.ssl_ import create_urllib3_context

        # The ciphers string used to replace default cipher string

        CIPHERS_STRING = '@SECLEVEL=0:ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:ECDH+AESGCM:DH+AESGCM:' \
                         'ECDH+AES:DH+AES:RSA+ANESGCM:RSA+AES:!aNULL:!eNULL:!MD5:!DSS'

        class SSLAdapter(HTTPAdapter):
            """
                A wrapper used for https communication to enable ciphers that are commonly used
                and are not enabled by default
                :return: No data returned
                :rtype: ``None``
            """
            context = create_urllib3_context(ciphers=CIPHERS_STRING)

            def __init__(self, verify=True, **kwargs):
                # type: (bool, dict) -> None
                if not verify and IS_PY3:
                    self.context.check_hostname = False
                if not verify and ssl.OPENSSL_VERSION_INFO >= (3, 0, 0, 0):
                    self.context.options |= 0x4
                super().__init__(**kwargs)  # type: ignore[arg-type]

            def init_poolmanager(self, *args, **kwargs):
                kwargs['ssl_context'] = self.context
                return super(SSLAdapter, self).init_poolmanager(*args, **kwargs)

            def proxy_manager_for(self, *args, **kwargs):
                kwargs['ssl_context'] = self.context
                return super(SSLAdapter, self).proxy_manager_for(*args, **kwargs)

    class BaseClient(object):
        """Client to use in integrations with powerful _http_request
        :type base_url: ``str``
        :param base_url: Base server address with suffix, for example: https://example.com/api/v2/.

        :type verify: ``bool``
        :param verify: Whether the request should verify the SSL certificate.

        :type proxy: ``bool``
        :param proxy: Whether to run the integration using the system proxy.

        :type ok_codes: ``tuple`` or ``None``
        :param ok_codes:
            The request codes to accept as OK, for example: (200, 201, 204).
            Will use requests.Response.ok if set to None.

        :type headers: ``dict`` or ``None``
        :param headers:
            The request headers, for example: {'Accept`: `application/json`}.
            Can be None.

        :type auth: ``dict`` or ``tuple`` or ``None``
        :param auth:
            The request authorization, for example: (username, password).
            Can be None.

        :return: No data returned
        :rtype: ``None``
        """

        REQUESTS_TIMEOUT = 60
        TIME_SENSITIVE_TOTAL_TIMEOUT = 15

        def __init__(
            self,
            base_url,
            verify=True,
            proxy=False,
            ok_codes=tuple(),
            headers=None,
            auth=None,
            timeout=REQUESTS_TIMEOUT,
        ):
            self._base_url = base_url
            self._verify = verify
            self._ok_codes = ok_codes
            self._headers = headers
            self._auth = auth
            self._session = requests.Session()

            # the following condition was added to overcome the security hardening happened in Python 3.10.
            # https://github.com/python/cpython/pull/25778
            # https://bugs.python.org/issue43998

            if IS_PY3 and PY_VER_MINOR >= 10 and not verify:
                self._session.mount('https://', SSLAdapter(verify=verify))

            if proxy:
                ensure_proxy_has_http_prefix()
            else:
                skip_proxy()
            if not verify:
                skip_cert_verification()

            # removing trailing = char from env var value added by the server
            entity_timeout = os.getenv('REQUESTS_TIMEOUT.' + (get_integration_name() or get_script_name()), '')
            system_timeout = os.getenv('REQUESTS_TIMEOUT', '')
            self.timeout = float(entity_timeout or system_timeout or timeout)

            # Time-Sensitive Logic
            self._time_sensitive_deadline = None
            self._time_sensitive_total_timeout = self.TIME_SENSITIVE_TOTAL_TIMEOUT

            if is_time_sensitive():
                demisto.debug("Time-sensitive mode enabled. Setting execution time limit to {} seconds.".format(self._time_sensitive_total_timeout))
                self._time_sensitive_deadline = time.time() + float(
                    self._time_sensitive_total_timeout
                )

            self.execution_metrics = ExecutionMetrics()


        def __del__(self):
            self._return_execution_metrics_results()
            try:
                self._session.close()
            except AttributeError:
                # we ignore exceptions raised due to session not used by the client and hence do not exist in __del__
                pass
            except Exception:  # noqa
                demisto.debug('failed to close BaseClient session with the following error:\n{}'.format(traceback.format_exc()))

        def _implement_retry(self, retries=0,
                             status_list_to_retry=None,
                             backoff_factor=5,
                             backoff_jitter=0.0,
                             raise_on_redirect=False,
                             raise_on_status=False):
            """
            Implements the retry mechanism.
            In the default case where retries = 0 the request will fail on the first time

            :type retries: ``int``
            :param retries: How many retries should be made in case of a failure. when set to '0'- will fail on the first time

            :type status_list_to_retry: ``iterable``
            :param status_list_to_retry: A set of integer HTTP status codes that we should force a retry on.
                A retry is initiated if the request method is in ['GET', 'POST', 'PUT']
                and the response status code is in ``status_list_to_retry``.

            :type backoff_factor ``float``
            :param backoff_factor:
                A backoff factor to apply between attempts after the second try
                (most errors are resolved immediately by a second try without a
                delay). urllib3 will sleep for::

                    {backoff factor} * (2 ** ({number of total retries} - 1))

                seconds. If the backoff_factor is 0.1, then :func:`.sleep` will sleep
                for [0.0s, 0.2s, 0.4s, ...] between retries. It will never be longer
                than :attr:`Retry.BACKOFF_MAX`.

                By default, backoff_factor set to 5

            :type backoff_jitter ``float``
            :param backoff_jitter: the sleep (backoff factor) is extended by
                random.uniform(0, {backoff jitter})

            :type raise_on_redirect ``bool``
            :param raise_on_redirect: Whether, if the number of redirects is
                exhausted, to raise a MaxRetryError, or to return a response with a
                response code in the 3xx range.

            :type raise_on_status ``bool``
            :param raise_on_status: Similar meaning to ``raise_on_redirect``:
                whether we should raise an exception, or return a response,
                if status falls in ``status_forcelist`` range and retries have
                been exhausted.
            """
            try:
                method_whitelist = "allowed_methods" if hasattr(
                    Retry.DEFAULT, "allowed_methods") else "method_whitelist"  # type: ignore[attr-defined]
                whitelist_kawargs = {
                    method_whitelist: frozenset(['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
                }
                retry = Retry(
                    total=retries,
                    read=retries,
                    connect=retries,
                    backoff_factor=backoff_factor,
                    backoff_jitter=backoff_jitter,
                    status=retries,
                    status_forcelist=status_list_to_retry,
                    raise_on_status=raise_on_status,
                    raise_on_redirect=raise_on_redirect,
                    **whitelist_kawargs  # type: ignore[arg-type]
                )
                http_adapter = HTTPAdapter(max_retries=retry)

                # the following condition was added to overcome the security hardening happened in Python 3.10.
                # https://github.com/python/cpython/pull/25778
                # https://bugs.python.org/issue43998

                if self._verify:
                    https_adapter = http_adapter
                elif IS_PY3 and PY_VER_MINOR >= 10:
                    https_adapter = SSLAdapter(max_retries=retry, verify=self._verify)  # type: ignore[arg-type]
                else:
                    https_adapter = http_adapter

                self._session.mount('https://', https_adapter)

            except NameError:
                pass

        def _http_request(self, method, url_suffix='', full_url=None, headers=None, auth=None, json_data=None,
                          params=None, data=None, files=None, timeout=None, resp_type='json', ok_codes=None,
                          return_empty_response=False, retries=0, status_list_to_retry=None,
                          backoff_factor=5, backoff_jitter=0.0, raise_on_redirect=False, raise_on_status=False,
                          error_handler=None, empty_valid_codes=None, params_parser=None, with_metrics=False, **kwargs):
            """A wrapper for requests lib to send our requests and handle requests and responses better.

            :type method: ``str``
            :param method: The HTTP method, for example: GET, POST, and so on.

            :type url_suffix: ``str``
            :param url_suffix: The API endpoint.

            :type full_url: ``str``
            :param full_url:
                Bypasses the use of self._base_url + url_suffix. This is useful if you need to
                make a request to an address outside of the scope of the integration
                API.

            :type headers: ``dict``
            :param headers: Headers to send in the request. If None, will use self._headers.

            :type auth: ``tuple``
            :param auth:
                The authorization tuple (usually username/password) to enable Basic/Digest/Custom HTTP Auth.
                if None, will use self._auth.

            :type params: ``dict``
            :param params: URL parameters to specify the query.

            :type data: ``dict``
            :param data: The data to send in a 'POST' request.

            :type json_data: ``dict``
            :param json_data: The dictionary to send in a 'POST' request.

            :type files: ``dict``
            :param files: The file data to send in a 'POST' request.

            :type timeout: ``float`` or ``tuple``
            :param timeout:
                The amount of time (in seconds) that a request will wait for a client to
                establish a connection to a remote machine before a timeout occurs.
                can be only float (Connection Timeout) or a tuple (Connection Timeout, Read Timeout).

            :type resp_type: ``str``
            :param resp_type:
                Determines which data format to return from the HTTP request. The default
                is 'json'. Other options are 'text', 'content', 'xml' or 'response'. Use 'response'
                 to return the full response object.

            :type ok_codes: ``tuple``
            :param ok_codes:
                The request codes to accept as OK, for example: (200, 201, 204). If you specify
                "None", will use self._ok_codes.

            :type retries: ``int``
            :param retries: How many retries should be made in case of a failure. when set to '0'- will fail on the first time

            :type status_list_to_retry: ``iterable``
            :param status_list_to_retry: A set of integer HTTP status codes that we should force a retry on.
                A retry is initiated if the request method is in ['GET', 'POST', 'PUT']
                and the response status code is in ``status_list_to_retry``.

            :type backoff_factor ``float``
            :param backoff_factor:
                A backoff factor to apply between attempts after the second try
                (most errors are resolved immediately by a second try without a
                delay). urllib3 will sleep for::

                    {backoff factor} * (2 ** ({number of total retries} - 1))

                seconds. If the backoff_factor is 0.1, then :func:`.sleep` will sleep
                for [0.0s, 0.2s, 0.4s, ...] between retries. It will never be longer
                than :attr:`Retry.BACKOFF_MAX`.

                By default, backoff_factor set to 5

            :type backoff_jitter ``float``
            :param backoff_jitter: the sleep (backoff factor) is extended by
                random.uniform(0, {backoff jitter})

            :type raise_on_redirect ``bool``
            :param raise_on_redirect: Whether, if the number of redirects is
                exhausted, to raise a MaxRetryError, or to return a response with a
                response code in the 3xx range.

            :type raise_on_status ``bool``
            :param raise_on_status: Similar meaning to ``raise_on_redirect``:
                whether we should raise an exception, or return a response,
                if status falls in ``status_forcelist`` range and retries have
                been exhausted.

            :type error_handler ``callable``
            :param error_handler: Given an error entry, the error handler outputs the
                new formatted error message.

            :type empty_valid_codes: ``list``
            :param empty_valid_codes: A list of all valid status codes of empty responses (usually only 204, but
                can vary)

            :type params_parser: ``callable``
            :param params_parser: How to quote the params. By default, spaces are replaced with `+` and `/` to `%2F`.
            see here for more info: https://docs.python.org/3/library/urllib.parse.html#urllib.parse.urlencode
            Note! supported only in python3.

            :type with_metrics ``bool``
            :param with_metrics: Whether or not to calculate execution metrics from the response

            :return: Depends on the resp_type parameter
            :rtype: ``dict`` or ``str`` or ``bytes`` or ``xml.etree.ElementTree.Element`` or ``requests.Response``
            """

            # Time-Sensitive command Logic
            request_timeout = timeout
            request_retries = retries
            remaining_time = None

            # Time-Sensitive command mode
            if self._time_sensitive_deadline:
                remaining_time = self._time_sensitive_deadline - time.time()

                if remaining_time <= 0:
                    raise DemistoException(
                            "Time-sensitive command execution time limit ({time_limit}s) reached before performing the API request."
                            .format(time_limit=self._time_sensitive_total_timeout)
                        )

                request_retries = 0
                request_timeout = remaining_time

            # Set default timeout if one hasn't been set by user OR by time-sensitive logic
            if request_timeout is None:
                request_timeout = self.timeout

            try:
                # Replace params if supplied
                address = full_url if full_url else urljoin(self._base_url, url_suffix)
                headers = headers if headers else self._headers
                auth = auth if auth else self._auth

                if request_retries:
                    self._implement_retry(
                        request_retries,
                        status_list_to_retry,
                        backoff_factor,
                        backoff_jitter,
                        raise_on_redirect,
                        raise_on_status,
                    )

                if (
                    IS_PY3 and params_parser
                ):  # The `quote_via` parameter is supported only in python3.
                    params = urllib.parse.urlencode(params, quote_via=params_parser)

                # Execute
                res = self._session.request(
                    method,
                    address,
                    verify=self._verify,
                    params=params,
                    data=data,
                    json=json_data,
                    files=files,
                    headers=headers,
                    auth=auth,
                    timeout=request_timeout,
                    **kwargs
                )

                if not self._is_status_code_valid(res, ok_codes):
                    self._handle_error(error_handler, res, with_metrics)

                return self._handle_success(
                    res,
                    resp_type,
                    empty_valid_codes,
                    return_empty_response,
                    with_metrics,
                )

            except requests.exceptions.ConnectTimeout as exception:
                if with_metrics:
                    self.execution_metrics.timeout_error += 1
                err_msg = (
                    "Connection Timeout Error - potential reasons might be that the Server URL parameter"
                    " is incorrect or that the Server is not accessible from your host."
                )
                if (
                    self._time_sensitive_deadline
                    and remaining_time is not None
                    and remaining_time <= request_timeout
                ):
                    err_msg = "Time-sensitive command execution time limit ({time_limit}s) exceeded. Original error: {original_msg}".format(
                        time_limit=self._time_sensitive_total_timeout,
                        original_msg=err_msg
                    )
                raise DemistoException(err_msg, exception)
            except requests.exceptions.SSLError as exception:
                if with_metrics:
                    self.execution_metrics.ssl_error += 1
                # in case the "Trust any certificate" is already checked
                if not self._verify:
                    raise
                err_msg = 'SSL Certificate Verification Failed - try selecting \'Trust any certificate\' checkbox in' \
                          ' the integration configuration.'
                raise DemistoException(err_msg, exception)
            except requests.exceptions.ProxyError as exception:
                if with_metrics:
                    self.execution_metrics.proxy_error += 1
                err_msg = 'Proxy Error - if the \'Use system proxy\' checkbox in the integration configuration is' \
                          ' selected, try clearing the checkbox.'
                raise DemistoException(err_msg, exception)
            except requests.exceptions.ConnectionError as exception:
                if with_metrics:
                    self.execution_metrics.connection_error += 1
                # Get originating Exception in Exception chain
                error_class = str(exception.__class__)
                err_type = '<' + error_class[error_class.find('\'') + 1: error_class.rfind('\'')] + '>'

                err_msg = 'Verify that the server URL parameter' \
                          ' is correct and that you have access to the server from your host.' \
                          '\nError Type: {}'.format(err_type)
                if exception.errno and exception.strerror:
                    err_msg += '\nError Number: [{}]\nMessage: {}\n'.format(exception.errno, exception.strerror)
                else:
                    err_msg += '\n{}'.format(str(exception))
                raise DemistoException(err_msg, exception)

            except requests.exceptions.RetryError as exception:
                if with_metrics:
                    self.execution_metrics.retry_error += 1
                try:
                    reason = 'Reason: {}'.format(exception.args[0].reason.args[0])
                except Exception:  # noqa: disable=broad-except
                    reason = ''
                err_msg = 'Max Retries Error- Request attempts with {} retries failed. \n{}'.format(retries, reason)
                raise DemistoException(err_msg, exception)

        def _handle_error(self, error_handler, res, should_update_metrics):
            """ Handles error response by calling error handler or default handler.
            If an exception is raised, update metrics with failure. Otherwise, proceeds.

            :type res: ``requests.Response``
            :param res: Response from API after the request for which to check error type

            :type error_handler ``callable``
            :param error_handler: Given an error entry, the error handler outputs the
                new formatted error message.

            :type should_update_metrics ``bool``
            :param should_update_metrics: Whether or not to update execution metrics according to response
            """
            try:
                if error_handler:
                    error_handler(res)
                else:
                    self.client_error_handler(res)
            except Exception:
                if should_update_metrics:
                    self._update_metrics(res, success=False)
                raise

        def _handle_success(self, res, resp_type, empty_valid_codes, return_empty_response, should_update_metrics):
            """ Handles successful response

            :type res: ``requests.Response``
            :param res: Response from API after the request for which to check error type

            :type resp_type: ``str``
            :param resp_type:
                Determines which data format to return from the HTTP request. The default
                is 'json'. Other options are 'text', 'content', 'xml' or 'response'. Use 'response'
                 to return the full response object.

            :type empty_valid_codes: ``list``
            :param empty_valid_codes: A list of all valid status codes of empty responses (usually only 204, but
                can vary)

            :type return_empty_response: ``bool``
            :param response: Whether to return an empty response body if the response code is in empty_valid_codes

            :type should_update_metrics ``bool``
            :param should_update_metrics: Whether or not to update execution metrics according to response
            """
            if should_update_metrics:
                self._update_metrics(res, success=True)

            if not empty_valid_codes:
                empty_valid_codes = [204]
            is_response_empty_and_successful = (res.status_code in empty_valid_codes)
            if is_response_empty_and_successful and return_empty_response:
                return res

            return self.cast_response(res, resp_type)

        def cast_response(self, res, resp_type, raise_on_error=True):
            resp_type = resp_type.lower()
            try:
                if resp_type == 'json':
                    return res.json()
                if resp_type == 'text':
                    return res.text
                if resp_type == 'content':
                    return res.content
                if resp_type == 'xml':
                    ET.fromstring(res.text)
                if resp_type == 'response':
                    return res
                return res
            except ValueError as exception:
                if raise_on_error:
                    raise DemistoException('Failed to parse {} object from response: {}'  # type: ignore[str-bytes-safe]
                                           .format(resp_type, res.content), exception, res)

        def _update_metrics(self, res, success):
            """ Updates execution metrics based on response and success flag.

            :type response: ``requests.Response``
            :param response: Response from API after the request for which to check error type

            :type success: ``bool``
            :param success: Wheter the request succeeded or failed
            """
            if success:
                if not self.is_polling_in_progress(res):
                    self.execution_metrics.success += 1
            else:
                error_type = self.determine_error_type(res)
                if error_type == ErrorTypes.QUOTA_ERROR:
                    self.execution_metrics.quota_error += 1
                elif error_type == ErrorTypes.AUTH_ERROR:
                    self.execution_metrics.auth_error += 1
                elif error_type == ErrorTypes.SERVICE_ERROR:
                    self.execution_metrics.service_error += 1
                elif error_type == ErrorTypes.GENERAL_ERROR:
                    self.execution_metrics.general_error += 1

        def determine_error_type(self, response):
            """ Determines the type of error based on response status code and content.
            Note: this method can be overriden by subclass when implementing execution metrics.

            :type response: ``requests.Response``
            :param response: Response from API after the request for which to check error type

            :return: The error type if found, otherwise None
            :rtype: ``ErrorTypes``
            """
            if response.status_code == 401:
                return ErrorTypes.AUTH_ERROR
            elif response.status_code == 429:
                return ErrorTypes.QUOTA_ERROR
            elif response.status_code == 500:
                return ErrorTypes.SERVICE_ERROR
            return ErrorTypes.GENERAL_ERROR

        def is_polling_in_progress(self, response):
            """If thie response indicates polling operation in progress, return True.
            Note: this method should be overriden by subclass when implementing polling reputation commands
            with execution metrics.

            :type response: ``requests.Response``
            :param response: Response from API after the request for which to check the polling status

            :return: Whether the response indicates polling in progress
            :rtype: ``bool``
            """
            return False

        def _is_status_code_valid(self, response, ok_codes=None):
            """If the status code is OK, return 'True'.

            :type response: ``requests.Response``
            :param response: Response from API after the request for which to check the status.

            :type ok_codes: ``tuple`` or ``list``
            :param ok_codes:
                The request codes to accept as OK, for example: (200, 201, 204). If you specify
                "None", will use response.ok.

            :return: Whether the status of the response is valid.
            :rtype: ``bool``
            """
            # Get wanted ok codes
            status_codes = ok_codes if ok_codes else self._ok_codes
            if status_codes:
                return response.status_code in status_codes
            return response.ok

        def client_error_handler(self, res):
            """Generic handler for API call error
            Constructs and throws a proper error for the API call response.

            :type response: ``requests.Response``
            :param response: Response from API after the request for which to check the status.
            """
            err_msg = 'Error in API call [{}] - {}'.format(res.status_code, res.reason)
            try:
                # Try to parse json error response
                error_entry = res.json()
                err_msg += '\n{}'.format(json.dumps(error_entry))
                raise DemistoException(err_msg, res=res)
            except ValueError:
                err_msg += '\n{}'.format(res.text)
                raise DemistoException(err_msg, res=res)

        def _return_execution_metrics_results(self):
            """ Returns execution metrics results.
            Might raise an AttributeError exception if execution_metrics is not initialized.
            """
            try:
                if self.execution_metrics.metrics:
                    return_results(cast(CommandResults, self.execution_metrics.metrics))
            except AttributeError:
                pass

class Client(BaseClient):
    """
    Client to use in the Securonix integration. Overrides BaseClient
    """

    def __init__(
        self,
        tenant: str,
        server_url: str,
        username: str,
        password: str,
        verify: bool,
        proxy: bool,
        securonix_retry_count: int,
        securonix_retry_delay: int,
        securonix_retry_delay_type: str,
    ):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy)
        self._username = username
        self._password = password
        self._tenant = tenant
        self._securonix_retry_count = securonix_retry_count
        self._securonix_retry_delay = securonix_retry_delay
        self._securonix_retry_delay_type = securonix_retry_delay_type
        self.session = requests.Session()

        # Fetch cached integration context.
        integration_context = get_integration_context()
        self._token = integration_context.get("token") or self._generate_token()
        # the following condition was added to overcome the security hardening happened in Python 3.10.
        # https://github.com/python/cpython/pull/25778
        # https://bugs.python.org/issue43998

        if IS_PY3 and PY_VER_MINOR >= 10 and not verify:
            self.session.mount("https://", SSLAdapter(verify=verify))

    def get_securonix_retry_count(self):
        return self._securonix_retry_count

    def get_securonix_retry_delay(self):
        return self._securonix_retry_delay

    def get_securonix_retry_delay_type(self):
        return self._securonix_retry_delay_type

    def implement_retry(
        self,
        retries: int = 0,
        status_list_to_retry: list = None,
        backoff_factor: int = 30,
        raise_on_redirect: bool = False,
        raise_on_status: bool = False,
    ):
        """
        Implements the retry mechanism.
        In the default case where retries = 0 the request will fail on the first time

        :type retries: ``int`` :param retries: How many retries should be made in case of a failure. when set to '0'-
        will fail on the first time

        :type status_list_to_retry: ``iterable``
        :param status_list_to_retry: A set of integer HTTP status codes that we should force a retry on.
            A retry is initiated if the request method is in ['GET', 'POST', 'PUT']
            and the response status code is in ``status_list_to_retry``.

        :type backoff_factor ``float``
        :param backoff_factor:
            A backoff factor to apply between attempts after the second try
            (most errors are resolved immediately by a second try without a
            delay). urllib3 will sleep for::

                {backoff factor} * (2 ** ({number of total retries} - 1))

            seconds. If the backoff_factor is 0.1, then :func:`.sleep` will sleep
            for [0.0s, 0.2s, 0.4s, ...] between retries. It will never be longer
            than :attr:`Retry.BACKOFF_MAX`.

            By default, backoff_factor set to 5

        :type raise_on_redirect ``bool``
        :param raise_on_redirect: Whether, if the number of redirects is
            exhausted, to raise a MaxRetryError, or to return a response with a
            response code in the 3xx range.

        :type raise_on_status ``bool``
        :param raise_on_status: Similar meaning to ``raise_on_redirect``:
            whether we should raise an exception, or return a response,
            if status falls in ``status_forcelist`` range and retries have
            been exhausted.
        """
        try:
            method_whitelist = (
                "allowed_methods"
                if hasattr(
                    Retry.DEFAULT,  # type: ignore[attr-defined]
                    "allowed_methods",
                )
                else "method_whitelist"
            )
            whitelist_kawargs = {method_whitelist: frozenset(["GET", "POST", "PUT"])}
            retry = None
            if self._securonix_retry_delay_type == "Fixed":
                demisto.debug("Securonix Retry delay type is Fixed")
                # Set DEFAULT_BACKOFF_MAX to 2hour(in seconds)
                RetryFixed.DEFAULT_BACKOFF_MAX = 7200
                retry = RetryFixed(
                    total=retries,
                    connect=0,
                    read=0,
                    backoff_factor=backoff_factor,
                    status=retries,
                    status_forcelist=status_list_to_retry,
                    raise_on_status=raise_on_status,
                    raise_on_redirect=raise_on_redirect,
                    **whitelist_kawargs,  # type: ignore[arg-type]
                )
            else:
                demisto.debug("Securonix Retry delay type is Exponential")
                # Set DEFAULT_BACKOFF_MAX to 2hour(in seconds)
                RetryExponential.DEFAULT_BACKOFF_MAX = 7200
                retry = RetryExponential(  # type: ignore
                    total=retries,
                    backoff_factor=backoff_factor,
                    connect=0,
                    read=0,
                    status=retries,
                    status_forcelist=status_list_to_retry,
                    raise_on_status=raise_on_status,
                    raise_on_redirect=raise_on_redirect,
                    **whitelist_kawargs,  # type: ignore[arg-type]
                )
            http_adapter = HTTPAdapter(max_retries=retry)

            # the following condition was added to overcome the security hardening happened in Python 3.10.
            # https://github.com/python/cpython/pull/25778
            # https://bugs.python.org/issue43998

            if self._verify:
                https_adapter = http_adapter
            elif IS_PY3 and PY_VER_MINOR >= 10:
                https_adapter = SSLAdapter(max_retries=retry, verify=self._verify)  # type: ignore[arg-type]
            else:
                https_adapter = http_adapter

            self.session.mount("https://", https_adapter)

        except NameError:
            pass

    def http_request(
        self,
        method,
        url_suffix,
        headers=None,
        params=None,
        response_type: str = "json",
        json=None,
        data=None,
        regenerate_access_token=True,
    ):
        """
        Generic request to Securonix
        """
        global FULL_URL
        FULL_URL = urljoin(self._base_url, url_suffix)
        status_list_to_retry = [429] + list(range(500, 600))
        if self._securonix_retry_count > 0:
            self.implement_retry(
                retries=self._securonix_retry_count,
                status_list_to_retry=status_list_to_retry,
                backoff_factor=self._securonix_retry_delay,
                raise_on_redirect=False,
                raise_on_status=True,
            )

        try:
            print(f"Making HTTP request with URL {FULL_URL}")
            result = self.session.request(
                method,
                FULL_URL,
                params=params,
                headers=headers,
                verify=self._verify,
                json=json,
                data=data,
            )
            if result.status_code == 403 and regenerate_access_token:
                self._token = self._generate_token()
                headers["token"] = self._token
                return self.http_request(method, url_suffix, headers, params, response_type, json, data, False)
            if not result.ok:
                raise ValueError(f"Error in API call to Securonix {result.status_code}. Reason: {result.text}")
            try:
                if url_suffix == "/incident/attachments":
                    return result
                if response_type != "json":
                    return result.text
                return result.json()
            except Exception:
                raise ValueError(f"Failed to parse http response to JSON format. Original response body: \n{result.text}")

        except requests.exceptions.ConnectTimeout as exception:
            err_msg = (
                "Connection Timeout Error - potential reasons might be that the Server URL parameter"
                " is incorrect or that the Server is not accessible from your host."
            )
            raise Exception(f"{err_msg}\n{exception}")

        except requests.exceptions.SSLError as exception:
            err_msg = (
                "SSL Certificate Verification Failed - try selecting 'Trust any certificate' checkbox in"
                " the integration configuration."
            )
            raise Exception(f"{err_msg}\n{exception}")

        except requests.exceptions.ProxyError as exception:
            err_msg = (
                "Proxy Error - if the 'Use system proxy' checkbox in the integration configuration is"
                " selected, try clearing the checkbox."
            )
            raise Exception(f"{err_msg}\n{exception}")

        except requests.exceptions.ConnectionError as exception:
            error_class = str(exception.__class__)
            err_type = "<" + error_class[error_class.find("'") + 1 : error_class.rfind("'")] + ">"  # noqa: E203
            err_msg = (
                f"Error Type: {err_type}\n"
                f"Error Number: [{exception.errno}]\n"
                f"Message: {exception.strerror}\n"
                f"Verify that the tenant parameter is correct "
                f"and that you have access to the server from your host."
            )
            raise Exception(f"{err_msg}\n{exception}")

        except requests.exceptions.RetryError as exception:
            try:
                reason = f"Reason: {exception.args[0].reason.args[0]}"  # pylint: disable=no-member
            except Exception:  # noqa: disable=broad-except
                reason = ""
            err_msg = (
                f"Max Retries Error: Request attempts with {self._securonix_retry_count} retries and with "
                f"{self._securonix_retry_delay} seconds {self._securonix_retry_delay_type} delay "
                f"failed.\n{reason}"
            )
            if self._securonix_retry_delay_type == "Exponential":
                # For Exponential delay we are dividing it by 2 so for error message make it to original value
                err_msg = (
                    f"Max Retries Error: Request attempts with {self._securonix_retry_count} retries and with"
                    f" {self._securonix_retry_delay * 2} seconds {self._securonix_retry_delay_type} delay "
                    f"failed.\n{reason}"
                )
            demisto.error(err_msg)
            raise Exception(f"{err_msg}\n{exception}")

        except requests.exceptions.InvalidHeader as exception:
            set_integration_context({})
            raise Exception(f"Invalid token generated from the API.\n{exception}")

        except Exception as exception:
            raise Exception(str(exception))

    def _generate_token(self) -> str:
        """Generate a token

        Returns:
            token valid for 1 day
        """
        print("Generating new access token.")
        headers = {
            "username": self._username,
            "password": self._password,
            "validity": "1",
        }
        token = self.http_request("GET", "/token/generate", headers=headers, response_type="text")
        print(token)
        set_integration_context({"token": token})
        return token

    def list_workflows_request(self) -> dict:
        """List workflows.

        Returns:
            Response from API.
        """
        workflows = self.http_request("GET", "/incident/get", headers={"token": self._token}, params={"type": "workflows"})
        return workflows.get("result").get("workflows")

    def get_default_assignee_for_workflow_request(self, workflow: str) -> dict:
        """Get default assignee for a workflow..

        Args:
            workflow: workflow name

        Returns:
            Response from API.
        """
        params = {"type": "defaultAssignee", "workflow": workflow}
        default_assignee = self.http_request("GET", "/incident/get", headers={"token": self._token}, params=params)
        return default_assignee.get("result")

    def list_possible_threat_actions_request(self) -> dict:
        """List possible threat actions.

        Returns:
            Response from API.
        """

        threat_actions = self.http_request(
            "GET", "/incident/get", headers={"token": self._token}, params={"type": "threatActions"}
        )
        return threat_actions.get("result")

    def list_policies_request(self) -> dict:
        """List policies.

        Returns:
            Response from API.
        """

        policies = self.http_request("GET", "/policy/getAllPolicies", headers={"token": self._token}, response_type="xml")
        return policies

    def list_resource_groups_request(self) -> dict:
        """List resource groups.

        Returns:
            Response from API.
        """

        resource_groups = self.http_request("GET", "/list/resourceGroups", headers={"token": self._token}, response_type="xml")
        return resource_groups

    def list_users_request(self) -> dict:
        """List users.

        Returns:
            Response from API.
        """

        users = self.http_request("GET", "/list/allUsers", headers={"token": self._token}, response_type="xml")
        return users

    def list_activity_data_request(self, from_: str, to_: str, query: str = None, max_records: int = None) -> dict:
        """List activity data.

        Args:
            from_: eventtime start range in format MM/dd/yyyy HH:mm:ss.
            to_: eventtime end range in format MM/dd/yyyy HH:mm:ss.
            query: open query.
            max_records: maximum number of activity records to retrieve.

        Returns:
            Response from API.
        """
        params = {"query": "index=activity", "eventtime_from": from_, "eventtime_to": to_, "prettyJson": True}
        if max_records is not None:
            params["max"] = max_records
        remove_nulls_from_dictionary(params)
        if query:
            if re.findall(r"index\s*=\s*\w+", query):
                params["query"] = query
            else:
                params["query"] = f"{params['query']} AND {query}"
        activity_data = self.http_request("GET", "/spotter/index/search", headers={"token": self._token}, params=params)
        return activity_data

    def list_violation_data_request(
        self, from_: str, to_: str, query: str = None, query_id: str = None, max_violations: int | None = 1000
    ) -> dict:
        """List violation data.

        Args:
            from_: eventtime start range in format MM/dd/yyyy HH:mm:ss.
            to_: eventtime end range in format MM/dd/yyyy HH:mm:ss.
            query: open query.
            query_id: query_id to paginate violations.
            max_violations: max number of violations to return.

        Returns:
            Response from API.
        """
        params = {
            "query": "index=violation",
            "generationtime_from": from_,
            "generationtime_to": to_,
            "queryId": query_id,
            "prettyJson": True,
            "max": max_violations,
        }
        if query:
            if re.findall(r"index\s*=\s*\w+", query):
                params["query"] = query
            else:
                params["query"] = f"{params['query']} AND {query}"

        remove_nulls_from_dictionary(params)
        violation_data = self.http_request("GET", "/spotter/index/search", headers={"token": self._token}, params=params)
        return violation_data

    def list_incidents_request(
        self, from_epoch: str, to_epoch: str, incident_status: str, max_incidents: str = "200", offset: str = "0"
    ) -> dict:
        """List all incidents by sending a GET request.

        Args:
            from_epoch: from time in epoch
            to_epoch: to time in epoch
            incident_status: incident status e.g:closed, opened
            max_incidents: max incidents to get
            offset: offset to be used

        Returns:
            Response from API.
        """
        headers = {"token": self._token, "Accept": "application/vnd.snypr.app-v6.0+json"}
        params = {
            "type": "list",
            "from": from_epoch,
            "to": to_epoch,
            "rangeType": incident_status,
            "max": max_incidents,
            "order": "asc",
            "offset": offset,
        }
        incidents = self.http_request("GET", "/incident/get", headers=headers, params=params)
        return incidents.get("result").get("data")

    def get_incident_request(self, incident_id: str) -> dict:
        """get incident meta data by sending a GET request.

        Args:
            incident_id: incident ID.

        Returns:
            Response from API.
        """
        headers = {"token": self._token, "Accept": "application/vnd.snypr.app-v6.0+json"}
        params = {
            "type": "metaInfo",
            "incidentId": incident_id,
        }
        incident = self.http_request("GET", "/incident/get", headers=headers, params=params)
        return incident.get("result").get("data")

    def get_incident_status_request(self, incident_id: str) -> dict:
        """get incident meta data by sending a GET request.

        Args:
            incident_id: incident ID.

        Returns:
            Response from API.
        """
        params = {
            "type": "status",
            "incidentId": incident_id,
        }
        incident = self.http_request("GET", "/incident/get", headers={"token": self._token}, params=params)
        return incident.get("result")

    def get_incident_workflow_request(self, incident_id: str) -> dict:
        """get incident workflow by sending a GET request.

        Args:
            incident_id: incident ID.

        Returns:
            Response from API.
        """
        params = {
            "type": "workflow",
            "incidentId": incident_id,
        }
        incident = self.http_request("GET", "/incident/get", headers={"token": self._token}, params=params)
        return incident.get("result")

    def get_incident_available_actions_request(self, incident_id: str) -> dict:
        """get incident available actions by sending a GET request.

        Args:
            incident_id: incident ID.

        Returns:
            Response from API.
        """
        params = {
            "type": "actions",
            "incidentId": incident_id,
        }
        incident = self.http_request("GET", "/incident/get", headers={"token": self._token}, params=params)
        return incident.get("result")

    def get_incident_attachments_request(
        self, incident_id, attachment_type: str = None, attachment_from: int = None, attachment_to: int = None
    ):
        """Get incident attachments by sending a GET request.

        Args:
            incident_id: Incident ID.
            attachment_type: The type of attachment to retrieve. Supported options are
            csv, pdf, and txt. Comma-separated values are supported.
            attachment_from: Start time for which to retrieve attachments. (in the format YYYY-MM-DDTHH:MM:SS format)
            attachment_to: End time for which to retrieve attachments. (in the in the format YYYY-MM-DDTHH:MM:SS format)
            format)

        Returns:
            Response from API.
        """
        params = {
            "incidentId": incident_id,
            "attachmenttype": attachment_type,
            "datefrom": attachment_from,
            "dateto": attachment_to,
        }
        remove_nulls_from_dictionary(params)
        attachment_res = self.http_request("GET", "/incident/attachments", headers={"token": self._token}, params=params)
        return attachment_res

    def perform_action_on_incident_request(self, incident_id, action: str, action_parameters: str) -> dict:
        """get incident available actions by sending a GET request.

        Args:
            incident_id: incident ID.
            action: action to perform on the incident.
            action_parameters: parameters needed in order to perform the action.

        Returns:
            Response from API.
        """

        params = {"type": "actionInfo", "incidentId": incident_id, "actionName": action}
        if action_parameters:
            action_parameters_dict = {k: v.strip('"') for k, v in [i.split("=", 1) for i in action_parameters.split(",")]}
            params.update(action_parameters_dict)

        possible_action = self.http_request("GET", "/incident/get", headers={"token": self._token}, params=params)

        if "error" in possible_action:
            err_msg = possible_action.get("error")
            raise Exception(
                f"Failed to perform the action {action} on incident {incident_id}.\nError from Securonix is: {err_msg}"
            )

        incident = self.http_request("POST", "/incident/actions", headers={"token": self._token}, params=params)
        return incident.get("result")

    def add_comment_to_incident_request(self, incident_id: str, comment: str) -> dict:
        """add comment to an incident by sending a POST request.

        Args:
            incident_id: incident ID.
            comment: action to perform on the incident

        Returns:
            Response from API.
        """
        params = {"incidentId": incident_id, "comment": comment, "actionName": "comment"}
        incident = self.http_request("POST", "/incident/actions", headers={"token": self._token}, params=params)
        return incident.get("result")

    def create_incident_request(
        self,
        violation_name: str,
        resource_group: str,
        resource_name: str,
        entity_type: str,
        entity_name: str,
        action_name: str,
        workflow: str = None,
        comment: str = None,
        criticality: str = None,
    ) -> dict:
        """create an incident by sending a POST request.

        Args:
            violation_name: violation or policy name.
            resource_group: resource group name.
            resource_name: resource name.
            entity_type: entity type.
            entity_name: entity name.
            action_name: action name.
            workflow: workflow name.
            comment: comment on the incident.
            criticality: criticality for the incident.

        Returns:
            Response from API.
        """
        params = {
            "violationName": violation_name,
            "datasourceName": resource_group,
            "resourceName": resource_name,
            "entityType": entity_type,
            "entityName": entity_name,
            "actionName": action_name,
        }
        if workflow:
            params["workflow"] = workflow
        if comment:
            params["comment"] = comment
        if criticality:
            params["criticality"] = criticality

        response = self.http_request("POST", "/incident/actions", headers={"token": self._token}, params=params)
        return response

    def list_watchlist_request(self):
        """list watchlists by sending a GET request.

        Returns:
            Response from API.
        """
        watchlists = self.http_request("GET", "/incident/listWatchlist", headers={"token": self._token})
        return watchlists.get("result")

    def get_watchlist_request(self, watchlist_name: str) -> dict:
        """Get a watchlist by sending a GET request.

        Args:
            watchlist_name: watchlist name.

        Returns:
            Response from API.
        """
        params = {
            "query": f'index=watchlist AND watchlistname="{watchlist_name}"',
        }
        watchlist = self.http_request("GET", "/spotter/index/search", headers={"token": self._token}, params=params)
        return watchlist

    def create_watchlist_request(self, watchlist_name: str, tenant_name: str) -> dict:
        """Create a watchlist by sending a POST request.

        Args:
            watchlist_name: watchlist name.
            tenant_name: Name of the tenant the watchlist belongs to.

        Returns:
            Response from API.
        """
        params = {"watchlistname": watchlist_name, "tenantname": tenant_name}
        remove_nulls_from_dictionary(params)
        watchlist = self.http_request(
            "POST", "/incident/createWatchlist", headers={"token": self._token}, params=params, response_type="text"
        )
        return watchlist

    def check_entity_in_watchlist_request(self, entity_name: str, watchlist_name: str) -> dict:
        """Check if an entity is whitelisted by sending a GET request.

        Args:
            entity_name: Entity name.
            watchlist_name: Watchlist name.

        Returns:
            Response from API.
        """
        params = {"entityId": entity_name, "watchlistname": watchlist_name}
        response = self.http_request("GET", "/incident/checkIfWatchlisted", headers={"token": self._token}, params=params)
        return response

    def add_entity_to_watchlist_request(self, watchlist_name: str, entity_type: str, entity_name: str, expiry_days: str) -> dict:
        """Check if an entity is whitelisted by sending a GET request.

        Args:
            watchlist_name: Watchlist name.
            entity_type: Entity type.
            entity_name: Entity name.
            expiry_days: Expiry in days.
        Returns:
            Response from API.
        """
        params = {
            "watchlistname": watchlist_name,
            "entityType": entity_type,
            "entityId": entity_name,
            "expirydays": expiry_days,
            "resourcegroupid": "-1",
        }
        watchlist = self.http_request(
            "POST", "/incident/addToWatchlist", headers={"token": self._token}, params=params, response_type="txt"
        )
        return watchlist

    def list_threats_request(
        self, from_epoch: int, to_epoch: int, tenant_name: str, offset: int = 0, max_incidents: int = 10
    ) -> dict:
        """List all threats by sending a GET request.

        Args:
            from_epoch: from time in epoch
            to_epoch: to time in epoch
            tenant_name: tenant name
            offset: A page number to fetch from
            max_incidents: max incidents to get

        Returns:
            Response from API.
        """
        params = {
            "datefrom": from_epoch,
            "dateto": to_epoch,
            "tenantname": tenant_name,
            "max": max_incidents,
            "offset": offset,
        }
        headers = {"token": self._token, "Accept": "application/vnd.snypr.app-v1.0+json"}

        remove_nulls_from_dictionary(params)
        response = self.http_request("GET", "/sccWidget/getThreats", headers=headers, params=params)
        return response.get("Response", {}).get("threats", {})

    def get_incident_activity_history_request(self, incident_id: str) -> list:
        """Get incident activity history by sending a GET request.

        Args:
            incident_id (str): Incident ID for which to retrieve the activity history.

        Returns:
            Response from API.
        """
        params = {
            "type": "activityStreamInfo",
            "incidentId": incident_id,
        }
        incident = self.http_request("GET", "/incident/get", headers={"token": self._token}, params=params)
        return incident.get("result", {}).get("activityStreamData", [])

    def list_whitelists_request(self, tenant_name: str) -> list:
        """Get a whitelist information by sending a GET request.

        Args:
            tenant_name: Name of the tenant the whitelist belongs to.

        Returns:
            Response from API.
        """
        params = {"tenantname": tenant_name}
        remove_nulls_from_dictionary(params)
        whitelist = self.http_request("GET", "/incident/getlistofWhitelist", headers={"token": self._token}, params=params)
        return whitelist.get("result", [])

    def get_whitelist_entry_request(self, tenant_name: str, whitelist_name: str) -> dict:
        """Get a whitelist information by sending a GET request.

        Args:
            tenant_name: Name of the tenant the whitelist belongs to.
            whitelist_name: Name of the whitelist.

        Returns:
            Response from API.
        """
        params = {"tenantname": tenant_name, "whitelistname": whitelist_name}
        remove_nulls_from_dictionary(params)
        whitelist = self.http_request("GET", "/incident/listWhitelistEntities", headers={"token": self._token}, params=params)
        return whitelist.get("result", {})

    def add_whitelist_entry_request(
        self,
        tenant_name: str,
        whitelist_name: str,
        whitelist_type: str,
        entity_type: str,
        entity_id: str,
        expiry_date: str,
        resource_name: str,
        resource_group_id: str,
        attribute_name: str,
        attribute_value: str,
        violation_type: str,
        violation_name: str,
    ):
        """Add entry in whitelist by sending a POST request.

        Args:
            tenant_name: Name of the tenant the whitelist belongs to.
            whitelist_name: Name of the whitelist.
            whitelist_type: Type of the whitelist.
            entity_type: Entity Type is required if whitelist is global.
            entity_id: Entity ID is required if whitelist is global.
            expiry_date: Expiry Date in format(MM/DD/YYYY).
            resource_name: Resource name which the account belongs to.
            resource_group_id: Resource Group ID which the account belongs to.
            attribute_name: Attribute name.
            attribute_value: Attribute Value.
            violation_type: Violation Type.
            violation_name: Violation Name.

        Returns:
            Response from API.
        """
        params = {
            "tenantname": tenant_name,
            "whitelistname": whitelist_name,
            "whitelisttype": whitelist_type,
            "entitytype": entity_type,
            "entityid": entity_id,
            "expirydate": expiry_date,
            "resourcename": resource_name,
            "resourcegroupid": resource_group_id,
            "attributename": attribute_name,
            "attributevalue": attribute_value,
            "violationtype": violation_type,
            "violationname": violation_name,
        }
        remove_nulls_from_dictionary(params)
        response = self.http_request("POST", "/incident/addToWhitelist", headers={"token": self._token}, params=params)
        return response

    def create_whitelist_request(self, tenant_name: str, whitelist_name: str, entity_type: str) -> dict:
        """Create a whitelist by sending a POST request.

        Args:
            tenant_name: Name of the tenant the whitelist belongs to.
            whitelist_name: Name of the whitelist.
            entity_type: Type of entity that the whitelist is intended to hold.

        Returns:
            Response from API.
        """
        params = {"tenantname": tenant_name, "whitelistname": whitelist_name, "entitytype": entity_type}
        remove_nulls_from_dictionary(params)
        whitelist = self.http_request("POST", "/incident/createGlobalWhitelist", headers={"token": self._token}, params=params)
        return whitelist

    def delete_whitelist_entry_request(
        self,
        tenant_name: str,
        whitelist_name: str,
        whitelist_type: str,
        entity_id: str,
        attribute_name: str,
        attribute_value: str,
    ) -> dict:
        """Delete a whitelist entry by sending POST request.

        Args:
            tenant_name: Name of the tenant the whitelist belongs to.
            whitelist_name: Name of the whitelist.
            whitelist_type: Type of whitelist that user wants to delete from.
            entity_id: Entity ID value that needs to be removed from the whitelist.
            attribute_name: Name of the attribute being removed.
            attribute_value: The value of the attribute being removed.

        Returns:
            Response from API.
        """
        params = {
            "tenantname": tenant_name,
            "whitelistname": whitelist_name,
            "whitelisttype": whitelist_type,
            "entityid": entity_id,
            "attributename": attribute_name,
            "attributevalue": attribute_value,
        }
        remove_nulls_from_dictionary(params)
        return self.http_request("GET", "/incident/removeFromWhitelist", headers={"token": self._token}, params=params)

    def delete_lookup_table_config_and_data_request(self, name: str) -> str:
        """Delete a lookup table and its configuration data from Securonix.

        Args:
            name (str): Name of the lookup table.

        Returns:
            str: Response from API.
        """
        params = {"lookupTableName": name}
        return self.http_request(
            "DELETE",
            "/lookupTable/deleteLookupConfigAndData",
            headers={"token": self._token},
            params=params,
            response_type="text",
        )

    def get_lookup_tables_request(self, max_records: int | None = 50, offset: int | None = 0) -> list:
        """Get the list of lookup tables stored on the Securonix platform.

        Args:
            max_records (Optional[int]): Number of records to return. Default value is 50.
            offset (Optional[int]): Specify from which record the data should be returned.

        Returns:
            Response from API.
        """
        params = {"max": max_records, "offset": offset}
        return self.http_request("GET", "/lookupTable/listLookupTables", headers={"token": self._token}, params=params)

    def add_entry_to_lookup_table_request(self, name: str, entries: list[dict], tenant_name: str | None = None) -> str:
        """Adds the provided entries to the specified lookup table.

        Args:
            name (str): Name of the lookup table in which to add the data.
            entries (List[Dict]): List of entries to add to the table.
            tenant_name (Optional[str]): Tenant name to which the lookup table belongs to.
        """
        body = {"lookupTableName": name, "tenantName": tenant_name, "lookupTableData": entries}
        remove_nulls_from_dictionary(body)
        return self.http_request(
            "POST", "/lookupTable/addLookupTableData", headers={"token": self._token}, json=body, response_type="text"
        )

    def list_lookup_table_entries_request(
        self,
        name: str,
        query: str | None = None,
        attribute: str | None = "key",
        max_records: int | None = 15,
        offset: int | None = 0,
        page_num: int | None = 1,
        sort: str | None = None,
        order: str | None = "asc",
    ) -> list:
        """List the entries of the lookup table.

        Args:
            name (str): Name of the lookup table.
            query (Optional[str], optional): Query to filter the entries of the lookup table. Defaults to None.
            attribute (Optional[str], optional): Column name on which to filter the data. Defaults to 'key'.
            max_records (Optional[int], optional): Number of records to retrieve. Defaults to 15.
            offset (Optional[int], optional): Specify from which record the data should be returned. Defaults to 0.
            page_num (Optional[int], optional): Specify a value to retrieve the records from a specified page.
                Defaults to 1.
            sort (Optional[str]): Name of the column on which to sort the data.
            order (Optional[str]): The order in which to sort the data.

        Returns:
            List: List of lookup table entries.
        """
        headers = {"token": self._token, "Content-Type": "application/json"}

        body = {
            "lookupTableName": name,
            "query": query,
            "attribute": attribute,
            "max": max_records,
            "offset": offset,
            "pagenum": page_num,
            "sort": sort,
            "order": order,
        }
        remove_nulls_from_dictionary(body)
        payload = json.dumps(body)

        return self.http_request("GET", "/lookupTable/getLookupTableData", headers=headers, data=payload)

    def create_lookup_table_request(
        self, tenant_name: str, name: str, scope: str, field_names: list, encrypt: list, key: list
    ) -> dict:
        """Create a lookup table by sending a POST request.

        Args:
            tenant_name: Name of the tenant the whitelist belongs to.
            name: Lookup table name.
            scope: Scope of lookup table.
            field_names: Field names for lookup table.
            encrypt: Field name which data needs to be encrypted.
            key: Field name to be used as key.

        Returns:
            Response from API.
        """
        data: dict[str, Any] = {"lookupTableName": name, "lookupTableScope": scope, "tenantName": tenant_name}
        field_list: list = []
        for field in field_names:
            field_dic = {"fieldName": field, "encrypt": field in encrypt, "key": field in key}
            field_list.append(field_dic)
        data.update({"lookupFieldList": field_list})
        remove_nulls_from_dictionary(data)
        response = self.http_request(
            "POST", "/lookupTable/createLookupTable", headers={"token": self._token}, json=data, response_type="text"
        )
        return response

    def delete_lookup_table_entries(self, name: str, lookup_unique_keys: list[str]) -> str:
        """Delete entries from the lookup table.

        Args:
            name (str): Name of the lookup table.
            lookup_unique_keys (List[str]): List of keys to delete from the lookup table.

        Returns:
            str: Response from API.
        """
        data: dict[str, Any] = {"lookupTableName": name, "keyList": lookup_unique_keys}
        response = self.http_request(
            "DELETE", "/lookupTable/deleteLookupKeys", headers={"token": self._token}, json=data, response_type="text"
        )
        return response


def remove_nulls_from_dictionary(data):
    """
        Remove Null values from a dictionary. (updating the given dictionary)

        :type data: ``dict``
        :param data: The data to be added to the context (required)

        :return: No data returned
        :rtype: ``None``
    """
    list_of_keys = list(data.keys())[:]
    for key in list_of_keys:
        if data[key] in ('', None, [], {}, ()):
            del data[key]

def encode_string_results(text):
    """
    Encode string as utf-8, if any unicode character exists.

    :param text: string to encode
    :type text: str
    :return: encoded string
    :rtype: str
    """
    if not isinstance(text, STRING_OBJ_TYPES):
        return text
    try:
        return str(text)
    except UnicodeEncodeError:
        return text.encode("utf8", "replace")


def arg_to_number(arg, arg_name=None, required=False):
    # type: (Any, Optional[str], bool) -> Optional[int]
    """Converts an XSOAR argument to a Python int

    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``int`` type. It will throw a ValueError
    if the input is invalid. If the input is None, it will throw a ValueError
    if required is ``True``, or ``None`` if required is ``False.

    :type arg: ``Any``
    :param arg: argument to convert

    :type arg_name: ``str``
    :param arg_name: argument name

    :type required: ``bool``
    :param required:
        throws exception if ``True`` and argument provided is None

    :return:
        returns an ``int`` if arg can be converted
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    :rtype: ``Optional[int]``
    """

    if arg is None or arg == '':
        if required is True:
            if arg_name:
                raise ValueError('Missing "{}"'.format(arg_name))
            else:
                raise ValueError('Missing required argument')

        return None

    arg = encode_string_results(arg)

    if isinstance(arg, str):
        if arg.isdigit():
            return int(arg)

        try:
            return int(float(arg))
        except Exception:
            if arg_name:
                raise ValueError('Invalid number: "{}"="{}"'.format(arg_name, arg))
            else:
                raise ValueError('"{}" is not a valid number'.format(arg))
    if isinstance(arg, int):
        return arg

    if arg_name:
        raise ValueError('Invalid number: "{}"="{}"'.format(arg_name, arg))
    else:
        raise ValueError('"{}" is not a valid number'.format(arg))


def argToBoolean(value):
    """
        Boolean-ish arguments that are passed through demisto.args() could be type bool or type string.
        This command removes the guesswork and returns a value of type bool, regardless of the input value's type.
        It will also return True for 'yes' and False for 'no'.

        :param value: the value to evaluate
        :type value: ``string|bool``

        :return: a boolean representation of 'value'
        :rtype: ``bool``
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, STRING_OBJ_TYPES):
        if value.lower() in ('y', 'yes', 't', 'true', 'on', '1'):
            return True
        elif value.lower() in ('n', 'no', 'f', 'false', 'off', '0'):
            return False
        else:
            raise ValueError('Argument does not contain a valid boolean-like value')
    else:
        raise ValueError('Argument is neither a string nor a boolean')

def argToList(arg, separator=',', transform=None):
    """
       Converts a string representation of args to a python list

       :type arg: ``str`` or ``list``
       :param arg: Args to be converted (required)

       :type separator: ``str``
       :param separator: A string separator to separate the strings, the default is a comma.

       :type transform: ``callable``
       :param transform: A function transformer to transfer the returned list arguments.

       :return: A python list of args
       :rtype: ``list``
    """
    if not arg:
        return []

    result = []
    if isinstance(arg, list):
        result = arg
    elif isinstance(arg, STRING_TYPES):
        is_comma_separated = True
        if arg[0] == '[' and arg[-1] == ']':
            try:
                result = json.loads(arg)
                is_comma_separated = False
            except Exception:
                demisto.debug('Failed to load {} as JSON, trying to split'.format(arg))  # type: ignore[str-bytes-safe]
        if is_comma_separated:
            result = [s.strip() for s in arg.split(separator)]
    else:
        result = [arg]

    if transform:
        return [transform(s) for s in result]

    return result

def date_to_timestamp(date_str_or_dt, date_format='%Y-%m-%dT%H:%M:%S'):
    """
      Parses date_str_or_dt in the given format (default: %Y-%m-%dT%H:%M:%S) to milliseconds
      Examples: ('2018-11-06T08:56:41', '2018-11-06T08:56:41', etc.)

      :type date_str_or_dt: ``str`` or ``datetime.datetime``
      :param date_str_or_dt: The date to be parsed. (required)

      :type date_format: ``str``
      :param date_format: The date format of the date string (will be ignored if date_str_or_dt is of type
        datetime.datetime). (optional)

      :return: The parsed timestamp.
      :rtype: ``int``
    """
    if isinstance(date_str_or_dt, STRING_OBJ_TYPES):
        return int(time.mktime(safe_strptime(date_str_or_dt, date_format, time.strptime)) * 1000)

    # otherwise datetime.datetime
    return int(time.mktime(date_str_or_dt.timetuple()) * 1000)

def parse_date_range(date_range, date_format=None, to_timestamp=False, timezone=0, utc=True):
    """
        THIS FUNCTTION IS DEPRECATED - USE dateparser.parse instead

      Parses date_range string to a tuple date strings (start, end). Input must be in format 'number date_range_unit')
      Examples: (2 hours, 4 minutes, 6 month, 1 day, etc.)

      :type date_range: ``str``
      :param date_range: The date range to be parsed (required)

      :type date_format: ``str``
      :param date_format: Date format to convert the date_range to. (optional)

      :type to_timestamp: ``bool``
      :param to_timestamp: If set to True, then will return time stamp rather than a datetime.datetime. (optional)

      :type timezone: ``int``
      :param timezone: timezone should be passed in hours (e.g if +0300 then pass 3, if -0200 then pass -2).

      :type utc: ``bool``
      :param utc: If set to True, utc time will be used, otherwise local time.

      :return: The parsed date range.
      :rtype: ``(datetime.datetime, datetime.datetime)`` or ``(int, int)`` or ``(str, str)``
    """
    range_split = date_range.strip().split(' ')
    if len(range_split) != 2:
        return_error('date_range must be "number date_range_unit", examples: (2 hours, 4 minutes,6 months, 1 day, '
                     'etc.)')

    try:
        number = int(range_split[0])
    except ValueError:
        return_error('The time value is invalid. Must be an integer.')

    unit = range_split[1].lower()
    if unit not in ['minute', 'minutes',
                    'hour', 'hours',
                    'day', 'days',
                    'month', 'months',
                    'year', 'years',
                    ]:
        return_error('The unit of date_range is invalid. Must be minutes, hours, days, months or years.')

    if not isinstance(timezone, (int, float)):
        return_error('Invalid timezone "{}" - must be a number (of type int or float).'.format(timezone))

    if utc:
        utc_now = datetime.utcnow()
        end_time = utc_now + timedelta(hours=timezone)
        start_time = utc_now + timedelta(hours=timezone)
    else:
        now = datetime.now()
        end_time = now + timedelta(hours=timezone)
        start_time = now + timedelta(hours=timezone)

    if 'minute' in unit:
        start_time = end_time - timedelta(minutes=number)
    elif 'hour' in unit:
        start_time = end_time - timedelta(hours=number)
    elif 'day' in unit:
        start_time = end_time - timedelta(days=number)
    elif 'month' in unit:
        start_time = end_time - timedelta(days=number * 30)
    elif 'year' in unit:
        start_time = end_time - timedelta(days=number * 365)

    if to_timestamp:
        return date_to_timestamp(start_time), date_to_timestamp(end_time)

    if date_format:
        return datetime.strftime(start_time, date_format), datetime.strftime(end_time, date_format)

    return start_time, end_time

def arg_to_datetime(arg, arg_name=None, is_utc=True, required=False, settings=None):
    # type: (Any, Optional[str], bool, bool, dict) -> Optional[datetime]
    """Converts an XSOAR argument to a datetime

    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``datetime``. It will throw a ValueError if the input is invalid.
    If the input is None, it will throw a ValueError if required is ``True``,
    or ``None`` if required is ``False.

    :type arg: ``Any``
    :param arg: argument to convert

    :type arg_name: ``str``
    :param arg_name: argument name

    :type is_utc: ``bool``
    :param is_utc: if True then date converted as utc timezone, otherwise will convert with local timezone.

    :type required: ``bool``
    :param required:
        throws exception if ``True`` and argument provided is None

    :type settings: ``dict``
    :param settings: If provided, passed to dateparser.parse function.

    :return:
        returns an ``datetime`` if conversion works
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    :rtype: ``Optional[datetime]``
    """

    if arg is None:
        if required is True:
            if arg_name:
                raise ValueError('Missing "{}"'.format(arg_name))
            else:
                raise ValueError('Missing required argument')
        return None

    if isinstance(arg, str) and arg.isdigit() or isinstance(arg, (int, float)):
        # timestamp is a str containing digits - we just convert it to int
        ms = float(arg)
        if ms > 2000000000.0:
            # in case timestamp was provided as unix time (in milliseconds)
            ms = ms / 1000.0

        if is_utc:
            return datetime.fromtimestamp(ms, tz=timezone.utc)
        else:
            return datetime.fromtimestamp(ms)
    if isinstance(arg, str):
        # we use dateparser to handle strings either in ISO8601 format, or
        # relative time stamps.
        # For example: format 2019-10-23T00:00:00 or "3 days", etc
        if settings:
            date = dateparser.parse(arg, settings=settings)  # type: ignore[arg-type]
        else:
            date = dateparser.parse(arg, settings={'TIMEZONE': 'UTC'})

        if date is None:
            # if d is None it means dateparser failed to parse it
            if arg_name:
                raise ValueError('Invalid date: "{}"="{}"'.format(arg_name, arg))
            else:
                raise ValueError('"{}" is not a valid date'.format(arg))

        return date

    if arg_name:
        raise ValueError('Invalid date: "{}"="{}"'.format(arg_name, arg))
    else:
        raise ValueError('"{}" is not a valid date'.format(arg))


def return_error(message):
    print(f"ERROR: {message}")
    traceback.print_exc()
    sys.exit(1)
    
def return_results(results):
    if results is not None:
        print(results)

def return_outputs(readable_output, outputs=None, raw_response=None, **kwargs):
    if readable_output is not None:
        print(readable_output)
    elif raw_response is not None:
        print(raw_response)
    elif outputs is not None:
        print(outputs)
        
def validate_configuration_parameters(params: dict[str, Any]):
    """
    Check whether entered configuration parameters are valid or not.

    :type: params: dict
    :param: Dictionary of demisto configuration parameter

    :return: raise ValueError if any configuration parameter is not in valid format else returns None
    :rtype: None
    """
    fetch_time = params.get("fetch_time")
    max_fetch = params.get("max_fetch")
    # Validate empty values
    if fetch_time is None:
        raise ValueError("Please provide First fetch time")
    if max_fetch is None:
        raise ValueError("Please provide max_fetch")
    # validate max_fetch
    arg_to_number(max_fetch, arg_name="max_fetch")
    # validate first_fetch parameter
    arg_to_datetime(fetch_time, "First fetch time")

def list_incidents_request(
        self, from_epoch: str, to_epoch: str, incident_status: str, max_incidents: str = "200", offset: str = "0"
    ) -> dict:
        """List all incidents by sending a GET request.

        Args:
            from_epoch: from time in epoch
            to_epoch: to time in epoch
            incident_status: incident status e.g:closed, opened
            max_incidents: max incidents to get
            offset: offset to be used

        Returns:
            Response from API.
        """
        headers = {"token": self._token, "Accept": "application/vnd.snypr.app-v6.0+json"}
        params = {
            "type": "list",
            "from": from_epoch,
            "to": to_epoch,
            "rangeType": incident_status,
            "max": max_incidents,
            "order": "asc",
            "offset": offset,
        }
        incidents = self.http_request("GET", "/incident/get", headers=headers, params=params)
        return incidents.get("result").get("data")

def test_module(client: Client, params: dict) -> str:
    """
    Performs basic get request to get incident samples
    """
    client.list_workflows_request()

    if params.get("isFetch"):
        validate_configuration_parameters(params)
#        validate_mirroring_parameters(params=params)

        timestamp_format = "%Y-%m-%dT%H:%M:%S.%fZ"
        from_epoch = date_to_timestamp(parse_date_range("1 day", utc=True)[0], date_format=timestamp_format)
        to_epoch = date_to_timestamp(datetime.now(), date_format=timestamp_format)
        client.list_incidents_request(from_epoch, to_epoch, incident_status="opened")

    return "ok"

def get_mirroring(params) -> dict:
    """Add mirroring related keys in an incident.

    Returns:
        Dict: A dictionary containing required key-value pairs for mirroring.
    """
    # Fetch the integration configuration parameters to determine the flow of the mirroring and mirror tags.
    mirror_direction = params.get("mirror_direction", "None").strip()
    mirror_tags = params.get("comment_tag", "").strip()

    return {
        "mirror_direction": MIRROR_DIRECTION.get(mirror_direction),
        "mirror_instance": "securonix",
        "mirror_tags": mirror_tags,
    }

def get_incident_name(incident: dict, incident_id: str, violator_id: str) -> str:
    """Get the incident name by concatenating the incident reasons if possible

    Args:
        incident: incident details
        incident_id: the incident id
        violator_id: the violator id

    Returns:
        incident name.
    """
    incident_reasons = incident.get("reason", [])
    try:
        incident_reason = ""
        for reason in incident_reasons:
            if isinstance(reason, str):
                if reason.startswith("Threat Model: "):
                    incident_reason += f"{reason[14:]}, "
                if reason.startswith("Policy: "):
                    incident_reason += f"{reason[8:]}, "
        if incident_reason:
            # Remove ", " last chars and concatenate with the incident ID
            incident_name = f"{incident_reason[:-2]}: {incident_id}"
        else:
            incident_name = f"Securonix Incident {incident_id}, Violator ID: {violator_id}"
    except ValueError:
        incident_name = f"Securonix Incident: {incident_id}."

    return incident_name

def escape_spotter_query(original_query: str) -> str:
    """Escape the special characters of the spotter query provided from Securonix Incident.

    Args:
        original_query: The original spotter query provided from Securonix Incident

    Returns:
        str: The spotter query escaped for special characters.
    """
    escaped_query = original_query
    for special_char in SPOTTER_SPECIAL_CHARACTERS:
        escaped_query = escaped_query.replace(special_char, f"\\{special_char}")
    return escaped_query

def list_violation_data(client: Client, args) -> list:
    """List violation data.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    from_ = args.get("from", "").strip()
    to_ = args.get("to", "").strip()
    query = escape_spotter_query(args.get("query", "").strip())
    query_id = args.get("query_id", "").strip()
    max_violations = arg_to_number(args.get("max", "1000"))

    if max_violations is not None and max_violations <= 0:
        raise ValueError(MESSAGE["INVALID_MAX_VALUE"])

    violation_data = client.list_violation_data_request(from_, to_, query, query_id, max_violations)

    if violation_data.get("error"):
        raise Exception(
            f"Failed to get violation data in the given time frame.\n"
            f"Error from Securonix is: {violation_data.get('errorMessage')}"
        )
    violation_events = violation_data.get("events")
    if len(violation_events) > 0:  # type: ignore[arg-type]
        violation_readables, violation_outputs = parse_data_arr(violation_events)
        headers = ["EventID", "Eventtime", "Message", "Policyname", "Accountname"]
        human_readable = tableToMarkdown(
            name="Activity data:",
            t=[
                {key: string_escape_MD(value) for key, value in violation_readable.items()}
                for violation_readable in violation_readables
            ],
            headers=headers,
            removeNull=True,
        )

        data = {
            "totalDocuments": violation_data.get("totalDocuments"),
            "message": violation_data.get("message"),
            "queryId": violation_data.get("queryId"),
        }

        return [
        {
            "outputs": remove_empty_elements(violation_outputs),
            "raw_response": violation_data,
        },
        {
            "outputs": remove_empty_elements(data),
            "readable_output": f"#### Next page query id: {data.get('queryId')}",
        }
    ]
    else:
        return ["There are no violation events."]


def run_polling_command(client, args: dict, command_name: str, search_function: Callable):
    """
    For Scheduling command.

    Args:
        client: Client object with request.
        args: Command arguments.
        command_name: Name of the command.
        search_function: Callable object of command.

    Returns:
        Outputs.
    """
    command_results = []
    result = search_function(client, args)
    command_results.append(result)
    outputs = result[0]["raw_response"].get("events")
    delay_type = client.get_securonix_retry_delay_type()
    retry_count: int = client.get_securonix_retry_count()
    retry_delay: int = client.get_securonix_retry_delay()

    if len(outputs) == 0 and retry_count > 0:
        if delay_type == "Exponential":
            retry_delay = client.get_securonix_retry_delay() * 2
        retry_timeout: int = retry_delay * retry_count + retry_count * 1
        policy_type = args.get("policy_type", "").strip().upper()
        if policy_type in POLICY_TYPES_TO_RETRY:
            args["to"] = datetime.now().astimezone(timezone.utc).strftime(r"%m/%d/%Y %H:%M:%S")
        polling_args = {"polling": True, **args}
        scheduled_command = ScheduledCommand(
            command=command_name, next_run_in_seconds=retry_delay, args=polling_args, timeout_in_seconds=retry_timeout
        )
        command_results.append(scheduled_command=scheduled_command)
        return command_results
    return result


def fetch_securonix_incident(
    client: Client,
    fetch_time: str | None,
    incident_status: str,
    default_severity: str,
    max_fetch: str,
    last_run: dict,
    close_incident: bool,
    params: dict,
    integration_id: int,
) -> list:
    """Uses to fetch incidents into Demisto
    Documentation: https://github.com/demisto/content/tree/master/docs/fetching_incidents

    Args:
        client: Client object with request
        fetch_time: From when to fetch if first time, e.g. `3 days`
        incident_status: Incident statuses to fetch, can be: all, opened, closed, updated
        default_severity: Default incoming incident severity
        last_run: Last fetch object.
        max_fetch: maximum amount of incidents to fetch
        close_incident: Close respective Securonix incident.

    Returns:
        incidents, new last_run
    """
    timestamp_format = "%Y-%m-%dT%H:%M:%S.%fZ"
    if not last_run:  # if first time running
        new_last_run = {
            "from": int(
                arg_to_datetime(fetch_time, arg_name="First fetch time range").timestamp() * 1000  # type: ignore
            ),
            "to": int(datetime.now(tz=timezone.utc).timestamp() * 1000),
            "offset": 0,
        }
        print(f"No last run object found, creating new last run object with value: {json.dumps(new_last_run)}")
    elif "time" in last_run:
        print("Upgrading the last run object.")
        new_last_run = last_run
        new_last_run["from"] = date_to_timestamp(last_run.get("time"), date_format=timestamp_format)
        new_last_run["to"] = int(datetime.now(tz=timezone.utc).timestamp() * 1000)
        new_last_run["offset"] = 0
        del new_last_run["time"]
    else:
        new_last_run = last_run
        print("Using the last run object got from the previous run.")

    demisto_incidents: list = []

    from_epoch = new_last_run.get("from")
    to_epoch = new_last_run.get("to")
    offset = new_last_run.get("offset")
    print(f"Fetching Securonix incidents. From: {from_epoch}. To: {to_epoch}. Offset: {offset}")

    if incident_status.lower() == "all":
        incident_status = "updated"

    securonix_incidents = client.list_incidents_request(
        from_epoch=str(from_epoch),
        to_epoch=str(to_epoch),
        incident_status=incident_status,
        max_incidents=max_fetch,
        offset=str(offset),
    )

    if securonix_incidents:
        already_fetched: list[str] = new_last_run.get("already_fetched", [])  # type: ignore
        incident_items = securonix_incidents.get("incidentItems", [])

        for incident in incident_items:
            incident_id = str(incident.get("incidentId", 0))
            violator_id = str(incident.get("violatorId", 0))
            reasons = incident.get("reason", [])
            policy_list: list[str] = []
            policy_stages_json = {}
            policy_stages_table = []
            if isinstance(reasons, list):
                for reason in reasons:
                    if isinstance(reason, str) and "PolicyType" in reason:
                        policy_type = reason.split(":")[-1].strip()
                        incident["policy_type"] = policy_type
                    if isinstance(reason, dict) and "Policies" in reason:
                        # Parse the policies.
                        policies = reason.get("Policies")
                        if not isinstance(policies, dict):
                            continue
                        policy_keys = list(policies.keys())
                        policy_keys.sort()
                        for stage_key in policy_keys:
                            stage_dict = policies.get(stage_key)
                            if not stage_dict or not isinstance(stage_dict, dict):
                                continue
                            stage_name = list(stage_dict.keys())[0]
                            stage_policies: list[str] = stage_dict.get(stage_name)  # type: ignore
                            if not stage_policies or not isinstance(stage_policies, list):
                                continue
                            stage_policies_str = ", ".join(str(policy) for policy in stage_policies)  # type: ignore
                            policy_list.extend(stage_policies)  # type: ignore
                            policy_stages_json[f"{stage_key}:{stage_name}"] = stage_policies  # noqa: E231
                            policy_stages_table.append(
                                {"Stage Name": f"{stage_key}:{stage_name}", "Policies": stage_policies_str}  # noqa: E231
                            )

            if policy_list:
                # Add the parsed policies to the incident.
                incident["policy_list"] = list(dict.fromkeys(policy_list))
                incident["policy_stages_json"] = policy_stages_json
                incident["policy_stages_table"] = policy_stages_table

            if incident_id not in already_fetched:
                incident.update(get_mirroring(params))

                if close_incident:
                    incident["close_sx_incident"] = True
                else:
                    incident["close_sx_incident"] = False

                incident_name = get_incident_name(incident, incident_id, violator_id)
                
                violation_query = incident.get("solrquery")
                from_time, to_time = extract_time_range(violation_query)
                print(violation_query)
                print(from_time)
                print(to_time)
                
                args = {
                    "from": from_time,
                    "to": to_time,
                    "query": violation_query,
                    "query_id": "",
                    "max": "2"
                }
                
                events = run_polling_command(
                    client=client,
                    args=args,
                    search_function=list_violation_data,
                    command_name="securonix-list-violation-data",
                )
                
                raw_events = events[0]['outputs']
                #print(raw_events)
                total_violations = events[0]['raw_response']['totalDocuments']
                #print(total_violations)
                incident['totalViolations'] = total_violations               
                incident['violations'] = raw_events

                #print(incident)
                incident_row = {
                    "name": incident_name,
                    "type": "securonix",
                    "occurred_at": timestamp_to_datestring(incident.get("lastUpdateDate")),
                    "rawJSON": json.dumps(incident),
                }
                print(incident_row)
                
                insert_incident_row_in_supabase(incident=incident_row)
                
                demisto_incidents.append(
                    {
                        "name": incident_name,
                        "occurred": timestamp_to_datestring(incident.get("lastUpdateDate")),
                        "severity": incident.get("priority"),
                        "rawJSON": json.dumps(incident),
                    }
                )

                already_fetched.append(str(incident_id))

        # If incidents returned from API, then only update the offset value.
        if incident_items:
            new_offset = offset + len(incident_items)  # type: ignore
            new_from = from_epoch
            new_to = to_epoch
            print(f"Updating the offset to {new_offset}.")
        # Else, reset the value of offset. From value would be the to_epoch of previous run.
        # And, To value would be current timestamp.
        else:
            new_offset = 0
            new_from = to_epoch
            new_to = int(datetime.now(tz=timezone.utc).timestamp() * 1000)
            print(f"Resetting the offset to 0. New From is {new_from}. New To is {new_to}.")

        new_last_run.update(
            {
                "from": new_from,  # type: ignore
                "to": new_to,  # type: ignore
                "offset": new_offset,
                "already_fetched": already_fetched,  # type: ignore
            }
        )
        print(new_last_run)
    
    update_last_run_in_supabase(integration_id=integration_id,last_run=new_last_run)    
    #demisto.setLastRun({"value": json.dumps(new_last_run)})

    print(f"Creating {len(demisto_incidents)} new incidents.")
    return demisto_incidents

def get_supabase_client() -> Client:
    """
    Create and return a Supabase client instance
    
    Returns:
        Client: Supabase client instance
        
    Raises:
        RuntimeError: If Supabase is not available or credentials are missing
    """
    if not SUPABASE_AVAILABLE:
        raise RuntimeError("Supabase client is not available. Please install it with: pip install supabase")
    
    if not SUPABASE_URL or not SUPABASE_ANON_KEY:
        raise RuntimeError("Supabase credentials not found. Please set SUPABASE_URL and SUPABASE_ANON_KEY environment variables")
    
    try:
        return create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
    except Exception as e:
        raise RuntimeError(f"Failed to create Supabase client: {str(e)}") from e

def get_supabase_params(integration_id: int) -> dict:
    """
    Fetch integration parameters from Supabase integration_instances table
    
    Args:
        integration_id (int): The ID of the integration instance
        
    Returns:
        dict: Parameters dictionary for the integration
        
    Raises:
        RuntimeError: If Supabase is not available or connection fails
    """
    print(f"Fetching parameters for integration_id: {integration_id}")
    
    try:
        # Create Supabase client
        supabase = get_supabase_client()
        
        # Fetch integration instance data
        print(f"Querying Supabase for integration_id: {integration_id}")
        response = supabase.table('integration_instances').select('*').eq('integration_id', integration_id).execute()
        print(f"Supabase response: {len(response.data) if response.data else 0} records found")
        
        if not response.data:
            raise ValueError(f"No integration instance found with ID: {integration_id}")
        
        instance_data = response.data[0]
        print(f"Raw instance data keys: {list(instance_data.keys())}")
        
        # Extract configuration from the JSON column
        configuration = instance_data.get('configuration', {})
        
        # Map the configuration fields to the expected parameter format
        params = {
        # Connection
        "tenant": "a3t7vabb",
        "tenant_name": "",
        "host": "",
        "username": "shubham.k",
        "password": "Network@5714",

        # Network / security
        "unsecure": True,
        "proxy": False,

        # Retry / backoff
        "securonix_retry_count": 3,
        "securonix_retry_delay_type": "Exponential",
        "securonix_retry_delay": 60,

        # Fetch / incident behavior
        "fetch_time": "24 hour",
        "max_fetch": 200,
        "incident_status": "opened",
        "default_severity": "Medium",
        "close_incident": False,

        # Mirroring / remote
        "close_states_of_securonix": "",
        "entity_type_to_fetch": "Incident",
        "isFetch": True,
    }
        
        print("Successfully mapped parameters from Supabase")
        print(f"Key mapped values: server={params.get('server')}, query={params.get('query')}, offenses_per_fetch={params.get('offenses_per_fetch')}")
        return params
        
    except Exception as e:
        raise RuntimeError(f"Failed to fetch parameters from Supabase: {str(e)}") from e
    
def get_last_run_from_supabase(integration_id: int) -> int:
    """
    Fetch the last_run from Supabase integration_instances table
    
    Args:
        integration_id (int): The ID of the integration instance
        
    Returns:
        int: The last_run, or {} if not found
    """
    
    try:
        supabase = get_supabase_client()

        response = (
            supabase
            .table('integration_instances')
            .select('last_run')
            .eq('id', integration_id)
            .execute()
        )
        print(response)

        if response.data and len(response.data) > 0:
            last_run = response.data[0].get('last_run')
            # Normalize None → {}
            if last_run is None:
                last_run = {}

            print(f"Fetched last_run from Supabase: {last_run}")
            return last_run

        print("No integration instance found, using default last_run")
        return {}

    except Exception as e:
        print(f"Error fetching last_run from Supabase: {str(e)}")
        print("Using default last_run")
        return {}

def update_last_run_in_supabase(integration_id: int, last_run: dict) -> None:
    """
    Update the last_run in Supabase integration_instances table
    
    """
    try:
        supabase = get_supabase_client()
        
        # Update last_highest_id in the integration_instances table
        response = supabase.table('integration_instances').update({'last_run': last_run}).eq('id', integration_id).execute()
        
        if response.data:
            print(f"Updated last_run in Supabase: {last_run}")
        else:
            print("Failed to update last_run in Supabase")
            
    except Exception as e:
        print(f"Error updating last_run in Supabase: {str(e)}")
        
def insert_incident_row_in_supabase(incident: dict) -> None:
    """
    Insert a single incident row into a Supabase table.

    """

    try:
        supabase = get_supabase_client()
        response = (
            supabase
            .table("dev_tickets")
            .insert(incident)   # single row, no list needed
            .execute()
        )

        if response.data:
            print("Incident row inserted successfully")
        else:
            print("Incident insert returned no data")

    except Exception as e:
        print(f"Error inserting incident row: {e}")

def main(integration_id: int = None, command: str = None) -> None:
#instance id, command, row number for command results

    if integration_id is None:
        raise ValueError("Integration ID is required. Usage: main(integration_id=1, command='test-module')")
    
    # Use provided command or default to test-module
    if command is None:
        command = "test-module"  # Default command
    
    # Fetch parameters from Supabase
    try:
        params = get_supabase_params(integration_id)
        print("Successfully fetched parameters from Supabase")
        print(f"Parameters received: {list(params.keys())}")
        print(f"Key parameters: server={params.get('server')}, query={params.get('query')}, offenses_per_fetch={params.get('offenses_per_fetch')}")
    except Exception as e:
        print(f"Error fetching parameters: {str(e)}")
        # FALLBACK DISABLED: Commented out static params fallback
        # print("Falling back to static parameters...")
        # params = STATIC_PARAMS
        raise RuntimeError(f"Failed to fetch parameters from Supabase: {str(e)}")
    
    print(f"Executing command: {command}")

    remove_nulls_from_dictionary(params)

    host = params.get("host", None)
    tenant = params.get("tenant")
    if not host:
        server_url = tenant
        if not tenant.startswith("http://") and not tenant.startswith("https://"):
            server_url = f"https://{tenant}"  # noqa: E231
        if not tenant.endswith(".securonix.net/Snypr/ws/"):
            server_url += ".securonix.net/Snypr/ws/"
    else:
        host = host.rstrip("/")
        if not host.endswith("/ws"):
            host += "/ws/"
        server_url = host

    username = params.get("username")
    password = params.get("password")
    verify = not params.get("unsecure", False)
    proxy = params.get("proxy")
    # Updating TOTAL_RETRY_COUNT to get user provided value
    global TOTAL_RETRY_COUNT
    TOTAL_RETRY_COUNT = arg_to_number(
        params.get("securonix_retry_count", "0"),  # type: ignore
        arg_name="securonix_retry_count",
    )
    TOTAL_RETRY_COUNT = min(TOTAL_RETRY_COUNT, 5)
    securonix_retry_delay_type = params.get("securonix_retry_delay_type", "Exponential")
    securonix_retry_delay = arg_to_number(params.get("securonix_retry_delay", "30"), arg_name="securonix_retry_delay")
    if securonix_retry_delay <= 30:  # type: ignore
        securonix_retry_delay = 30
    elif securonix_retry_delay >= 300:  # type: ignore
        securonix_retry_delay = 300
    if securonix_retry_delay_type == "Exponential":
        securonix_retry_delay = int(securonix_retry_delay / 2)  # type: ignore
    # Create a state mapping from XSOAR to Securonix.
#    create_xsoar_to_securonix_state_mapping(params)

    command = "fetch-incidents"
    print(f"Command being called in Securonix is: {command}")

    try:
        client = Client(
            tenant=tenant,
            server_url=server_url,
            username=username,
            password=password,
            verify=verify,
            proxy=proxy,
            securonix_retry_count=TOTAL_RETRY_COUNT,  # type: ignore
            securonix_retry_delay=securonix_retry_delay,  # type: ignore[arg-type]
            securonix_retry_delay_type=securonix_retry_delay_type,
        )
        commands: dict[str, Callable[[Client, dict[str, str]], tuple[str, dict[Any, Any], dict[Any, Any]]]] = {
#           "securonix-list-workflows": list_workflows,
        }
        if command == "fetch-incidents":
 #           validate_mirroring_parameters(params=params)

            fetch_time = params.get("fetch_time", "1 hour")
            tenant_name = params.get("tenant_name")
            incident_status = params.get("incident_status") if "incident_status" in params else "opened"
            default_severity = params.get("default_severity", "")
            max_fetch_ = arg_to_number(params.get("max_fetch", "200"), arg_name="max_fetch")
            max_fetch = str(min(200, max_fetch_))  # type: ignore
            last_run = get_last_run_from_supabase(integration_id)
            #last_run = {}
            #{'from': 1766601499218, 'to': 1766664499219, 'offset': 1, 'already_fetched': ['70']}
            close_incident = argToBoolean(params.get("close_incident", False))

            if params.get("entity_type_to_fetch") == "Threat":
                incidents = fetch_securonix_threat(client, fetch_time, tenant_name, max_fetch, last_run=last_run)
            else:
                incidents = fetch_securonix_incident(
                    client,
                    fetch_time,
                    incident_status,
                    default_severity,
                    max_fetch,
                    last_run=last_run,
                    close_incident=close_incident,
                    params = params,
                    integration_id = integration_id,
                )

            print(incidents)
        elif command == "securonix-list-violation-data":
            return_results(
                run_polling_command(
                    client=client,
                    args=demisto.args(),
                    search_function=list_violation_data,
                    command_name="securonix-list-violation-data",
                )
            )
        elif command == "test-module":
            print(test_module(client,params))
        elif command == "securonix-incident-attachment-get":
            return_results(get_incident_attachments(client=client, args=demisto.args()))
        elif command == "get-remote-data":
            close_states_of_securonix = params.get("close_states_of_securonix", "").strip().lower()
            close_states_of_securonix = argToList(close_states_of_securonix)

            return_results(get_remote_data_command(client, demisto.args(), close_states_of_securonix))
        elif command == "get-modified-remote-data":
            return_results(get_modified_remote_data_command(client, demisto.args()))
        elif command == "securonix-xsoar-state-mapping-get":
            return_results(create_xsoar_to_securonix_state_mapping(params=params))
        elif command == "update-remote-system":
            return_results(update_remote_system(client, demisto.args()))
        elif command in commands:
            return_outputs(*commands[command](client, demisto.args()))
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as err:
        return_error(str(err))


if __name__ in ["__main__", "builtin", "builtins"]:
    try:
        integration_id = 2  # Change this to your integration ID
        command = "fetch-incidents"  # Change this to "fetch-incidents" or "test-module"
        
        main(integration_id=integration_id, command=command)
    except Exception as e:
        print(f"Script execution failed: {e}")
        traceback.print_exc()