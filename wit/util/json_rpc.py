from collections import OrderedDict
from typing import Any, Callable, Dict, Iterator, Optional

def sort_request(request: Dict[str, Any]) -> OrderedDict:
    """
    Sort a JSON-RPC request dict.
    This has no effect other than making the request nicer to read.
        >>> json.dumps(sort_request(
        ...     {'id': 2, 'params': [2, 3], 'method': 'add', 'jsonrpc': '2.0'}))
        '{"jsonrpc": "2.0", "method": "add", "params": [2, 3], "id": 2}'
    Args:
        request: JSON-RPC request in dict format.
    """
    sort_order = ["jsonrpc", "method", "params", "id"]
    return OrderedDict(sorted(request.items(), key=lambda k: sort_order.index(k[0])))


def format_node_request(method: str, params = None, id: int = 1):
    if params is None:
        json_req = {'id': 1, 'method': method, 'jsonrpc': '2.0'}
    else:
        json_req = {'id': 1, 'params': params, 'method': method, 'jsonrpc': '2.0'}
    return sort_request(json_req)
