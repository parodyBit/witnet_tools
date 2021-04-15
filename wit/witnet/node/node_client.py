from wit.util.json_rpc import format_node_request
from wit.util.socket_manager import SocketManager


class NodeClient(object):
    _instance = None

    def __init__(self, ipv4='12.0.0.1', port=21338):
        if NodeClient._instance is not None:
            raise Exception('Singleton')
        else:
            NodeClient._instance = self
            self.ip = ipv4
            self.port = port
            self.running = False
            self.wallet_thread = None
            self.socket_manager = SocketManager(ip=self.ip, port=self.port, internal=True)
            self.socket_manager.connect()
            self.local_transactions = {}

    @staticmethod
    def manager(ipv4='12.0.0.1', port=21338):
        if NodeClient._instance is not None:
            return NodeClient._instance
        else:
            return NodeClient(ipv4=ipv4, port=port)

    def disconnect_socket(self):
        self.socket_manager.disconnect()

    def process_request(self, method, params=None):
        return self.socket_manager.query(request=format_node_request(method=method, params=params))

    def get_sync_status(self):
        return self.process_request(method='syncStatus')

    def get_address(self):
        return self.process_request(method='getPkh')

    def get_utxo_info(self, address: str):
        """
        :param address: bech32 encoded address
        :return:
        """
        request = format_node_request(method='getUtxoInfo', params=[address])
        response = self.socket_manager.query(request=request)
        collateral_min, utxos = response.values()
        return utxos

    def get_block(self, block_hash: str):
        """
        :param block_hash: block hash
        :return:
        """
        request = format_node_request(method='getBlock', params=[block_hash])
        raw_block = self.socket_manager.query(request=request)
        return raw_block

    def get_transaction(self, transaction_hash):
        """
        :param transaction_hash:
        :return:
        """
        if transaction_hash in self.local_transactions.keys():
            return self.local_transactions[transaction_hash]
        else:
            response = self.process_request(method='getTransaction', params=[transaction_hash])
            return response

    def get_blockchain(self, epoch=-1, limit=1):
        """
        :param epoch:
        :param limit:
        :return:
        """
        return self.process_request(method='getBlockChain', params=[epoch, limit])

    def data_request_report(self, transaction_hash: str):
        return self.process_request(method='dataRequestReport', params=[transaction_hash])

    def get_reputation(self, address: str = None):
        """
        :param address:
        :return:
        """
        if address is None:
            address = self.get_address()
        return self.process_request(method='getReputation', params=[address])

    def peers(self, ):
        return self.process_request(method='peers')

    def known_peers(self, ):
        return self.process_request(method='knownPeers')

    def get_mempool(self, ):
        return self.process_request(method='getMempool')

    def get_consensus_constants(self):
        return self.process_request(method='getConsensusConstants')

    def execute_request(self, request):
        response = self.socket_manager.query(request)
        return response

    def inventory(self, inventory_item):
        return self.process_request(method='inventory', params=inventory_item)

    def get_balance(self, address: str = None):
        return self.process_request(method='getBalance', params=[address])

    def get_reputation_all(self):
        return self.process_request(method='getReputationAll')

    def node_stats(self):
        return self.process_request(method='nodeStats')

    def get_super_block(self):
        return self.process_request(method='getSuperblock')

    # ## Protected Methods
    def send_request(self):
        return self.process_request(method='sendRequest')

    def send_value(self):
        return self.process_request(method='sendValue')

    def get_public_key(self):
        return self.process_request(method='getPublicKey')

    def get_pkh(self):
        return self.process_request(method='getPkh')

    def sign(self):
        return self.process_request(method='sign')

    def create_vrf(self):
        return self.process_request(method='createVRF')

    def master_key_export(self):
        return self.process_request(method='masterKeyExport')

    def add_peers(self):
        return self.process_request(method='addPeers')

    def clear_peers(self):
        return self.process_request(method='clearPeers')

    def initialize_peers(self):
        return self.process_request(method='initializePeers')

    def rewind(self):
        return self.process_request(method='rewind')
