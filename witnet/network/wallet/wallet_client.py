from witnet.network.wallet.models import WalletError
from witnet.util.json_rpc import format_node_request
import json
import witnet.util.websockets as websockets
import asyncio

wallet_url = '127.0.0.1:11212'


def send(uri, request):
    async def _send():
        async with websockets.connect(uri) as websocket:
            await websocket.send(json.dumps(request))
            resp = await websocket.recv()
            return resp

    loop = asyncio.get_event_loop().run_until_complete(_send())
    return loop


class WalletSocket(object):
    _instance = None

    def __init__(self, ipv4, port):
        if WalletSocket._instance is not None:
            raise Exception('Singleton')
        else:
            self.ip = ipv4
            self.port = port

    @staticmethod
    def manager(ipv4='127.0.0.1', port=11212):
        if WalletSocket._instance is not None:
            return WalletSocket._instance
        else:
            return WalletSocket(ipv4=ipv4, port=port)

    def query(self, request):
        tmp = send(f'ws://{self.ip}:{self.port}/', request)
        return tmp


class WalletClient:

    def __init__(self, ipv4='127.0.0.1', port=11212):

        self.ip = ipv4
        self.port = port
        self.running = False
        self.wallet_thread = None
        self.socket = WalletSocket.manager(ipv4=ipv4, port=port)
        self._session = None

    @property
    def session(self):
        if self._session is None:
            return WalletError(code=1, message='Session is None. use `unlock_wallet` to create a session.')

    def process_request(self, request):

        try:
            response = json.loads(self.socket.query(request=request))
            if 'error' in response:
                error = response['error']
                return WalletError(code=int(error['code']), message=error['message'])
            return response['result']
        except Exception as e:
            print(e)

    # length must be: 12, 15, 18, 21, 24
    # create_mnemonics(length=12)
    def create_mnemonics(self, length=12):
        """
        Creates a BIP39 mnemonic word sentence that can be used to generate a new HD wallet
        :param length: Integer. valid lengths are: 12, 15, 18, 21, 24
        :return: A dict with key 'mnemonics' containing the word phrase OR returns None
        """
        request = format_node_request(method='create_mnemonics', params={'length': length})
        return self.process_request(request)

    def create_wallet(self, name='', caption='', password='', seed_source='mnemonics/xprv', seed_data=''):
        """

        :param name: A human-friendly name for your the wallet. (optional)
        :param caption: A human-friendly caption for your the wallet. (optional)
        :param password:  The password that will seed the key used to encrypt
                          the wallet in the file system. The password must have
                          at least eight characters.
        :param seed_source: Must be `mnemonics` or `xprv` and determines
                            how the HD wallet master key will be generated
                            from the data sent in the `seedData` param.
        :param seed_data: The data used for generating the new HD wallet master key.
        :return: wallet_id
        """

        request = format_node_request(method='create_wallet',
                                      params={'name': name,
                                              'caption': caption,
                                              'password': password,
                                              'seed_source': seed_source,
                                              'seed_data': seed_data})
        return self.process_request(request)

    def export_master_key(self, wallet_id='', password='', session_id=''):
        """

        :param wallet_id:
        :param password:
        :param session_id:
        :return:
        """

        request = format_node_request(method='export_master_key', params={'wallet_id': wallet_id,
                                                                          'password': password,
                                                                          'session_id': session_id})
        return self.process_request(request)

    def unlock_wallet(self, wallet_id='', password=''):
        """

        :param wallet_id: The ID associated to the wallet.
        :param password: The password that unlocks the wallet.
        :return:
        """
        request = format_node_request(method='unlock_wallet', params={'wallet_id': wallet_id, 'password': password})
        return self.process_request(request)

    def lock_wallet(self, wallet_id='', session_id=''):
        """
        `lock_wallet` is used to *lock* the wallet with the specified id
        and close the active session. What does it mean to *lock a wallet*?
        It means that the decryption key for that wallet that is being hold
        in memory is forgotten and the Wallet server will be unable to update
        that wallet information until it is unlocked again.

        :param wallet_id: The ID associated to the wallet.
        :param session_id: The session ID assigned to you when you unlocked the wallet.
        :return:
        """
        request = format_node_request(method='lock_wallet', params={'wallet_id': wallet_id, 'session_id': session_id})
        return self.process_request(request)

    def run_rad_request(self, rad_request: dict = None):
        """

        :param rad_request:
        :return:
        """
        request = format_node_request(method='run_rad_request', params={'rad_request': rad_request})
        return self.process_request(request)

    def close_session(self, session_id=''):
        """

        :param session_id:
        :return:
        """
        request = format_node_request(method='close_session', params={'session_id': session_id})
        return self.process_request(request)

    def create_data_request(self, wallet_id='', session_id='', request: dict = None, fee=0):
        """

        :param wallet_id:
        :param session_id:
        :param request:
        :param fee:
        :return:
        """
        request = format_node_request(method='create_data_request', params={'wallet_id': wallet_id,
                                                                            'session_id': session_id,
                                                                            'request': request,
                                                                            'fee': fee})
        return self.process_request(request)

    def create_vtt(self, wallet_id='', session_id='', outputs=None, fee=0, fee_type='absolute'):
        """

        :param fee_type:
        :param outputs:
        :param wallet_id:
        :param session_id:
        :param fee:
        :return:
        """
        if outputs is None:
            outputs = list()
        request = format_node_request(method='create_vtt', params={'wallet_id': wallet_id,
                                                                   'session_id': session_id,
                                                                   'outputs': outputs,
                                                                   'fee': fee,
                                                                   'fee_type': fee_type})
        return self.process_request(request)

    def get_wallet_infos(self):
        """

        """
        request = format_node_request(method='get_wallet_infos', params=None)
        return self.process_request(request)

    def generate_address(self, wallet_id='', session_id=''):
        """

        :param wallet_id:
        :param session_id:
        :return:
        """
        request = format_node_request(method='generate_address', params={'wallet_id': wallet_id,
                                                                         'session_id': session_id})
        return self.process_request(request)

    def get_addresses(self, wallet_id='', session_id='', offset=0, limit=0):
        """

        :param wallet_id:
        :param session_id:
        :param offset:
        :param limit:
        :return:
        """
        request = format_node_request(method='get_addresses', params={'wallet_id': wallet_id,
                                                                      'session_id': session_id,
                                                                      'offset': offset,
                                                                      'limit': limit})
        return self.process_request(request)

    def import_seed(self, mnemonics='', seed=''):
        """

        :param mnemonics:
        :param seed:
        :return:
        """
        request = format_node_request(method='import_seed', params={'mnemonics': mnemonics, 'seed': seed})
        return self.process_request(request)

    def next_subscription_id(self):
        """

        """
        request = format_node_request(method='next_subscription_id', params=None)
        return self.process_request(request)

    def get_transactions(self, wallet_id='', session_id='', offset=0, limit=0):
        """

        :param wallet_id:
        :param session_id:
        :param offset:
        :param limit:
        :return:
        """
        request = format_node_request(method='get_transactions', params={'wallet_id': wallet_id,
                                                                         'session_id': session_id,
                                                                         'offset': offset,
                                                                         'limit': limit})
        return self.process_request(request)

    def send_transaction(self, wallet_id='', session_id='', transaction: dict = None):
        """

        :param wallet_id:
        :param session_id:
        :param transaction:
        :return:
        """
        request = format_node_request(method='send_transaction', params={'wallet_id': wallet_id,
                                                                         'session_id': session_id,
                                                                         'transaction': transaction})
        return self.process_request(request)

    def unsubscribe_notifications(self):
        """


        """
        request = format_node_request(method='unsubscribe_notifications', params=None)
        return self.process_request(request)

    def subscribe_notifications(self):
        """

        """
        request = format_node_request(method='subscribe_notifications', params=None)
        return self.process_request(request)

    def update_wallet(self):
        """

        """
        request = format_node_request(method='update_wallet', params=None)
        return self.process_request(request)


# Test Wallet Function


def main():
    ...


if __name__ == '__main__':
    main()
