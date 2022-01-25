from typing import List

from witnet.rad.op_codes import OP


class RadArray(List):


    def op(self, op: int, key):
        ops = [
            OP
        ]
