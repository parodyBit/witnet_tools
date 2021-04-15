from wit.crypto.ECDSA.secp256k1.point import Point

from dataclasses import dataclass, InitVar
from typing import Union, Tuple


@dataclass
class Curve:
    prime: int  # P
    a: int
    b: int
    generator: Union[Tuple, Point]
    order: int  # N
    name: str

    def __post_init__(self):
        if type(self.generator).__name__ == 'tuple':
            print('-----')
            self.generator = Point(*self.generator, curve=self)

    def point_add(self, p, q):
        """https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_addition"""
        P = self.prime
        if p == q:
            lam = (3 * p.x * p.x) * pow(2 * p.y % P, P - 2, P)
        else:
            lam = pow(q.x - p.x, P - 2, P) * (q.y - p.y) % P

        rx = lam ** 2 - p.x - q.x
        ry = lam * (p.x - rx) - p.y
        return Point(rx % P, ry % P, curve=self)

    def point_mul(self, p, d):
        d = d % self.order

        n = p
        q = None

        for i in reversed(format(d, 'b')):
            if i == '1':
                if q is None:
                    q = n
                else:
                    q = self.point_add(q, n)

            n = self.point_add(n, n)
        return q

    def __contains__(self, point):
        return point.y ** 2 % self.prime == (point.x ** 3 + self.a * point.x + self.b) % self.prime

    def f(self, x):
        """Compute y**2 = x^3 + ax + b in field FP"""
        return (x ** 3 + self.a * x + self.b) % self.prime
