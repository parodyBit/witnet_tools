
class Point:

    def __init__(self, x, y, curve=None):
        self.x = x
        self.y = y
        self.curve = curve
        assert self in curve, f"Point {x}, {y} not in curve"

    def __add__(self, other):
        assert self.curve == other.curve, 'Cannot add points on different curves'
        return self.curve.point_add(self, other)

    def __sub__(self, other):
        return self + (other * -1)

    def __mul__(self, other: int):
        assert isinstance(other, int), 'Multiplication is only defined between a point and an integer'
        return self.curve.point_mul(self, other)

    def __repr__(self):
        return f"Point({self.x}, {self.y}, {self.curve.name})"

    def __eq__(self, other):
        return self.x % self.curve.prime == other.x % self.curve.prime \
               and self.y % self.curve.prime == other.y % self.curve.prime
