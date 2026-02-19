
class IdentitySBox:
    """
    S-Box identidad de tamaño n × n, implementa table e apply().
    """
    def __init__(self, n: int):
        self.input_size = n
        self.output_size = n
        self.table = list(range(1 << n))

    def apply(self, value: int) -> int:
        return value