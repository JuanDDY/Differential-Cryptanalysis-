class SBox:
    input_size: int
    output_size: int
    table: list[int]
    name: str

    def __init__(self, input_size, output_size, table, name="Unmaned"):
        self.input_size = input_size
        self.output_size = output_size
        self.table = table
        self.name = name