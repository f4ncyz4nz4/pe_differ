class Entry:
    def __init__(self, addr, size, key, value) -> None:
        self.addr = addr
        self.size = size
        self.key = key
        self.value = value

    def __str__(self) -> str:
        return "0x%-8x 0x%-8x %-30s %s" % (self.addr, self.size, self.key, self.value)
