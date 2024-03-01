from hashlib import sha256


class Unknown:
    def __init__(self, start, end) -> None:
        if start >= end:
            raise Exception
        self.start = start
        self.end = end
        self.unknown_data = None
        self.unknown_hash = None

    def __str__(self) -> str:
        info = []
        info.append("0x%-8x 0x%-8x %-30s %s" % (self.start, self.end -
                    self.start, "unknown", "sha256:" + str(self.unknown_hash)))
        info.append("")
        return '\n'.join(info)

    def calculate_hash(self, data):
        self.unknown_data = data[self.start:self.end]
        self.unknown_hash = sha256(self.unknown_data).hexdigest()
