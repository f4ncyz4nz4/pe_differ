from hashlib import sha256


class Authenticode:
    def __init__(self, start, size, data) -> None:
        self.start = start
        self.size = size
        self.data = data[self.start:self.start + self.size]
        self.hash = sha256(self.data).hexdigest()
        extracted_size = int.from_bytes(self.data[:4], byteorder='little')
        self.revision = int.from_bytes(self.data[4:6], byteorder='little')
        self.certificate_type = int.from_bytes(
            self.data[6:8], byteorder='little')
        self.certificate = self.data[8:extracted_size]
        # TODO sometimes size is not the same firseria/00b608377975469589e88051563c7968367cc454f08806bc4357f722b902e31e
        # if self.size != extracted_size:
        #     raise Exception

    def __str__(self) -> str:
        info = []
        info.append("AUTHENTICODE")
        info.append("0x%-8x 0x%-8x %-30s %s" % (self.start,
                    self.size, "authenticode", "sha256:" + self.hash))
        return '\n'.join(info)
