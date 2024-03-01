from hashlib import sha256


class Rich_header:
    def __init__(self, pe_file, pe_file_data) -> None:
        self.start = 0x80
        rich_index = pe_file.__data__.find(
            b"Rich", 0x80, pe_file.OPTIONAL_HEADER.get_file_offset())
        end = rich_index + 8
        rich_header = pe_file_data[self.start:end]
        self.size = len(rich_header)
        self.hash = sha256(rich_header).hexdigest()

    def __str__(self) -> str:
        return "0x%-8x 0x%-8x %-30s %s" % (self.start, self.size, "rich_header", "sha256:" + self.hash)
