from classes.pe_file import Pe_file


class Optional_header:
    def __init__(self, pe_file) -> None:
        self.header = pe_file.OPTIONAL_HEADER
        self.entries = Pe_file.dump(self.header)
        self.start = self.entries[0].addr
        self.end = self.start
        for entry in self.entries:
            self.end += entry.size

    def __str__(self) -> str:
        info = []
        info.append("OPTIONAL_HEADER")
        for entry in self.entries:
            info.append(str(entry))
        info.append("")
        return '\n'.join(info)