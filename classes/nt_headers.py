from classes.entry import Entry


class Nt_headers:
    def __init__(self, pe_file) -> None:
        self.header = pe_file.NT_HEADERS
        self.entries = Entry.dump(self.header)
        self.start = self.entries[0].addr
        self.end = self.start
        for entry in self.entries:
            self.end += entry.size

    def __str__(self) -> str:
        info = []
        info.append("NT_HEADERS")
        for entry in self.entries:
            info.append(str(entry))
        info.append("")
        return '\n'.join(info)
