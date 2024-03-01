from classes.entry import Entry


class Dos_header:
    def __init__(self, pe_file) -> None:
        self.header = pe_file.DOS_HEADER
        self.entries = Entry.dump(self.header)
        self.start = 0
        self.end = 0
        for entry in self.entries:
            self.end += entry.size

    def __str__(self) -> str:
        info = []
        info.append("DOS_HEADER")
        for entry in self.entries:
            info.append(str(entry))
        info.append("")
        return '\n'.join(info)
