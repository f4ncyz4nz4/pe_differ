from classes.entry import Entry


class Section_header:
    def __init__(self, section) -> None:
        self.entries = Entry.dump(section)
        self.start = self.entries[0].addr
        self.end = self.start
        for entry in self.entries:
            self.end += entry.size

    def __str__(self) -> str:
        info = []
        info.append("SECTION_HEADER")
        for entry in self.entries:
            info.append(str(entry))
        info.append("")
        return '\n'.join(info)
