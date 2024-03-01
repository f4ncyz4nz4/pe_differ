from classes.rich_header import Rich_header
from hashlib import sha256


class Dos_stub:
    def __init__(self, pe_file, pe_file_data) -> None:
        self.header = pe_file.DOS_HEADER
        self.start = self.header.__field_offsets__["e_lfanew"] + 4
        if pe_file.RICH_HEADER == None:
            self.rich_header_exists = False
            dos_stub_end = getattr(self.header, "e_lfanew")
            self.dos_stub_size = dos_stub_end - self.start
            stub = pe_file_data[self.start:dos_stub_end]
            self.dos_stub_hash = sha256(stub).hexdigest()
            self.total_size = self.dos_stub_size
        else:
            self.rich_header_exists = True
            # DOS STUB
            dos_stub_end = 0x80
            self.dos_stub_size = dos_stub_end - self.start
            stub = pe_file_data[self.start:dos_stub_end]
            self.dos_stub_hash = sha256(stub).hexdigest()
            # RICH HEADER
            self.rich_header = Rich_header(pe_file, pe_file_data)
            self.total_size = self.dos_stub_size + self.rich_header.size

    def __str__(self) -> str:
        info = []
        info.append("DOS_STUB")
        if self.rich_header_exists:
            info.append("0x%-8x 0x%-8x %-30s %s" % (self.start,
                        self.dos_stub_size, "dos_stub", "sha256:" + self.dos_stub_hash))
            info.append(str(self.rich_header))
        else:
            info.append("0x%-8x 0x%-8x %-30s %s" % (self.start,
                        self.dos_stub_size, "dos_stub", "sha256:" + self.dos_stub_hash))
        info.append("")
        return '\n'.join(info)
