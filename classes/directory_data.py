from hashlib import sha256


class Directory_data:
    def __init__(self, directory_header, pe_file, pe_file_data) -> None:
        self.name = directory_header.name
        rva = int(directory_header.rva_of_dir, 16)
        self.start = pe_file.get_offset_from_rva(rva)
        self.size = int(directory_header.size_of_dir, 16)
        directory_data = pe_file_data[self.start:self.start + self.size]
        self.hash = sha256(directory_data).hexdigest()
        self.included = False

    def __str__(self) -> str:
        info = []
        info.append("DIRECTORY_DATA")
        info.append("0x%-8x 0x%-8x %-30s %s" % (self.start,
                    self.size, self.name.lower(), "sha256:" + self.hash))
        info.append("")
        return '\n'.join(info)

    def set_included(self):
        self.included = True
