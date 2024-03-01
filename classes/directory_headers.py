class Directory_header:
    def __init__(self, directory) -> None:
        self.name = directory.name[16:]
        self.size = 4
        self.rva_of_dir = '0x' + ''.join(format(byte, '02x')
                                         for byte in directory.VirtualAddress.to_bytes(self.size, byteorder='big'))
        self.size_of_dir = '0x' + \
            ''.join(format(byte, '02x')
                    for byte in directory.Size.to_bytes(self.size, byteorder='big'))
        self.addr_rva = directory.__field_offsets__[
            "VirtualAddress"] + directory.__file_offset__
        self.addr_size = directory.__field_offsets__[
            "Size"] + directory.__file_offset__

    def __str__(self) -> str:
        info = []
        info.append("%s" % (self.name))
        info.append("0x%-8x 0x%-8x %-30s %s" %
                    (self.addr_rva, self.size, "rva", self.rva_of_dir))
        info.append("0x%-8x 0x%-8x %-30s %s" %
                    (self.addr_size, self.size, "size", self.size_of_dir))
        return '\n'.join(info)


class Directory_headers:
    def __init__(self, pe_file) -> None:
        self.list = []
        self.start = 0
        size = 0
        for directory in pe_file.OPTIONAL_HEADER.DATA_DIRECTORY:
            directory_header = Directory_header(directory)
            size += 2 * directory_header.size
            self.list.append(directory_header)
        self.start = self.list[0].addr_rva
        self.end = self.start+size

    def __str__(self) -> str:
        info = []
        info.append("DIRECTORIES_HEADER")
        for directory in self.list:
            info.append(str(directory))
        info.append("")
        return '\n'.join(info)
