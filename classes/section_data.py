from hashlib import sha256


class Section_data:
    def __init__(self, section, directory_datas) -> None:
        section_data = section.get_data()
        self.hash = sha256(section_data).hexdigest()
        self.start = section.PointerToRawData
        self.size = len(section_data)
        try:
            self.sec_name = section.Name.strip(b"\x00").decode('utf-8')
        except:
            self.sec_name = str(section.Name)
        self.directory_included = []
        for directory_data in directory_datas:
            if self.contains(directory_data.start, directory_data.size):
                directory_data.set_included()
        # only to store and print included directory data
        #         self.directory_included.append(directory_data)
        # self.directory_included.sort(key=lambda x: x.start)

    def __str__(self) -> str:
        info = []
        info.append("SECTION_DATA")
        info.append("0x%-8x 0x%-8x %-30s %s" %
                    (self.start, self.size, self.sec_name, "sha256:" + self.hash))
        # for directory in self.directory_included:
        #     info.append("-----------0x%-8x 0x%-8x %-30s %s" % (directory.start,
        #                 directory.size, directory.name.lower(), "sha256:" + directory.hash))
        info.append("")
        return '\n'.join(info)

    def contains(self, start, size):
        end = start + size
        if self.start <= start and end <= self.start + self.size:
            return True
        return False
