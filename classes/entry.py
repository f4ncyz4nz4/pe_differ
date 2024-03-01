import time
import string


class Entry:
    def __init__(self, addr, size, key, value) -> None:
        self.addr = addr
        self.size = size
        self.key = key
        self.value = value

    def __str__(self) -> str:
        return "0x%-8x 0x%-8x %-30s %s" % (self.addr, self.size, self.key, self.value)

    @staticmethod
    def dump(header):
        entries = []
        printable_bytes = [ord(i)
                           for i in string.printable if i not in string.whitespace]
        format_iterator = iter(header.__format_str__[1:])
        for keys in header.__keys__:
            for key in keys:
                # addressy of the field
                addr = header.__field_offsets__[key] + header.__file_offset__
                # size of the field
                if key == "Misc" or key == "Misc_PhysicalAddress":
                    size = 4
                else:
                    size = Entry.get_field_size(format_iterator)
                # val of the field
                val = getattr(header, key)
                if isinstance(val, int):
                    val_str = '0x' + ''.join(format(byte, '02x')
                                             for byte in val.to_bytes(size, byteorder='big'))
                    if key == "TimeDateStamp" or key == "dwTimeStamp":
                        try:
                            val_str += " [%s UTC]" % time.asctime(
                                time.gmtime(val))
                        except ValueError:
                            val_str += " [INVALID TIME]"
                else:
                    val_str = "".join([chr(i) if (i in printable_bytes) else "\\x{0:02x}".format(
                        i) for i in bytearray(val).rstrip(b"\x00")])
                entries.append(Entry(addr, size, key, val_str))
        return entries

    @staticmethod
    def get_field_size(iterator):
        STRUCT_SIZEOF_TYPES = {"x": 1, "c": 1, "b": 1, "B": 1, "h": 2, "H": 2,
                               "i": 4, "I": 4, "l": 4, "L": 4, "f": 4, "q": 8, "Q": 8, "d": 8, "s": 1, }
        char = next(iterator)
        if char.isalpha():
            return STRUCT_SIZEOF_TYPES[char]
        elif char.isdigit():
            d = int(char, 10)
            for char in iterator:
                if char.isalpha():
                    return d * STRUCT_SIZEOF_TYPES[char]
                else:
                    d = (d * 10) + int(char, 10)
