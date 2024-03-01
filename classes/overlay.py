from classes.authenticode import Authenticode
from hashlib import sha256
import pefile


class Overlay:
    def __init__(self, pe_file, pe_file_data, directory_datas) -> None:
        self.start = pe_file.sections[-1].PointerToRawData + \
            pe_file.sections[-1].SizeOfRawData
        # start = pe_file.get_overlay_data_start_offset()
        overlay = pe_file_data[self.start:]
        self.overlay_size = len(overlay)
        if overlay == None or self.overlay_size <= 0:
            self.overlay_exists = False
            self.authenticode_exists = False
            return
        self.overlay_exists = True
        authenticode_start = pe_file.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
        authenticode_size = pe_file.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size
        if authenticode_start < self.start or authenticode_size <= 0:
            # if authenticode_start <= 0 or authenticode_size <= 0:
            self.authenticode_exists = False
            self.overlay_hash = sha256(overlay).hexdigest()
        else:
            self.authenticode_exists = True
            # OVERLAY 1st part
            self.overlay_1_size = authenticode_start - self.start
            if self.overlay_1_size > 0:
                overlay_1 = overlay[:self.overlay_1_size]
                self.overlay_1_hash = sha256(overlay_1).hexdigest()
            # AUTHENTICODE
            self.authenticode = Authenticode(
                authenticode_start, authenticode_size, pe_file_data)
            # OVERLAY 2st part
            overlay_2 = overlay[self.overlay_1_size + authenticode_size:]
            self.overlay_2_size = len(overlay_2)
            if self.overlay_2_size > 0:
                self.overlay_2_start = self.start + self.overlay_1_size + authenticode_size
                self.overlay_2_hash = sha256(overlay_2).hexdigest()
        for directory_data in directory_datas:
            if self.contains(directory_data.start, directory_data.size):
                directory_data.set_included()

    def __str__(self) -> str:
        info = []
        if self.authenticode_exists:
            if self.overlay_1_size > 0:
                info.append("OVERLAY_BEFORE_AUTHENTICODE")
                info.append("0x%-8x 0x%-8x %-30s %s" % (self.start, self.overlay_1_size,
                            "overlay_before_authenticode", "sha256:" + self.overlay_1_hash))
            info.append(str(self.authenticode))
            if self.overlay_2_size > 0:
                info.append("OVERLAY_AFTER_AUTHENTICODE")
                info.append("0x%-8x 0x%-8x %-30s %s" % (self.overlay_2_start, self.overlay_2_size,
                            "overlay_after_authenticode", "sha256:" + self.overlay_2_hash))
        else:
            info.append("OVERLAY")
            info.append("0x%-8x 0x%-8x %-30s %s" % (self.start,
                        self.overlay_size, "overlay", "sha256:" + self.overlay_hash))
        info.append("")
        return '\n'.join(info)

    def contains(self, start, size):
        end = start + size
        if self.start <= start and end <= self.start + self.overlay_size:
            return True
        return False
