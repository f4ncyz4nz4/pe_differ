from classes.dos_header import Dos_header
from classes.dos_stub import Dos_stub
from classes.nt_headers import Nt_headers
from classes.file_header import File_header
from classes.optional_header import Optional_header
from classes.directory_headers import Directory_headers
from classes.section_header import Section_header
from classes.directory_data import Directory_data
from classes.section_data import Section_data
from classes.overlay import Overlay
from classes.unknown import Unknown
import ssdeep
import tlsh
import pefile
from hashlib import sha256


class Pe_file:
    def __init__(self, path=None, data=None) -> None:
        if path is None and data is None:
            raise ValueError("Must supply either name or data")
        if data:
            self.path = path if path else "<unknown>"
            self.data = data
        else:
            self.path = path
            with open(self.path, 'rb') as file:
                self.data = file.read()
        # elements list
        self.elements = []
        # metadata
        self.sha256 = sha256(self.data).hexdigest()
        self.tlsh = tlsh.hash(self.data)
        self.ssdeep = ssdeep.hash(self.data)
        # size
        self.actual_size = len(self.data)
        # pe file
        try:
            self.pe_file = pefile.PE(data=self.data)
        except:
            self.pe_file = None
            return
        # expected size
        self.expected_size = self.pe_file.sections[-1].PointerToRawData + \
            self.pe_file.sections[-1].SizeOfRawData
        # now compute difference
        self.difference = self.actual_size - self.expected_size
        # create unknowns
        self.unknowns = [Unknown(0, self.actual_size)]
        # dos header
        self.dos_header = Dos_header(self.pe_file)
        self.update_unknowns(self.dos_header.start, self.dos_header.end)
        self.elements.append(self.dos_header)
        # dos stub
        self.dos_stub = Dos_stub(self.pe_file, self.data)
        if self.dos_stub.dos_stub_size > 0:
            self.update_unknowns(
                self.dos_stub.start, self.dos_stub.start + self.dos_stub.total_size)
            self.elements.append(self.dos_stub)
        # nt headers
        self.nt_headers = Nt_headers(self.pe_file)
        self.update_unknowns(self.nt_headers.start, self.nt_headers.end)
        self.elements.append(self.nt_headers)
        # file header
        self.file_header = File_header(self.pe_file)
        self.update_unknowns(self.file_header.start, self.file_header.end)
        self.elements.append(self.file_header)
        # optional header
        self.optional_header = Optional_header(self.pe_file)
        self.update_unknowns(self.optional_header.start,
                             self.optional_header.end)
        self.elements.append(self.optional_header)
        # directories header
        self.directory_headers = Directory_headers(self.pe_file)
        if len(self.directory_headers.list) > 0:
            self.update_unknowns(self.directory_headers.start,
                                 self.directory_headers.end)
            self.elements.append(self.directory_headers)
        # sections header
        self.section_headers = []
        for section in self.pe_file.sections:
            section_header = Section_header(section)
            self.section_headers.append(section_header)
            self.update_unknowns(section_header.start,
                                 section_header.end - 8)
            self.elements.append(section_header)
        # directories data
        self.directory_datas = []
        for dir_header in self.directory_headers.list:
            if int(dir_header.rva_of_dir, 16) < self.actual_size and int(dir_header.size_of_dir, 16) > 0 and dir_header.name != "ENTRY_SECURITY":
                directory_data = Directory_data(
                    dir_header, self.pe_file, self.data)
                self.directory_datas.append(directory_data)
        # sections data
        self.section_datas = []
        for section in self.pe_file.sections:
            section_data = Section_data(section, self.directory_datas)
            if section_data.start > 0 and section_data.size > 0 and section_data.start < self.actual_size:
                self.section_datas.append(section_data)
                self.update_unknowns(
                    section_data.start, section_data.start + section_data.size)
                self.elements.append(section_data)
        # overlay
        if self.actual_size >= self.expected_size:
            self.overlay = Overlay(
                self.pe_file, self.data, self.directory_datas)
            self.has_overlay = self.overlay.overlay_exists
            self.has_authenticode = self.overlay.authenticode_exists
            if self.has_overlay and self.overlay.start < self.actual_size:
                self.update_unknowns(
                    self.overlay.start, self.overlay.start + self.overlay.overlay_size)
                self.elements.append(self.overlay)
            if self.has_authenticode:
                self.authenticode = self.overlay.authenticode
        else:
            self.has_overlay = False
            self.has_authenticode = False
        # if directory data is not included, than flag it
        for directory_data in self.directory_datas:
            if not directory_data.included and directory_data.start < self.actual_size:
                self.update_unknowns(
                    directory_data.start, directory_data.start + directory_data.size)
                self.elements.append(directory_data)
        # calculate hash of unknown parts
        for unknown in self.unknowns:
            unknown.calculate_hash(self.data)
            self.elements.append(unknown)

    def __str__(self) -> str:
        info = []
        info.append("%-16s %s" % ("file_path", self.path))
        info.append("%-16s %s" % ("file_sha-256", self.sha256))
        info.append("%-16s %s" % ("file_tlsh", self.tlsh))
        info.append("%-16s %s" % ("file_ssdeep", self.ssdeep))
        info.append("%-16s 0x%-8x" % ("actual_size", self.actual_size))
        if self.pe_file == None:
            print(f"*\tpefile module cannot parse:\t{self.path}")
            return '\n'.join(info)
        info.append("%-16s 0x%-8x" % ("expected_size", self.expected_size))
        info.append("%-16s 0x%-8x" % ("difference",  self.difference))
        info.append("")
        for element in sorted(self.elements, key=lambda x: int(x.start)):
            info.append(str(element))
        return '\n'.join(info)

    def update_unknowns(self, start, end):
        index = 0
        if start >= end:
            return
        for unknown in self.unknowns:
            if (unknown.start >= start and end >= unknown.end):
                self.unknowns.pop(index)
            elif (unknown.start < start and unknown.end > start and unknown.end <= end):
                unknown.end = start
            elif (unknown.start >= start and unknown.start < end and unknown.end > end):
                unknown.start = end
            # totally inside
            elif (unknown.start < start and end < unknown.end):
                self.unknowns.insert(index+1, Unknown(end, unknown.end))
                unknown.end = start
            index += 1
