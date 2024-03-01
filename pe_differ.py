from classes.pe_file import Pe_file
import sys
import difflib


def extraction(file1, file2):
    pe1 = Pe_file(path=file1)
    pe2 = Pe_file(path=file2)

    file_path = "mal.diff"
    blob1_lines = str(pe1).splitlines(keepends=True)
    blob2_lines = str(pe2).splitlines(keepends=True)
    differ = difflib.Differ()
    diff = list(differ.compare(blob1_lines, blob2_lines))
    with open(file_path, 'w') as output_file:
        output_file.writelines(diff)


def analysis(file):
    pe = Pe_file(path=file)
    with open(file + ".analysis", 'w') as output_file:
        output_file.write(str(pe))


if __name__ == "__main__":
    if len(sys.argv) == 2:
        file = sys.argv[1]
        analysis(file)
    elif len(sys.argv) == 3:
        file1 = sys.argv[1]
        file2 = sys.argv[2]
        extraction(file1, file2)
