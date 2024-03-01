from classes.pe_file import Pe_file
import sys
import os
import difflib


def differ(file1, file2):
    if not os.path.exists("results"):
        os.makedirs("results")
    pe1 = Pe_file(path=file1)
    pe2 = Pe_file(path=file2)
    file_path1 = os.path.basename(file1)
    file_path2 = os.path.basename(file2)
    result_path = os.path.join(
        "results",  file_path1 + "-" + file_path2 + ".diff")

    blob1_lines = str(pe1).splitlines(keepends=True)
    blob2_lines = str(pe2).splitlines(keepends=True)
    differ = difflib.Differ()
    diff = list(differ.compare(blob1_lines, blob2_lines))
    with open(result_path, 'w') as output_file:
        output_file.writelines(diff)


def parser(file):
    if not os.path.exists("results"):
        os.makedirs("results")
    pe = Pe_file(path=file)
    file_path = os.path.basename(file)
    result_path = os.path.join("results", file_path + ".txt")
    print(result_path)

    with open(result_path, 'w') as output_file:
        output_file.write(str(pe))


if __name__ == "__main__":
    if len(sys.argv) == 2:
        file = sys.argv[1]
        parser(file)
    elif len(sys.argv) == 3:
        file1 = sys.argv[1]
        file2 = sys.argv[2]
        differ(file1, file2)
    else:
        print("Wrong arguments")
        exit(-1)
