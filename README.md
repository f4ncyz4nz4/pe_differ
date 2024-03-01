# PE Executable Differ
- [PE Executable Differ](#pe-executable-differ)
  - [Features](#features)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Usage](#usage)
  - [Contributions](#contributions)
  - [License](#license)

PE Executable Differ is a Python tool designed to analyze Portable Executable (PE) files commonly found in Windows environments. With this tool, you can parse individual PE files and compare two executables without the need for disassembly. Whether you're analyzing malware or understanding modifications to executable files, PE Executable Differ provides valuable insights quickly and efficiently.

## Features
- Parse PE files effortlessly.
- Compare two PE files to identify differences.
- Gain insights into modifications made to infected files.
- Useful for malware analysis and forensic investigations.

## Installation
You can install PE Executable Differ using pip:

```bash
git clone https://github.com/f4ncyz4nz4/pe_differ.git
```

### Requirements

```bash
pip install -r requirements.txt
```

## Usage
To parse a single PE file:

```bash
python pe_differ.py <path_to_pe_file>
```

To compare two PE files:

```bash
python pe_differ.py <path_to_pe_file1> <path_to_pe_file2>
```
For detailed usage and options, refer to the documentation.

## Contributions
Contributions are welcome! If you find any bugs or have suggestions for improvements, please open an issue or submit a pull request.

## License
PE Executable Differ is licensed under the GPL-3.0 License. See LICENSE for more information.
