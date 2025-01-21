
# MalScan - Malware Hash Scanner Tool

MalScan is a powerful, user-friendly tool designed to help cybersecurity professionals and enthusiasts scan files and directories for malware using VirusTotal's extensive malware database. MalScan calculates file hashes (MD5, SHA1, SHA256) and checks them against VirusTotal for potential threats, offering the option to upload unknown files for further analysis.

---

## Features

- **Hash Calculation**: Calculates MD5, SHA1, and SHA256 hashes of files.
- **VirusTotal Integration**: Automatically checks file hashes against VirusTotal’s database.
- **File Upload**: Uploads files to VirusTotal for scanning if no result is found.
- **Detailed Analysis**: Displays detection statistics and malicious file details.
- **Delete Malicious Files**: Provides an option to delete identified malicious files.
- **Rich Animations**: Uses the `Rich` library to display interactive output and progress bars.

---

## Installation

To install and use MalScan, follow these steps:

### Prerequisites
- Python 3.6 or later
- VirusTotal API key (you can obtain this by creating a free VirusTotal account)

### Steps

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/0xaswanth/MalScan.git
   cd MalScan
   ```

2. **Install Required Libraries**:
   Use `pip` to install the required dependencies from the `requirements.txt` file:
   ```bash
   pip install -r requirements.txt
   ```

3. **Set Up VirusTotal API Key**:
   Create a `.env` file in the project root and add your VirusTotal API key:
   ```plaintext
   VT_API_KEY=your_virustotal_api_key_here
   ```

---

## Usage

1. **Run the tool**:
   ```bash
   python malscan.py
   ```

2. **Select an option**:
   - Choose whether to scan a file or a directory when prompted.

3. **File scanning**:
   - MalScan calculates MD5, SHA1, and SHA256 hashes for the files and checks them against VirusTotal's database.

4. **Upload if needed**:
   - If no result is found, the tool gives you the option to upload the file to VirusTotal for further analysis.

5. **Results**:
   - The tool displays detection results, including VirusTotal detection counts, and offers an option to delete malicious files.

Example usage:
```
python malscan.py
Select an option:
1. Scan a file
2. Scan a directory
Enter your choice: 1
Enter the path to the file: /path/to/file.txt
Checking file hashes...
VirusTotal scan result: 3 detections found.
Do you want to delete this file? (y/n): y
```

---

## Tool Details

### Developer
- **Name**: Aswanth KP
- **GitHub**: [0xaswanth](https://github.com/0xaswanth)

### License
This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## Contributing

Contributions are welcome! Feel free to fork this repository, make your improvements, and submit a pull request.

---

## Roadmap

Planned future enhancements:
- Automating file scanning post-download from the internet.
- Integration with additional malware detection services.
- Adding a GUI for an enhanced user experience.

---

## Acknowledgments

Special thanks to the open-source community for resources and tools that contributed to the development of this project.

---

## Disclaimer
This tool is intended for educational and ethical purposes only. Unauthorized use of MalScan on systems or networks you do not own or have permission to test is illegal.

---

Happy Malware Scanning with MalScan! 🚀
