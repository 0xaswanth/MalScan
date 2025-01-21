# MalScan - Malware Hash Scanner Tool

**MalScan** is a powerful and user-friendly tool designed to scan files and directories for malware using VirusTotal's extensive database. It computes file hashes (MD5, SHA1, SHA256) and checks them against VirusTotal for potential threats. If a file is not found in the VirusTotal database, it offers the option to upload the file for scanning.

---

## Features

- **Scan Files and Directories**: Calculate file hashes and check them against VirusTotal's malware database.
- **Upload to VirusTotal**: Upload files for malware scanning if they aren't already present in the database.
- **Detailed Analysis**: Provides detection statistics and malicious file identification.
- **Delete Malicious Files**: Option to remove identified malicious files.
- **Interactive Interface**: Uses `Rich` for animated, modern output displays.

---

## Installation

### Prerequisites

Ensure you have the following installed:

- **Python 3.6+**
- **pip** (Python package manager)

### Step 1: Clone the repository

Clone the repository to your local machine using the following command:

```bash
git clone https://github.com/0xaswanth/MalScan.git
cd MalScan
Step 2: Install dependencies
Use pip to install the required dependencies:

bash
Copy
Edit
pip install -r requirements.txt
Step 3: Set up the VirusTotal API key
Visit VirusTotal and sign up for an account.
Go to your account settings and copy your API key.
Create a .env file in the project root and add your API key like this:
plaintext
Copy
Edit
VT_API_KEY=your_virustotal_api_key_here
Usage
Run the tool by executing the following command:

bash
Copy
Edit
python malscan.py
Choose an action:

You will be prompted to choose whether you want to scan a file or a directory.
File scanning:

The tool will calculate the file’s MD5, SHA1, and SHA256 hashes and check them against VirusTotal.
Upload if needed:

If no result is found in VirusTotal, you will have the option to upload the file for scanning.
View results:

The tool will display detailed results, including detection statistics and the option to delete malicious files.
Example
bash
Copy
Edit
python malscan.py
Select to scan a file or directory.
Results will display the scan results, including any detection counts from VirusTotal and an option to upload files for further analysis.
Tool Details
Developer
Name: Aswanth KP
GitHub: 0xaswanth
License
This project is licensed under the MIT License. See the LICENSE file for details.

Contributing
Contributions are welcome! Feel free to fork this repository, make your improvements, and submit a pull request.

Roadmap
Planned features for future versions:

Add an option to scan files automatically after downloading from the internet.
Integration with additional malware detection platforms.
Disclaimer
This tool is intended for educational and ethical purposes only. Unauthorized use of MalScan on systems or networks you do not own or have permission to test is illegal.

Thank you for using MalScan! Stay safe online. 🚀
