echo "# MalScan - Malware Hash Scanner Tool

MalScan is a powerful and user-friendly tool designed to scan files and directories for malware using VirusTotal's extensive database. It computes file hashes (MD5, SHA1, SHA256) and checks them against VirusTotal for potential threats. If a file is not found in the VirusTotal database, it offers the option to upload the file for scanning.

## Features

- Scan files and directories for malware by computing hashes.
- Checks file hashes against VirusTotal's database.
- Uploads files to VirusTotal for scanning if not already present.
- Provides detailed analysis results, including detection statistics and malicious detections.
- Allows the option to delete malicious files directly from the tool.
- Modern, interactive user interface built with \`Rich\`.

## Installation

### Prerequisites

Ensure you have the following installed:

- **Python 3.6+**
- **pip** (Python package manager)

### Step 1: Clone the repository

Clone the repository to your local machine using the following command:

\`\`\`bash
git clone https://github.com/0xaswanth/MalScan.git
cd MalScan
\`\`\`

### Step 2: Install dependencies

Use pip to install the required dependencies:

\`\`\`bash
pip install -r requirements.txt
\`\`\`

### Step 3: Set up the VirusTotal API key

1. Visit [VirusTotal](https://www.virustotal.com/) and sign up for an account.
2. Go to your account settings and copy your API key.
3. Create a \`.env\` file in the project root and add your API key like this:

\`\`\`plaintext
VT_API_KEY=your_virustotal_api_key_here
\`\`\`

### Step 4: Run the tool

Run the tool by executing the following command:

\`\`\`bash
python malscan.py
\`\`\`

## Usage

When you run the tool, you’ll be prompted to choose whether you want to scan a file or a directory.

1. For files, the tool will calculate the file’s MD5, SHA1, and SHA256 hashes and check them against VirusTotal.
2. If no result is found in VirusTotal, you will have the option to upload the file for scanning.
3. The tool will display detailed results, including detection statistics and the option to delete malicious files.

## Contributing

Feel free to fork the repository, create pull requests, and report issues. Contributions are welcome!

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For further questions or feedback, you can reach me at:

- **GitHub**: [0xaswanth](https://github.com/0xaswanth)
- **Email**: aswanthkpkpkp@gmail.com (replace with your email)

---

Thank you for using **MalScan**! Stay safe online." > README.md
