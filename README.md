# IndiFinder (Ransomware IOC Downloader)

This tool automates the discovery, download, and cross-verification of malware samples (IOCs) associated with specific ransomware groups. It facilitates incident response and threat intelligence workflows by aggregating samples from multiple sources.

## Key Features

*   **MalwareBazaar Integration:** Automated scanning and downloading of samples for target ransomware groups (e.g., LockBit, BlackBasta).
*   **Hybrid Analysis Cross-Verification:** Checks sample hashes against Hybrid Analysis to retrieve additional copies and verify attribution.
*   **Strict Verification Mode:**
    *   **Signature Validation:** Ensures samples match the expected malware signature.
    *   **Family Attribution:** Verifies "VX Family" classification during cross-referencing.
*   **Secure Storage:** Samples are saved as encrypted `.zip` archives (Standard password: `infected`).
*   **Metadata Preservation:** Retains original filenames and generates comprehensive JSON metadata for each artifact.

## Installation

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/username/indiFinder.git
    cd indiFinder
    ```

2.  **Set Up Virtual Environment:**
    ```bash
    python -m venv venv
    # Windows:
    .\venv\Scripts\activate
    # Linux/Mac:
    source venv/bin/activate
    ```

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

5.  **Build from Source (Optional):**
    To create a standalone executable (`.exe`):
    ```bash
    pip install pyinstaller
    pyinstaller --onefile --name indiFinder src/main.py
    # Output: dist/indiFinder.exe
    ```

    **For Linux Users:**
    A helper script is available to automate the build process:
    ```bash
    chmod +x scripts/build_linux.sh
    ./scripts/build_linux.sh
    # Output: dist/indiFinder
    ```

## Configuration

1.  Initialize the environment configuration:
    ```bash
    cp .env.example .env
    ```
2.  Edit `.env` and provide valid API keys for the desired services:
    ```ini
    MALWARE_BAZAAR_API_KEY=your_key_here
    HYBRID_ANALYSIS_API_KEY=your_key_here
    ```

## Usage

## Usage

### Interactive Mode (Default)
Run the script without arguments to launch the interactive menu:
```bash
python src/main.py
```

### Command-Line Interface (CLI) Mode
Run the tool non-interactively for automation or scripting:
```bash
# Example: Process specific groups with a limit of 5 downloads each
python src/main.py --groups "LockBit3.0,BlackBasta" --max-count 5

# Example: Override API key and disable strict verification
python src/main.py --mb-key "YOUR_API_KEY" --no-verify-mb-sig

# View all available options
python src/main.py --help
```

### Menu Overview
1.  **Start Download Process:** Initiates the retrieval workflow based on configured groups.
2.  **Configure API Keys:** Manage API credentials.
3.  **Configure Target Groups:** Manage the list of target ransomware families.
4.  **Configure Filters & Verification:**
    *   Date range constraints.
    *   Download limits.
    *   Verification strictness settings.

## Project Structure
```
.
├── src/                # Core application logic
├── downloads/          # Artifact storage (Created at runtime)
├── groups.txt          # Target group configuration
├── requirements.txt    # Project dependencies
├── .env                # Environment configuration (Sensitive)
└── README.md           # Documentation
```

## Disclaimer
This tool is intended for **educational and research purposes only**. The downloaded artifacts are live malware samples. They must be handled only within a secure, isolated analysis environment. The authors assume no liability for misuse.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


