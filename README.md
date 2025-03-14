# URUK

URUK - A Secure File Encryption and Email Sender Program

Program Summary :

URUK is a robust, user-friendly application designed for secure file encryption, digital signing, and email transmission, developed by Ali Al-Kazaly, known as "aLi GeNiUs The Hackers." The program, currently at version 1.0.0.0 (2025), provides a comprehensive solution for users who need to protect sensitive data and share it securely via email. Built using Python and the Tkinter library for its graphical user interface (GUI), URUK leverages the cryptography library to implement strong encryption mechanisms, including AES (Advanced Encryption Standard) and RSA (Rivest–Shamir–Adleman) for encryption and digital signatures.

Below is a summary of its key features:

Key Features

    Password Protection:
        The program requires a password to access its main interface, ensuring only authorized users can use it.
        On the first run, users set an initial password (minimum 8 characters), which is encrypted using Fernet symmetric encryption (AES-128 in CBC mode) and stored securely in a password.enc file, with the encryption key in key.key.
        A "Change Password" option allows users to update the password if they know the old one.
    File Encryption and Signing:
        Users can select a file and encrypt it using AES (with selectable key lengths: 128, 192, or 256 bits).
        The file is digitally signed using RSA (2048-bit key) to ensure integrity and authenticity.
        Keys (public, private, and AES) are displayed in copyable text boxes and can be saved as files for later use.
    Email Configuration and Sending:
        Users can configure an SMTP server (e.g., Gmail with smtp.gmail.com and port 587) to send encrypted files and private keys to recipients.
        The email section allows users to input a recipient’s email address and send the encrypted file and private key as attachments.
    File Decryption:
        The decryption section allows users to select an encrypted file, load the corresponding private key and AES key, and decrypt the file.
        The program verifies the digital signature during decryption to ensure the file hasn’t been tampered with.
    User Interface:
        The GUI is divided into four resizable sections: Encryption, Email Configuration, Email Sending, and Decryption.
        An "About" button at the top displays program details:

        APP : URUK

        DEVELOPER : Ali Al-Kazaly  " aLi GeNiUs The Hackers "

        VERSION : 1.0.0.0  (2025)

    Security:
        Passwords are encrypted using Fernet, ensuring they are stored securely.
        File encryption uses AES with a randomly generated key, and RSA ensures secure digital signatures.
        The program prevents unauthorized access by requiring a correct password to proceed.

How to Run URUK on All Operating Systems
URUK is written in Python, making it cross-platform. However, to run it on different operating systems (Windows, Linux, macOS), you need to set up the environment and convert the script into an executable for ease of use. Below are the steps to run URUK on all OSes:
Prerequisites

    Python: Python 3.6 or higher is required.
    Dependencies: The program uses the following Python libraries:
        tkinter (usually included with Python)
        cryptography
        smtplib (included with Python for email functionality)

Step 1: Install Python and Dependencies
Windows

    Download and install Python from python.org. Ensure you check "Add Python to PATH" during installation.
    Open a Command Prompt and install the required library:
    bash

    pip install cryptography

Linux

    Most Linux distributions come with Python pre-installed. Check your version:
    bash

    python3 --version

    If not installed, install it (e.g., on Ubuntu):
    bash

    sudo apt update
    sudo apt install python3 python3-pip

    Install the cryptography library:
    bash

    pip3 install cryptography

    Ensure Tkinter is installed (e.g., on Ubuntu):
    bash

    sudo apt install python3-tk

macOS

    macOS typically includes Python, but you may need to install a newer version. Use Homebrew:
    bash

    brew install python3

    Install the cryptography library:
    bash

    pip3 install cryptography

    Tkinter should be included with Python on macOS.

Step 2: Save the Code
Copy the latest version of the URUK code (provided in previous responses) into a file named URUK.py. Ensure you’re using the version with password protection, as it’s the most secure.
Step 3: Run the Code Directly (For Development)
You can run the Python script directly if Python is set up:

    Windows/Linux/macOS:
    bash

    python3 URUK.py

    This will launch the program, prompting you to set an initial password (or use an existing one if already set).

Step 4: Convert to Executable for All OSes
To make URUK user-friendly and run without requiring Python, convert it to a standalone executable using PyInstaller.
Install PyInstaller
bash

pip3 install pyinstaller

Windows (Create .exe)

    Open a Command Prompt in the directory containing URUK.py.
    Run:
    bash

    pyinstaller --onefile --noconsole URUK.py

        --onefile: Bundles everything into a single .exe.
        --noconsole: Hides the console window (since it’s a GUI app).
    Find the executable in the dist folder (dist/URUK.exe).
    Double-click URUK.exe to run the program.

Linux (Create Binary)

    Open a terminal in the directory containing URUK.py.
    Run:
    bash

    pyinstaller --onefile URUK.py

    Find the binary in the dist folder (dist/URUK).
    Make it executable and run:
    bash

    chmod +x dist/URUK
    ./dist/URUK

macOS (Create Binary)

    Open a terminal in the directory containing URUK.py.
    Run:
    bash

    pyinstaller --onefile URUK.py

    Find the binary in the dist folder (dist/URUK).
    Make it executable and run:
    bash

    chmod +x dist/URUK
    ./dist/URUK

Notes on Executables

    The executable includes all dependencies (Tkinter, cryptography, etc.), so Python doesn’t need to be installed on the target system.
    On Windows, you may need to allow the .exe through Windows Defender (it might flag it as an unknown app).
    On macOS, you may need to allow the app in "Security & Privacy" settings (Gatekeeper might block it initially).

Step 5: Cross-Platform Considerations

    Build on Target OS: For best results, build the executable on the target operating system (e.g., build the .exe on Windows). If cross-compiling, tools like Wine (for Windows on Linux) can help.
    File Permissions: On Linux/macOS, ensure password.enc and key.key have restrictive permissions:
    bash

    chmod 600 password.enc key.key

    Dependencies: If the executable fails to run due to missing dependencies, ensure all libraries are included by adding --hidden-import flags in PyInstaller (e.g., --hidden-import cryptography).

How to Use URUK
Initial Setup

    Run the Program:
        Launch the executable (URUK.exe on Windows, ./URUK on Linux/macOS) or run the script (python3 URUK.py).
        On the first run, a "Set Initial Password" window appears.
    Set Password:
        Enter a password (minimum 8 characters) and click "Set Password".
        The password is encrypted and saved, and the login window appears.
    Login:
        Enter the password you set and click "Login".
        If correct, the main application window opens; otherwise, an error appears.

Using the Main Application
The main window is divided into four sections: Encryption, Email Configuration, Email Sending, and Decryption.
1. Encryption Section

    Select File: Click "Select File to Encrypt" and choose a file.
    Choose AES Key Length: Select 128, 192, or 256 bits from the dropdown.
    Encrypt & Sign: Click "Encrypt & Sign File". The file is encrypted with AES and signed with RSA.
    View Keys: The public key, private key, and AES key are displayed in copyable text boxes.
    Save Keys: Use the "Save" buttons to save each key as a file (e.g., .pem for RSA keys, .key for AES key).
    Save Encrypted File: Click "Save Encrypted File" to save the encrypted file (.enc extension).

2. Email Configuration Section

    Enter Details:
        Sender Email: Your email address (e.g., your.email@gmail.com).
        Sender Password: For Gmail, use an App Password (generate one at Google Account Security under 2-Step Verification > App Passwords).
        SMTP Server: smtp.gmail.com for Gmail.
        SMTP Port: 587 for Gmail.
    Save Config: Click "Save Email Config" to store the settings.

3. Email Section

    Enter Recipient Email: Input the recipient’s email address.
    Send Email: Click "Send Encrypted File & Key". The encrypted file and private key are attached and sent via email.
    Confirmation: A success or error message appears based on the email send status.

4. Decryption Section

    Select File: Click "Select File to Decrypt" and choose the .enc file.
    Load Keys:
        Select the private key (.pem file) when prompted.
        Select the AES key (.key file) when prompted.
    Select Original File: For signature verification, select the original unencrypted file.
    Decrypt: Click "Decrypt File". The file is decrypted, and the signature is verified.
    Save Decrypted File: Choose a location to save the decrypted file (.dec extension).

5. Change Password

    In the login window, enter the current password and click "Change Password".
    Enter a new password and confirm it. If successful, use the new password to log in.

6. About Information

    Click the "About" button at the top to view program details.

Security Best Practices

    Backup Keys: Keep backups of password.enc and key.key, as losing them will lock you out of the program.
    Secure Password: Choose a strong password with letters, numbers, and special characters.
    Protect Files: Ensure the password.enc and key.key files are not accessible to others (e.g., store them in a secure location or encrypt the directory).
    Email Security: Use an App Password for email to avoid exposing your main password.

Conclusion
URUK is a powerful tool for securely encrypting files, signing them, and sharing them via email, with a focus on user access control through password protection. Its cross-platform compatibility ensures it can be used on Windows, Linux, and macOS with minimal setup. By following the steps to install dependencies, convert to an executable, and use its intuitive GUI, users can protect sensitive data and communicate securely. Developed by Ali Al-Kazaly "aLi GeNiUs The Hackers," URUK is a testament to practical, secure software design for modern data protection needs.
For further assistance, refer to the program’s documentation or contact the developer. Happy encrypting!
