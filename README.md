# ByteWrapper
Byte Wrapper—a lightweight, user-friendly utility designed to bundle your scripts, files, and installers into seamless, self-contained executable packages (.exe).  Whether you're deploying batch files, PowerShell scripts, or custom tools, Byte Wrapper helps you automate execution, hide command windows, and secure your files effortlessly.

<img width="380" height="600" alt="ByteWrapper" src="https://github.com/user-attachments/assets/d4ed8dd1-477f-45fd-b8f9-92384d363259" />
Video: https://i.imgur.com/4kn6NWz.mp4

Key Features at a Glance

    Unattended & Silent Execution: Run your scripts or installation files smoothly in the background without cluttering the desktop.
    Smart Source Handling: Simply select or drag and drop your files and source folders right into the interface.
    Flexible Output Control: Define custom extraction directories (such as %Temp% or %ProgramFiles%) and configure automated cleanup.

    Advanced Options:
        Hidden Run: Execute .bat, .cmd, or .ps1 files invisibly via an embedded VBS runner.
        Crypto & Password Protection: Encrypt archive headers and protect your packages with custom passwords.
        Custom Icons: Easily apply or extract high-resolution icons to give your packages a professional touch.
        Others are as explained by its title.
        Also Drag & Drop existing sfx/exe packages to top left main icon to review its code.

    Config Export & Import: Save your build settings into JSON configuration scripts for quick reuse and team sharing.

Getting Started

    Set your Source: Drag and drop your target file or folder into the Source Folder field.
    Configure Paths: Choose where your package extracts and which file should run automatically upon launch.
    Select Options: Toggle admin privileges, hidden execution, or compression based on your deployment needs.
    Build: Click Start Process to generate your standalone, ready-to-use .exe package!


How To Install and Run

You will need to have python and 7zip installed in your system and install necessary python components for this script to run.

First install components via cmd, second save script via notepad and name it as "Byte Wrapper.py" or download and run.

pip install PyQt6 Pillow pillow-jxl-plugin pywin32 pyinstaller
