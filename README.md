# Byte Wrapper

**Turn files, scripts, and installers into convenient Windows `.exe` packages.**

Byte Wrapper is a lightweight, easy-to-use Windows application for creating self-extracting executable packages. Whether you're sharing a script, distributing a collection of files, or preparing a simple installer, Byte Wrapper brings the packaging options together in one interface.

<img width="380" alt="Byte Wrapper application interface" src="https://github.com/user-attachments/assets/20295340-4d55-4746-95d1-328ced08fd08" />

## Features

- **Package files or folders** into a single `.exe` file.
- **Automatic execution:** choose a file to run after extraction, or use **Extract Only** to unpack files without launching anything.
- **Flexible extraction:** select where the contents should be extracted, including Windows locations such as `%Temp%`.
- **Optional compression and protection:** reduce package size, enable encryption, or set a password.
- **Custom appearance:** choose an icon, filename, description, and version for your package.
- **Execution options:** request administrator privileges, hide the initial command window, show a progress bar, or manage cleanup after execution.
- **Shortcut creation:** add shortcuts to the Desktop, Start Menu, or a custom location.
- **Reusable settings:** export and import configurations as JSON files.
- **Drag-and-drop support:** quickly select source files, folders, and icons.

Byte Wrapper can also display supported configuration or embedded source information from compatible EXE/SFX packages by dropping them onto the application's top-left icon. This does **not** reveal the source code of arbitrary Windows programs.

## Getting Started

### Option 1: Download the application

1. Visit the [Releases page](https://github.com/EgeGurkan/ByteWrapper/releases).
2. Download the available **Byte Wrapper** executable.
3. Run it on Windows.

### Option 2: Run from Python source

You'll need **Windows**, **Python 3.10 or newer**, and the required Python packages.

1. Download or clone this repository.
2. Open a terminal in the project folder and install the dependencies:

   ```bash
   py -m pip install PyQt6 Pillow pillow-jxl-plugin
   ```

3. Start Byte Wrapper:

   ```bash
   py "Byte Wrapper.py"
   ```

### Additional requirement for creating packages

Byte Wrapper uses **7-Zip** and the **Windows .NET Framework C# compiler (`csc.exe`)** when building executable packages. Install [7-Zip](https://www.7-zip.org/) if it is not already available. The application looks for supported 7-Zip tools in common installation locations and beside the application.

If a build cannot start, check that these tools are available on your Windows system.

## How to Use

1. **Source Folder:** choose or drag in the file or folder you want to package.
2. **Extract To:** choose the destination where the package should unpack its contents.
3. **Run File:** select the file to launch after extraction. Leave execution disabled by choosing **Extract Only** if you only want to unpack files.
4. **Output:** choose where the finished `.exe` should be saved.
5. **Customize:** set the name, icon, description, version, and any shortcut details you need.
6. **Choose options:** enable compression, password protection, or other preferences as needed.
7. Click **Start Process** to create your package.

Use **Export** to save your settings for later, and **Import** to load them again.

> **Note:** Only package and distribute files you own or have permission to share. Some options, such as administrator access or automatic execution, may trigger normal Windows security prompts. Test your finished package before distributing it.

## Build the App Yourself (Optional)

If you want to create a standalone version of the Byte Wrapper application, install PyInstaller:

```bash
py -m pip install pyinstaller
```

Then, from the repository folder, run:

```bash
py -m PyInstaller --noconfirm --clean --onefile --windowed --name "Byte Wrapper" --icon "Byte.ICO" --collect-all pillow_jxl "Byte Wrapper.py"
```

The generated application will be in the `dist` folder.

## Feedback and Contributions

Found a bug or have an idea for an improvement? Feel free to [open an issue](https://github.com/EgeGurkan/ByteWrapper/issues) or submit a pull request.
