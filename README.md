# Simple iCloud Downloader (SiD)

[🇧🇷 Leia em Português](README.pt-br.md)

A Python-based tool to download, organize, and sync photos and videos from iCloud to your local storage. It automatically organizes files by `Year/Month` and maintains a local cache to prevent duplicates, ensuring speed and data integrity.

> **⚠️ DISCLAIMER & LEGAL NOTICE**
>
> **This project is a personal utility created solely for educational purposes.**
>
> * It is **not** affiliated with, supported by, or approved by Apple Inc.
> * Use of this script is the sole responsibility of the user.
> * The author does not store, collect, or have access to any user credentials, photos, videos, or personal data.
> * This software is provided "AS IS", without warranties of any kind, as described in the MIT License.
> * **Use at your own risk.**

---

## 🚀 Features

* **Smart Synchronization:** Downloads only new files (Incremental Sync).
* **Organization:** Automatically sorts files into folders: `Download_Folder/YYYY/YYYY_MM/`.
* **Local Cache:** Uses a JSON index to track downloaded files, ensuring speed and avoiding duplicates.
* **Batch Saving:** Optimizes disk I/O by saving the index only after specific intervals, protecting SSD lifespan.
* **Resumable:** Can be interrupted (`CTRL + C`) and resumed at any time without data corruption.
* **Filtering:** Option to download only specific months.
* **Multiple Users:** Can sync multiple iCloud accounts into separate folders by setting users/folders in different config.ini files.
* **Privacy:** Session cookies are isolated in the download directory.
* **Interactive Menu:** Easy-to-use interface for common tasks.

---

## 📋 Prerequisites

* **OS:** Windows 10/11 (Primary support), Linux, or macOS.
* **Python:** Version 3.12 or newer (Tested on 3.13.3).
* **Dependencies:** `pyicloud`, `tqdm`, `requests`, `keyring`.

---

## 🐍 1. Python Installation

If you don't have Python installed:

1. Download the latest version compatible with Windows (3.12+):
   https://www.python.org/downloads/windows/

2. **Crucial Step during installation:**
   * ✅ Check **"Add Python to PATH"** at the bottom of the installer.
   * ✅ Select **"Customize installation"** → Check **"Install for all users"**.

3. After installing, confirm the version in your Command Prompt:
   ```bash
   python --version
   ```

---

## 📦 2. Setting up Virtual Environment (venv)

It is highly recommended to use a virtual environment to keep dependencies isolated.

1. Open **Command Prompt** or PowerShell.
2. Navigate to the folder where you placed the script:
   ```bash
   cd C:\Simple_iCloud_Downloader\
   ```
3. Create the virtual environment:
   ```bash
   python -m venv venv
   ```
4. **Activate** the environment:
   * **Windows:**
     ```bash
     venv\Scripts\activate
     ```
   * **Linux/macOS:**
     ```bash
     source venv/bin/activate
     ```
   
   *You should see `(venv)` appear at the beginning of your command line prompt.*

---

## 📥 3. Installing Dependencies

With the virtual environment **activated** (look for the `(venv)` prefix), run:

```bash
pip install pyicloud tqdm requests future keyring
```
*(Or use `pip install -r requirements.txt` if you have the file)*

If pip requests an update, run:
```bash
python -m pip install --upgrade pip
```

---

## ⚙️ Configuration

Create a file named `config.ini` in the same folder as the script:

```ini
[icloud]
user = your_apple_id@email.com
download_base = C:\Backup_iCloud\My_Name\Photos
```

* **config.sample.ini**: You can use the provided `config.sample.ini`, change its contents and then save as `config.ini` for convenience.
* **user**: Your Apple ID email.
* **download_base**: The absolute path where photos/videos will be saved. A `_cache` folder will be created inside this directory automatically to store the index and session cookies.
* **My_Name**: Notice the `My_Name` folder in the example path. This is not essential. It could simply be `C:\Backup_iCloud_Photos`, but it makes it easier to identify which user it belongs to, especially if you use this script to sync multiple Apple/iCloud accounts.
* **Multiple Users**: Default account to sync always fetch settings from `config.ini`. If you want to sync photos and folders for multiple users, create separete config files (`config_UserA.ini`, `config_John.ini`, `config_Anna.ini`). Then, in order to tell the script to use the settings from these other config files, add the parameter `--config "config_John.ini"`. 

---

## 💻 Usage

Make sure your virtual environment is active (`venv\Scripts\activate`).

### Interactive Menu (Recommended)
Simply run the script without arguments:

```bash
python sid.py
```

You will see a menu like this:
```text
=== Simple iCloud Downloader - Quick Menu ===
1. Scan Files ( --scan )
2. Download Everything ( --download )
3. Download Only Specified Months ( --download --filter ... )
4. View Download Stats ( --view )
5. Terminate iCloud Session ( --logout )
q. Quit
```

### CLI Commands (Advanced)

| Command | Description |
| :--- | :--- |
| `python sid.py --scan` | Scans the iCloud library and updates the local index without downloading content. |
| `python sid.py --download` | Downloads all missing files found in the index. |
| `python sid.py --view` | Displays a visual dashboard of the download progress by month (makes use of the cached index). |
| `python sid.py --logout` | Deletes local session files/cookies from the cache folder. |

#### Advanced Parameter: Multiple Users
To instruct the script to use a config file other than the default `config.ini`, thus allowing to sync data for multiple iCloud users and into different folders:
```bash
python sid.py --download --config "other_config.ini"
```

#### Advanced Parameter: Filtering
To download only specific months (e.g., January and May of 2023):
```bash
python sid.py --download --filter "2023-01;2023-05"
```
*Note: The scan is always performed on the full library to maintain index integrity; the filter applies only to the download phase.*

### Typical Usage Scenarios

#### Scenario 1: The Full Backup (Anna)
Anna wants to download all her photos and videos to her backup storage hard drive.

1.  Anna plugs in her external drive (e.g., `D:\`) and her `config.ini` points to `D:\iCloud_Backup\Anna`.
2.  She runs `python sid.py`, which opens the **Quick Menu**. She selects **Option 2 (Download Everything)**.
3.  The script scans her entire library and then begins downloading all missing files. This first run can take a long time.
4.  Once finished, she runs `python sid.py` again and selects **Option 4 (View Download Stats)**. It shows 100% for all months. She can now safely unplug her backup drive.
5.  A month later, she plugs in the drive, runs `python sid.py`, and selects **Option 2 (Download Everything)** again. The script quickly scans, finds only the 50 new photos, downloads them, and finishes in minutes. Her backup is now up to date.

#### Scenario 2: The Selective Archive (John)
John wants to check how his photos are distributed to see if he can remove old data to free up iCloud space.

1.  John wants to analyze before downloading. He runs `python sid.py --scan`. The script scans his 70,000 items and builds the local `index.json` file, but downloads no content.
2.  He runs `python sid.py --view`. He sees that "2016-11" is taking up 40 GB due to long videos he doesn't need in the cloud anymore.
3.  To back up just that month, he runs `python sid.py --download --filter "2016-11"`.
4.  The script scans all items (for integrity) but only downloads the files from November 2016.
5.  He runs `python sid.py --view` again to confirm that the "2016-11" line now shows 100%. After checking the files are safe on his local drive, he can confidently delete them from iCloud to free up space.

---

## 📂 Directory Structure

After running, your `download_base` will look like this:

```text
C:\Backup_iCloud\My_Name\Photos\
                      ├── _cache\
                      │   ├── index.json          # Metadata database
                      │   └── ...session files... # Auth cookies (isolated per config)
                      ├── 2023\
                      │   ├── 2023_01\
                      │   │   ├── IMG_001.JPG
                      │   │   └── VIDEO_002.MOV
                      │   └── 2023_02\
                      └── 2024\
                          └── ...
```

---

## ❓ Troubleshooting

* **2FA Request:** On the first run, you will be asked to enter the 2FA code sent to your Apple device.
* **Error 503 (Service Unavailable):** If you see this error, Apple is rate-limiting your requests.
    * *Solution:* Wait 30 to 60 minutes and try again.
* **"Keyring" Errors:** If you have issues with password storage, ensure your OS credential locker is accessible.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.