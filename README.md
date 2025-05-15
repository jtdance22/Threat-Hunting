<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/jtdance22/Threat-Hunting/blob/main/Threat_Event(TOR%20Usage).md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-05-14T21:58:52.2414418Z`. These events began at `2025-05-14T21:38:49.4165584`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName contains "tor"
| where InitiatingProcessAccountName == "vulnlab1212"
| where DeviceName == 'vuln-vm-windows'
| where Timestamp >= datetime(2025-05-14T21:38:49.4165584Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```

![image](https://github.com/user-attachments/assets/bee0a489-af1e-40be-9881-cd0e51f8d85f)


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows". Based on the logs returned, at `2025-05-14T21:41:09.3282357Z`, user "vulnlab1212" on the "vuln-vm-windows" device ran the file `tor-browser-windows-x86_64-portable-14.5.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where ProcessCommandLine startswith "tor-browser-windows"
| where DeviceName == 'vuln-vm-windows'
| project Timestamp, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine

```
![image](https://github.com/user-attachments/assets/5d32d3eb-e130-4b2c-a011-113ad7db9e33)


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "vulnlab1212" actually opened the TOR browser. There was evidence that they did open it at `2025-05-14T21:45:44.3238297Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where FileName has_any("tor.exe","firefox.exe")
| where DeviceName == 'vuln-vm-windows'
| project  Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine, FileName, FolderPath, SHA256
| order by Timestamp desc

```
![image](https://github.com/user-attachments/assets/82b67b03-5f0a-4361-b897-5397c679417d)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-05-14T21:42:38.4864079Z`, user "vulnlab1212" on the "vuln-vm-windows" device successfully established a connection to the remote IP address `45.12.138.199` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\vulnlab1212\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == 'vuln-vm-windows'
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150, 443, 80)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, ActionType, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

```
![image](https://github.com/user-attachments/assets/d9a37f52-d6cd-4551-a44d-ab9e689dd971)



---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-05-14T21:38:49.4165584`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\vulnlab1212\Downloads\tor-browser-windows-x86_64-portable-14.5.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-05-14T21:41:09.3282357Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.5.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.1.exe /S`
- **File Path:** `C:\Users\vulnlab1212\Downloads\tor-browser-windows-x86_64-portable-14.5.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-05-14T21:45:44.3238297Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\vulnlab1212\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-05-14T21:42:38.4864079Z`
- **Event:** A network connection to IP `45.12.138.199` on port `9001` by user "vulnlab1212" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\vulnlab1212\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-05-14T21:42:37.5047368Z` - Connected to `107.189.6.124` on port `443`.
  - `2025-05-14T21:42:50.5921768Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-05-14T21:58:52.2414418Z`
- **Event:** The user "vulnlab1212" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\vulnlab1212\Desktop\tor-shopping-list.txt`

---

## Summary

The user "vulnlab1212" on the "vuln-vm-windows" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `vuln-vm-windows` by the user `vulnlab1212`. The device was isolated, and the user's direct manager was notified.

---
