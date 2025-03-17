# **Incident Investigation: Data Exfiltration Attempt by Bryce Montgomery**

![image](https://github.com/user-attachments/assets/7f745959-5e53-4fc0-853e-55b60d0eca6c)

## **Summary of Incident**
This investigation focuses on a suspected data exfiltration attempt by Bryce Montgomery, an employee within the company. It was observed that sensitive corporate files, including research and development documents, were accessed and possibly transmitted outside the network without authorization. Our task was to trace the movement of these files, identify any potential signs of exfiltration, and pinpoint who was responsible for the incident.

![2025-02-09_23-44_1](https://github.com/user-attachments/assets/bebf0744-56e3-4aa3-b150-6e59dc5c425f)

---

## **Step 1: Identifying the Initial File Access**
I began the investigation by identifying the file accessed by Bryce Montgomery. To ensure I track the file accurately, I started by searching for the SHA256 hash of the file. The SHA256 hash is a unique identifier for the file and helps us track its movement across systems, regardless of the file's name or location.

I searched the device logs for any events related to this specific file, including file renaming, creation, or modification, within the past 7 days.

```kql
DeviceFileEvents
| where Timestamp > ago(7d)  
| where InitiatingProcessAccountName == "bmontgomery"  
| where DeviceName == "corp-ny-it-0334"  
| where ActionType in ("FileRenamed", "FileCreated", "FileModified") and SHA256 != ""
| where FileName endswith ".pdf" or FileName endswith ".docx" or FileName endswith ".xlsx"  
| project Timestamp, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine  
| order by Timestamp desc
| distinct SHA256 
```

✅ **SHA256 Found:**  
`ec727a15bf51e027b9a1bbf097cfa9d57e46aa159bfa37f68dca5e3c5df5af3d`

This confirmed that the file in question was accessed and potentially manipulated on Bryce's workstation.

![2025-02-09_23-37](https://github.com/user-attachments/assets/5c6db7fc-a75f-4c42-82af-101468ca19de)

---

## **Step 2: Checking if the File Was Accessed by Other Devices**
After confirming that Bryce accessed the file on his workstation, I expanded the search to check if the file had been accessed on any other devices within the network. By querying for the same file, I could verify if the file was copied, transferred, or otherwise accessed from another machine.

```kql
DeviceFileEvents
| where Timestamp > ago(7d)  
| where FileName contains "Q1-2025-ResearchAndDevelopment.pdf"  
| where DeviceName != "corp-ny-it-0334"  
| project Timestamp, DeviceName, FileName, FolderPath  
| order by Timestamp asc
```

🔍 **Result:** No other devices accessed the file, indicating that the file had not been moved or shared across multiple workstations within the network.

---

## **Step 3: Identifying Other Users on Bryce’s Workstation**
To determine if other users had access to the workstation, I identified all account names associated with Bryce's device during the past 7 days. This would help us understand if there were any potential lapses in security or if someone else might have accessed the sensitive data.

```kql
DeviceLogonEvents
| where Timestamp > ago(7d)
| where DeviceName == "corp-ny-it-0334"
| distinct AccountName
| order by AccountName asc
```

👤 **Other Accounts Found:**  
`dwm-1, dwm-2, dwm-3, test, umfd-0, umfd-1, umfd-2, umfd-3`

This search showed that multiple accounts, besides Bryce's, had logged into the system. I then checked if any of these other accounts had accessed the file or made modifications.

```kql
DeviceLogonEvents
| where Timestamp > ago(7d)  
| where AccountName in ("dwm-1", "dwm-2", "dwm-3", "test", "umfd-0", "umfd-1", "umfd-2", "umfd-3", "bmontgomery")  
| where DeviceName != "corp-ny-it-0334"  
| project Timestamp, DeviceName, AccountName  
| order by Timestamp asc
```

🚫 **Result:** There were no indications that any other accounts accessed the file, narrowing down the scope of the investigation to Bryce’s activities.

![2025-02-09_23-39](https://github.com/user-attachments/assets/b3070088-14ce-4c2e-9a21-3d037365be73)

---

## **Step 4: Locating the File on Another Device Using the SHA256 Thumbprint**
Since the file was not accessed on any other device by name, I decided to search for the file using its unique SHA256 hash across the network. This would help us determine if the file was moved to another location or accessed from an external machine.

```kql
DeviceFileEvents
| where Timestamp > ago(7d)  
| where SHA256 == "ec727a15bf51e027b9a1bbf097cfa9d57e46aa159bfa37f68dca5e3c5df5af3d"  
| where DeviceName != "corp-ny-it-0334"  
| project Timestamp, DeviceName, FileName, FolderPath  
| order by Timestamp asc
```

✅ **File Found On:** `lobby-fl2-ae5fc`

I found that the file had been transferred or accessed on a different device named `lobby-fl2-ae5fc`, suggesting that the file might have been moved or copied.

![2025-02-09_23-42](https://github.com/user-attachments/assets/0b0025fd-97b4-4cd7-839d-1a676ae1d46d)

---

## **Step 5: Discovering Additional Files**
I expanded the investigation by searching for any other files that may have been accessed or manipulated in conjunction with the primary file. Our hypothesis was that the exfiltration attempt might have involved multiple files that could be related or similarly compromised.

```kql
DeviceFileEvents
| where PreviousFileName in ("Q1-2025-ResearchAndDevelopment.pdf", "Q2-2025-HumanTrials.pdf", "Q3-2025-AnimalTrials-SiberianTigers.pdf")
```

📁 **Additional Files Found:**  
- `bryce-homework-fall-2024.pdf`  
- `Amazon-Order-123456789-Invoice.pdf`  
- `temp___2bbf98cf.pdf`  

This revealed a collection of files that were potentially targeted for exfiltration.

![2025-02-09_23-42_1](https://github.com/user-attachments/assets/64378df6-4370-4189-a352-e62a5c07cbce)

---

## **Step 6: Discovering the Exfiltration Tool**
Next, I investigated the possibility that Bryce used a tool to hide or compress the files before attempting to exfiltrate them. Our analysis indicated the presence of `steghide.exe`, a tool often used for hiding data within other files (e.g., images or audio files).

I reviewed the device logs for any signs of `steghide.exe` being executed in relation to the sensitive files.

```kql
DeviceEvents
| where FileName in ("Q1-2025-ResearchAndDevelopment.pdf", "Q2-2025-HumanTrials.pdf", "Q3-2025-AnimalTrials-SiberianTigers.pdf", "bryce-homework-fall-2024.pdf", "Amazon-Order-123456789-Invoice.pdf", "temp___2bbf98cf.pdf")
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

✅ **Exfiltration Tool Identified:** `steghide.exe`

This confirmed that Bryce used steganography, a technique that hides data within other file types, to obscure his exfiltration efforts.

![2025-02-09_23-43](https://github.com/user-attachments/assets/bc81a8d5-03e4-449c-b93c-a0f99dd142fb)

---

## **Step 7: Finding the Stego File Paths**
Once I confirmed the use of `steghide.exe`, I then tracked the location of the hidden files. The tool had likely embedded sensitive files within images, and I located these files using the tool’s command line references.

```kql
DeviceProcessEvents
| where ProcessCommandLine contains "steghide.exe"
| distinct ProcessCommandLine
```

📂 **Extracted File Paths:**  
- `c:\programdata\suzie-and-bob.bmp`  
- `c:\programdata\bryce-fishing.bmp`  
- `c:\programdata\bryce-and-kid.bmp`  

These files were likely intended for transmission outside the company.

✅ **Two out of three files confirmed to work.**

![2025-02-09_23-44](https://github.com/user-attachments/assets/9003d350-daa7-467f-9afe-8bcd3870ac49)

---

## **Step 8: Identifying the Compression of Files**
Bryce’s next step was to compress the files using `7z.exe` before transmitting them. I traced the command lines to identify the specific file paths that were compressed.

```kql
DeviceProcessEvents
| where ProcessCommandLine contains "suzie-and-bob.bmp" or ProcessCommandLine contains "bryce-and-kid.bmp" 
  or ProcessCommandLine contains "bryce-fishing.bmp" or ProcessCommandLine contains "bryce-homework-fall-2024.pdf"
  or ProcessCommandLine contains "amazon-order-123456789-invoice.pdf" or ProcessCommandLine contains "temp__2bbg98cf.pdf"
| project SHA256, ProcessCommandLine, FileName
| distinct SHA256
```

✅ **SHA256 of the Compressed File:**  
`707f415d7d581edd9bce99a0429ad4629d3be0316c329e8b9ebd576f7ab50b71`

This confirmed that the compressed file, `secure_files.zip`, contained hidden files, including the stego images.

![2025-02-09_23-45](https://github.com/user-attachments/assets/e9fd8443-944b-48e5-9c66-31af78fb53af)

---

## **Step 9: Tracking the Renaming of the Compressed File**
Next, I observed that the compressed file was renamed, possibly to disguise its contents or evade detection.

```kql
DeviceFileEvents
| where PreviousFileName == "secure_files.zip"
```

✅ **Renamed to:** `F:\marketing_misc.zip`

![2025-02-09_23-45_1](https://github.com/user-attachments/assets/5462067b-c924-40a5-985a-9c7ea6b26c75)

This renaming was an attempt to make the file appear less suspicious.

---

## **Step 10: Identifying the Time of File Rename**
Finally, I tracked the exact time when the file was renamed, as this information would help establish the timeline of the exfiltration attempt.

```kql
DeviceFileEvents
| where PreviousFileName contains "marketing_misc.zip"
```

✅ **Timestamp of the File Rename:**  
`2025-02-05T08:57:32.2582822Z`

This timestamp marks the time at which the files were potentially ready for exfiltration.

---

## **Conclusion**
The investigation revealed that Bryce Montgomery attempted to exfiltrate sensitive corporate data using a series of covert methods:
- **Data hiding:** Using steganography (`steghide.exe`) to hide sensitive files in image formats.
- **File compression:** Compressing the hidden files into a zip archive to further obscure their content.
- **File renaming:** Renaming the compressed file to make it less recognizable.

✅ **Final Submission URL:**  
```
https://cyberrangeautomation1.azurewebsites.net/api/hunt?timestamp=2025-02-05T08:57:32.2582822Z
```

---

### **Key Takeaways**
- **Advanced evasion techniques:** The exfiltration used steganography and file compression to avoid detection.
- **File tracking is essential:** Hashes and file names are critical in tracing file movements and identifying suspicious activities.
- **Process tracking is vital:** By monitoring and analyzing process executions, I can identify tools like `steghide.exe` that are used to conceal illicit activity.

🔍 **Case Closed: Bryce Montgomery attempted to steal corporate data using sophisticated techniques.** 🚨

---
