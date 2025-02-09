# **Incident Investigation: Data Exfiltration Attempt by Bryce Montgomery**

![image](https://github.com/user-attachments/assets/7f745959-5e53-4fc0-853e-55b60d0eca6c)

## **Summary**
An internal investigation revealed that sensitive corporate files were accessed, compressed, and potentially exfiltrated. The goal was to trace the movement of these files and identify the individual responsible.



![2025-02-09_23-44_1](https://github.com/user-attachments/assets/bebf0744-56e3-4aa3-b150-6e59dc5c425f)

---

## **Step 1: Identifying the Initial File Access**
We started by identifying the SHA256 hash of the sensitive document using the query below:

```kql
DeviceFileEvents
| where Timestamp > ago(7d)  
| where InitiatingProcessAccountName == "bmontgomery"  
| where DeviceName == "corp-ny-it-0334"  
| where ActionType in ("FileRenamed", "FileCreated", "FileModified") and SHA256 != ""
| where FileName endswith ".pdf" or FileName endswith ".docx" or FileName endswith ".xlsx"  // Adjust for corporate files
| project Timestamp, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine  
| order by Timestamp desc
| distinct SHA256 
```

✅ **SHA256 Found:**  
`ec727a15bf51e027b9a1bbf097cfa9d57e46aa159bfa37f68dca5e3c5df5af3d`

![2025-02-09_23-37](https://github.com/user-attachments/assets/5c6db7fc-a75f-4c42-82af-101468ca19de)


---

## **Step 2: Checking if the File Was Accessed by Other Devices**

```kql
DeviceFileEvents
| where Timestamp > ago(7d)  
| where FileName contains "Q1-2025-ResearchAndDevelopment.pdf"  
| where DeviceName != "corp-ny-it-0334"  
| project Timestamp, DeviceName, FileName, FolderPath  
| order by Timestamp asc
```

🔍 **Result:** No other device accessed the file.

---

## **Step 3: Identifying Other Users on Bryce’s Workstation**

```kql
DeviceLogonEvents
| where Timestamp > ago(7d)
| where DeviceName == "corp-ny-it-0334"
| distinct AccountName
| order by AccountName asc
```

👤 **Other Accounts Found:**  
`dwm-1, dwm-2, dwm-3, test, umfd-0, umfd-1, umfd-2, umfd-3`


![2025-02-09_23-39](https://github.com/user-attachments/assets/b3070088-14ce-4c2e-9a21-3d037365be73)




We then checked if these accounts were used on any other devices.

```kql
DeviceLogonEvents
| where Timestamp > ago(7d)  
| where AccountName in ("dwm-1", "dwm-2", "dwm-3", "test", "umfd-0", "umfd-1", "umfd-2", "umfd-3", "bmontgomery")  
| where DeviceName != "corp-ny-it-0334"  
| project Timestamp, DeviceName, AccountName  
| order by Timestamp asc
```

🚫 **Result:** No relevant findings.

![2025-02-09_23-40](https://github.com/user-attachments/assets/cc130c66-28a8-4f96-843a-f214334a339f)


---

## **Step 4: Locating the File on Another Device using SHA256 thumbprint**

```kql
DeviceFileEvents
| where Timestamp > ago(7d)  
| where SHA256 == "ec727a15bf51e027b9a1bbf097cfa9d57e46aa159bfa37f68dca5e3c5df5af3d"  
| where DeviceName != "corp-ny-it-0334"  
| project Timestamp, DeviceName, FileName, FolderPath  
| order by Timestamp asc
```

✅ **File Found On:** `lobby-fl2-ae5fc`


![2025-02-09_23-42](https://github.com/user-attachments/assets/0b0025fd-97b4-4cd7-839d-1a676ae1d46d)


---

## **Step 5: Discovering Additional Files**

```kql
DeviceFileEvents
| where PreviousFileName in ("Q1-2025-ResearchAndDevelopment.pdf", "Q2-2025-HumanTrials.pdf", "Q3-2025-AnimalTrials-SiberianTigers.pdf")
```

📁 **Additional Files Found:**  
- `bryce-homework-fall-2024.pdf`  
- `Amazon-Order-123456789-Invoice.pdf`  
- `temp___2bbf98cf.pdf`  

![2025-02-09_23-42_1](https://github.com/user-attachments/assets/64378df6-4370-4189-a352-e62a5c07cbce)



## **Step 6: Discovering Potential Exfiltration Tool**

Using the query below, we identified the tool used for potential exfiltration.

```kql
DeviceEvents
| where FileName in ("Q1-2025-ResearchAndDevelopment.pdf", "Q2-2025-HumanTrials.pdf", "Q3-2025-AnimalTrials-SiberianTigers.pdf", "bryce-homework-fall-2024.pdf", "Amazon-Order-123456789-Invoice.pdf", "temp___2bbf98cf.pdf")
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

✅ **Tool Identified:** `steghide.exe`

![2025-02-09_23-43](https://github.com/user-attachments/assets/bc81a8d5-03e4-449c-b93c-a0f99dd142fb)


---

## **Step 7: Finding Stego File Paths**

```kql
DeviceProcessEvents
| where ProcessCommandLine contains "steghide.exe"
| distinct ProcessCommandLine
```

📂 **Extracted Files Paths:**  
- `c:\programdata\suzie-and-bob.bmp`  
- `c:\programdata\bryce-fishing.bmp`  
- `c:\programdata\bryce-and-kid.bmp`  

✅ **Two out of three distinct files confirmed working.**

![2025-02-09_23-44](https://github.com/user-attachments/assets/9003d350-daa7-467f-9afe-8bcd3870ac49)





---

## **Step 8: Identifying the Compression of Files**

```kql
DeviceProcessEvents
| where ProcessCommandLine contains "suzie-and-bob.bmp" or ProcessCommandLine contains "bryce-and-kid.bmp" 
  or ProcessCommandLine contains "bryce-fishing.bmp" or ProcessCommandLine contains "bryce-homework-fall-2024.pdf"
  or ProcessCommandLine contains "amazon-order-123456789-invoice.pdf" or ProcessCommandLine contains "temp__2bbg98cf.pdf"
| project SHA256, ProcessCommandLine, FileName
| distinct SHA256
```

✅ **SHA256 of the Zipped File:**  
`707f415d7d581edd9bce99a0429ad4629d3be0316c329e8b9ebd576f7ab50b71`

The zip file `secure_files.zip` was found to contain the stego images.

![2025-02-09_23-45](https://github.com/user-attachments/assets/e9fd8443-944b-48e5-9c66-31af78fb53af)


---

## **Step 9: Tracking File Renaming**

```kql
DeviceFileEvents
| where PreviousFileName == "secure_files.zip"
```

✅ **Renamed to:** `F:\marketing_misc.zip`

![2025-02-09_23-45_1](https://github.com/user-attachments/assets/5462067b-c924-40a5-985a-9c7ea6b26c75)


---

## **Step 10: Identifying the Time of File Rename**

```kql
DeviceFileEvents
| where PreviousFileName contains "marketing_misc.zip"
```

✅ **Timestamp of Evidence (UTC):**  
`2025-02-05T08:57:32.2582822Z`

---

## **Conclusion**
Bryce Montgomery attempted to exfiltrate sensitive corporate documents by:
- Hiding them in stego images
- Compressing them using `7z.exe`
- Renaming and potentially exfiltrating them

✅ **Final Submission URL:**  
```
https://cyberrangeautomation1.azurewebsites.net/api/hunt?timestamp=2025-02-05T08:57:32.2582822Z
```

---

### **Key Takeaways**
- **Adversaries use multiple evasion tactics:** steganography, file compression, and renaming.
- **Monitoring file movements is crucial:** tracking hashes and filenames helps.
- **Process tracking provides forensic evidence:** linking `steghide.exe` and `7z.exe` to Bryce’s activity confirmed intent.

🔍 **Case Closed: Bryce Montgomery attempted to steal corporate data.** 🚨
