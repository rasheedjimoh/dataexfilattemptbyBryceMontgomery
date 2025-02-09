# **Incident Investigation: Data Exfiltration Attempt by Bryce Montgomery**

## **Summary**
An internal investigation revealed that sensitive corporate files were accessed, compressed, and potentially exfiltrated. The goal was to trace the movement of these files and identify the individual responsible.

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

## **Step 6: Discovering Potential Exfiltration Tool**

Using the query below, we identified the tool used for potential exfiltration.

```kql
DeviceEvents
| where FileName in ("Q1-2025-ResearchAndDevelopment.pdf", "Q2-2025-HumanTrials.pdf", "Q3-2025-AnimalTrials-SiberianTigers.pdf", "bryce-homework-fall-2024.pdf", "Amazon-Order-123456789-Invoice.pdf", "temp___2bbf98cf.pdf")
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

✅ **Tool Identified:** `steghide.exe`

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

✅ **Two out of three files confirmed working.**

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

---

## **Step 9: Tracking File Renaming**

```kql
DeviceFileEvents
| where PreviousFileName == "secure_files.zip"
```

✅ **Renamed to:** `F:\marketing_misc.zip`

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
