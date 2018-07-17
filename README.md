# invade_keepass

invade_keepass is a proof of concept for extracting passwords and other sensitive information from a running KeePass process in Windows. KeePass is a popular and free password manager that runs locally. KeePass is said to have [strong security](https://keepass.info/features.html), including "Process Memory Protection" and "protected in-memory streams." However, these protections are circumvented by invade_keepass. In fairness, most local processes can be compromised in some way with sufficient access. Real-world use of invade_keepass against KeePass is unlikely, as a keylogger would be an effective and less advanced approach.

For educational use at your own risk.

## Background

KeePass provides users with the ability to copy password data to the clipboard using its interface or Ctrl+C. When this occurs, the sensitive data stored in the entry (user name, password, entry title, notes, etc.) become temporarily accessible in memory, then flushed soon after. To intercept this data, clr.dll's MarshalNative::CopyToNative function is detoured by shellcode injected into the KeePass process by invade_keepass. This shellcode saves two pointers in specific memory locations. One pointer is for the entry's password data. The other pointer is for the entry's other data. Externally, these pointers are periodically read by invade_keepass. invade_keepass is then able to format and display the sensitive information in plaintext. Keep in mind that invade_keepass can only access sensitive entry information on a "one at a time" basis as the user copies KeePass entry passwords.

clr.dll is the Microsoft .NET Common Language Runtime file. Essentially, it is the .NET engine. A vulnerability in this Microsoft file does not necessarily represent a weakness in KeePass itself.

This project is not affiliated with KeeFarce and uses a different technique.

## Requirements

* [Python 3.6+](https://www.python.org/downloads/)
* [Invade](https://github.com/cgio/invade), a Windows memory toolkit for Python (`pip install invade`)
* [KeePass 2.36](https://sourceforge.net/projects/keepass/files/KeePass%202.x/2.36/) (newer versions are not supported for safety reasons - see [KeePass security issues](https://keepass.info/help/kb/sec_issues.html))
* [x64dbg](https://x64dbg.com) is not required but recommended for experimentation
* [Multiline Ultimate Assembler](https://rammichael.com/multimate-assembler), an x64dbg plugin, is not required but recommended for experimentation

## Compatibility

* Tested with KeePass 2.36 (SHA-1: 2FCE8D337EA1848280FFC5582D919032723233D4) on Windows 10 Version 1803 x64 (OS Build 17134.165)
* Tested with clr.dll version 4.7.3131.0 (SHA-1: AF9370A09CF732DD69C2E49286DC6EC1FA24E357) from .NET version 4.0.30319 (loaded from C:\Windows\Microsoft.NET\Framework64\v4.0.30319 on test computer)

*Note: To support other clr.dll versions, at minimum, the hardcoded offsets in the shellcode would need updating.*

## Files

* **invade_keepass.py:** Main project file for extracting information from KeePass
* **shellcode.txt:** Shellcode assembly instructions written in Multiline Ultimate Assembler (MUA) for x64dbg. Using x64dbg and MUA, one can translate the assembly into a string of opcodes for injection.
* **extract_rtf.py:** Converts RTF text to plaintext. Adapted from [this gist](https://gist.github.com/gilsondev/7c1d2d753ddb522e7bc22511cfb08676). Original author is [Markus Jarderot](https://github.com/MizardX).

## Authors
* **Chad Gosselin** - [https://github.com/cgio](https://github.com/cgio)

## License
This project is licensed under the MIT License. See [LICENSE.md](LICENSE.md) for details.