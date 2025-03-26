[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Follow @JimKwik_X](https://img.shields.io/twitter/follow/JimKwik_X?style=social)](https://x.com/JimKwik_X)

# A DLL Shellcode Loader POC

![image](Images/loader.png)

# Techniques used:
- NTDLL.dll unhooking
- Anti analysis by self deleting after execution
- [Threadless injection](https://github.com/CCob/ThreadlessInject) with  with HWBP
- Remote payload download over HTTPs with a customed header for authtication
- VEH unhooking
- DLL sideload
- Payload AES encryption on the fly 

Compile in Visual Studio -> `x64` -> `Release`

⚠️ Disclaimer: Always tweak the code during an enagament, this is just a POC but its not good to add everything in one loader. Its better to use stagers to prevent the main C2 shellcode gets burnt. 


Click [here](https://drive.google.com/file/d/1LenFbhhj8n7esZXn6NXPdZ-pDy8bTdjx/view) to see the full demo.
