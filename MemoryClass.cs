//Note* Some namespaces are not used, they are there for future releases.
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using System.Drawing;

using Microsoft.Win32;


//***************************************************************************************
//MemoryClass v1.2
//Visual Studio 2008 - 2010
//Microsoft .NET Framework 4+ 
//Credits:
//---------------------------------------------------------------------------------------
//Delta Hackers / Null Coders
//http://www.delta-h.net
//http://www.null-coders.com
//Mr.A
//Kryptech
//Ghoster
//Iteration
//Solo
//Remedy
//StevePwns
//---------------------------------------------------------------------------------------
//Game Deception
//http://www.gamedeception.net
//Azorbix
//Patrick
//d0m1n1k
//atom0s
//---------------------------------------------------------------------------------------
//Cheat Engine
//http://forum.cheatengine.org
//samuri25404
//Wiccaan
//ej52
//***************************************************************************************




//***************************************************************************************
//Usage: Add code below to your form.
//
//Add to forms namespace
//  using TrainerClass;
//
//Add to forms partial class:
//  Trainer trainer = new Trainer();
//
//Add this to forms load eventhandler:
//  if (!trainer.SetCurrentProcess("name of exe here"))
//  {
//      MessageBox.Show("Please open game window before trying to load trainer.");
//      Application.Exit();
//  }
//
//Call examples: 
//  trainer.WriteMemory(0x123456, 1234567890);
//  trainer.SendKeyString("notepad", "This is just a test", 300);
//  trainer.SendKey("notepad", TrainerApi.VKCodes.Return , 100);
//  trainer.WriteByteArray(0x123456, "9090909090");
//  trainer.InjectDLL("Name of exe here", "C:\\Hook.dll");
//  trainer.LeftMouseClick(50, 50);
//  IntPtr Addy = trainer.FindBytePattern(0x123456, 5000, "45AA3412FF", "xxxx??xx??", 0);
//  string Test = trainer.ReadText(0x123456, 4);
//  bool Test   = trainer.GetModuleBaseAddress("Name of Process", "Name of Module");
//  -------------------------------------------------------------------------------------
//  File patching Example:
//  MemoryAddress - BaseAddress  = patchOffset
//  int[] patchOffset = { 0xDC2D3, 0xDC363 };
//  byte[] patchData = { 0xEB, 0xEB };
//  trainer.PatchFile(patchOffset, patchData, @"C:\File.exe", @"C:\File.exe", true);
//***************************************************************************************

namespace TrainerClass
{
    class Trainer
    {
        public bool DownloadComplete = false;
        public int DownloadProgress = 0;

        private Process m_ProcessActive = null;
        private Process m_ProcessByteScan = null;
        private IntPtr  m_hProcess = IntPtr.Zero;

        private byte[] m_vDumpedRegion = null;
        private IntPtr m_vAddress = IntPtr.Zero;
        private Int32  m_vSize = 0;



        //Holds start address for use in method FindBytePattern.
        private IntPtr Address
        {
            get { return this.m_vAddress; }
            set { this.m_vAddress = value; }
        }

        //Holds size of memory block for method FindBytePattern.
        private Int32 Size
        {
            get { return this.m_vSize; }
            set { this.m_vSize = value; }
        }

        //Holds Information of your active process.
        private Process ProcessActive
        {
            get { return this.m_ProcessActive; }
            set { this.m_ProcessActive = value; }
        }


        //***************************************************************************************
        // Method:    SetCurrentProcess
        // Access:    public
        // Returns:   bool
        // Parameter: string ProcessName
        // Description: Sets the process to the application you wish to manipulate
        //***************************************************************************************
        public bool SetCurrentProcess(string ProcessName)
        {
            Process[] p = Process.GetProcessesByName(ProcessName);
            if (p.Length != 0)
            {
                this.ProcessActive = p[0];
                this.m_ProcessActive = p[0];
                return true;
            }
            return false;
        }


        //***************************************************************************************
        // Method:    Open
        // Access:    private
        // Returns:   none
        // Description: Opens the handle of process to prepare for manipulation
        //***************************************************************************************
        private void Open()
        {
            TrainerApi.ProcessAccessType access;
            access = TrainerApi.ProcessAccessType.PROCESS_VM_READ
            | TrainerApi.ProcessAccessType.PROCESS_VM_WRITE
            | TrainerApi.ProcessAccessType.PROCESS_VM_OPERATION;
            m_hProcess = TrainerApi.OpenProcess((uint)access, 1, (uint)m_ProcessActive.Id);
        }


        //***************************************************************************************
        // Method:    CloseHandle
        // Access:    private
        // Returns:   none
        // Parameter: IntPtr ptrHandle
        // Description: Closes the handle to the process in which you wish to manipulate
        //***************************************************************************************
        private void CloseHandle(IntPtr ptrHandle)
        {
            int iRetValue;
            iRetValue = TrainerApi.CloseHandle(ptrHandle);
            if (iRetValue == 0)
                throw new Exception("CloseHandle Failed");
        }
        

        //***************************************************************************************
        // Method:    ReadMemory
        // Access:    public 
        // Returns:   byte[]
        // Parameter: uint MemoryAddress
        // Parameter: uint numBytesToRead
        // Description: Reads a value from a memory address in a selected process
        //***************************************************************************************
        public byte[] ReadMemory(uint MemoryAddress, uint numBytesToRead)
        {
            if (numBytesToRead > 4) numBytesToRead = 4;
            if (numBytesToRead < 1) numBytesToRead = 1;
            byte[] buffer = new byte[numBytesToRead];
            IntPtr ptrBytesRead;
            this.Open();
            TrainerApi.ReadProcessMemory(m_hProcess, (IntPtr)MemoryAddress, buffer, numBytesToRead, out ptrBytesRead);
            this.ProcessActive.Refresh();
            return buffer;
        }



        //***************************************************************************************
        // Method:    WriteMemory
        // Access:    public 
        // Returns:   none
        // Parameter: uint MemoryAddress
        // Parameter: uint numBytesToWrite
        // Description: Writes a value to a memory address in a selected process
        //***************************************************************************************
        public void WriteMemory(uint MemoryAddress, uint BytesToWrite)
        {
            byte[] bytes = null;
            bytes = BitConverter.GetBytes(BytesToWrite);

            this.Open();
            IntPtr ptrBytesWritten;
            TrainerApi.WriteProcessMemory(m_hProcess, (IntPtr)MemoryAddress, bytes, (uint)bytes.Length, out ptrBytesWritten);
            this.ProcessActive.Refresh();
            this.CloseHandle(m_hProcess);
        }


        //***************************************************************************************
        // Method:    WriteByteString
        // Access:    public 
        // Returns:   none
        // Parameter: uint MemoryAddress
        // Parameter: string bytesToWrite
        // Description: Writes a string array to a memory address in a selected process
        //***************************************************************************************
        public void WriteByteString(uint MemoryAddress, string bytesToWrite)
        {
            bytesToWrite.Replace(" ", string.Empty);
            int NumberChars = bytesToWrite.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(bytesToWrite.Substring(i, 2), 16);

            this.Open();
            IntPtr ptrBytesWritten;
            TrainerApi.WriteProcessMemory(m_hProcess, (IntPtr)MemoryAddress, bytes, (uint)bytes.Length, out ptrBytesWritten);
            this.ProcessActive.Refresh();
            this.CloseHandle(m_hProcess);
        }


        //***************************************************************************************
        // Method:    ReadByteArray
        // Access:    public 
        // Returns:   byte[]
        // Parameter: uint MemoryAddress
        // Parameter: uint numBytesToRead
        // Description: Reads an array of bytes from a memory address and returns them as a byte[]
        //***************************************************************************************
        public byte[] ReadByteArray(uint MemoryAddress, uint numBytesToRead)
        {
            byte[] buffer = new byte[numBytesToRead];
            string buffer2;
            IntPtr ptrBytesRead;

            this.Open();
            TrainerApi.ReadProcessMemory(m_hProcess, (IntPtr)MemoryAddress, buffer, numBytesToRead, out ptrBytesRead);
            this.ProcessActive.Refresh();
            this.CloseHandle(m_hProcess);
            buffer2 = BitConverter.ToString(buffer).Replace("-", string.Empty);

            int NumberChars = buffer2.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(buffer2.Substring(i, 2), 16);

            return bytes;
        }



        
        //***************************************************************************************
        // Method:    WriteByteArray
        // Access:    public 
        // Returns:   none
        // Parameter: uint MemoryAddress
        // Parameter: string bytesToWrite
        // Description: Writes a string array to a memory address in a selected process
        //***************************************************************************************
        public void WriteByteArray(uint MemoryAddress, byte[] bytesToWrite)
        {
            byte[] bytes = new byte[bytesToWrite.Length];
            for (int i = 0; i < bytesToWrite.Length; i++)
                bytes[i] = bytesToWrite[i];

            this.Open();
            IntPtr ptrBytesWritten;
            TrainerApi.WriteProcessMemory(m_hProcess, (IntPtr)MemoryAddress, bytes, (uint)bytes.Length, out ptrBytesWritten);
            this.ProcessActive.Refresh();
            this.CloseHandle(m_hProcess);
        }








        //***************************************************************************************
        // Method:    ReadText
        // Access:    public 
        // Returns:   string
        // Parameter: uint MemoryAddress
        // Parameter: uint numBytesToRead
        // Description: Reads a value from a process's memory and returns it as Text
        //***************************************************************************************
        public string ReadText(uint MemoryAddress, uint numBytesToRead)
        {
            byte[] buffer = new byte[numBytesToRead];
            IntPtr ptrBytesRead;

            this.Open();
            TrainerApi.ReadProcessMemory(m_hProcess, (IntPtr)MemoryAddress, buffer, numBytesToRead, out ptrBytesRead);
            System.Text.Encoding encoding = System.Text.Encoding.ASCII;
            string strString = encoding.GetString(buffer);
            this.ProcessActive.Refresh();
            this.CloseHandle(m_hProcess);
            return strString;
        }


        //***************************************************************************************
        // Method:    WriteText
        // Access:    public 
        // Returns:   none
        // Parameter: uint MemoryAdress
        // Parameter: string strTextToWrite
        // Description: Writes a string to a process's memory space
        //***************************************************************************************
        public void WriteText(uint MemoryAddress, string strTextToWrite)
        {
            System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
            Byte[] bytesToWrite = encoding.GetBytes(strTextToWrite);
            IntPtr ptrBytesWritten;

            this.Open();
            TrainerApi.WriteProcessMemory(m_hProcess, (IntPtr)MemoryAddress, bytesToWrite, (uint)bytesToWrite.Length, out ptrBytesWritten);
            this.ProcessActive.Refresh();
            this.CloseHandle(m_hProcess);
        }




        //***************************************************************************************
        // Method:    ReadFloat
        // Access:    public 
        // Returns:   float
        // Parameter: uint MemoryAddress
        // Description: Reads a value from a process's memory and returns it as a float
        //***************************************************************************************
        public float ReadFloat(uint MemoryAddress)
        {
            float rtnFloat;
            byte[] buffer = new byte[4];
            IntPtr ptrBytesRead;

            this.Open();
            TrainerApi.ReadProcessMemory(m_hProcess, (IntPtr)MemoryAddress, buffer, (uint)buffer.Length, out ptrBytesRead);
            rtnFloat = BitConverter.ToSingle(buffer, 0);
            this.ProcessActive.Refresh();
            this.CloseHandle(m_hProcess);
            return rtnFloat;
        }



        //***************************************************************************************
        // Method:    WriteFloat
        // Access:    public 
        // Returns:   none
        // Parameter: uint MemoryAddress
        // Parameter: float floatToWrite
        // Description: Writes a float value to a process's memory block
        //***************************************************************************************
        public void WriteFloat(uint MemoryAddress, float floatToWrite)
        {
            byte[] bytesToWrite;
            IntPtr ptrBytesWritten;
            bytesToWrite = BitConverter.GetBytes(floatToWrite);

            this.Open();
            TrainerApi.WriteProcessMemory(m_hProcess, (IntPtr)MemoryAddress, bytesToWrite, (uint)bytesToWrite.Length, out ptrBytesWritten);
            this.ProcessActive.Refresh();
            this.CloseHandle(m_hProcess);
        }




        //***************************************************************************************
        // Method:    CopyMemory
        // Access:    public 
        // Returns:   bool
        // Parameter: uint SourceAddress
        // Parameter: uint DestinationAddress
        // Parameter: uint numBytesToCopy
        // Description: Copys a block of memory from one address to another
        //***************************************************************************************
        public bool CopyMemory(uint SourceAddress, uint DestinationAddress, uint numBytesToCopy)
        {
            byte[] buffer = new byte[numBytesToCopy];
            buffer = this.ReadMemory(SourceAddress, numBytesToCopy);

            if (buffer.Length == 0)
                return false;

            this.WriteByteString(DestinationAddress, BitConverter.ToString(buffer));
            return true;
        }




        //***************************************************************************************
        // Method:    ModuleContainsFunction
        // Access:    public
        // Returns:   bool
        // Parameter: string moduleName
        // Parameter: string methodName
        // Description: Checks a module in a process to see if it uses a certain function
        //***************************************************************************************
        public bool ModuleContainsFunction(string moduleName, string methodName)
        {
            IntPtr hModule = TrainerApi.GetModuleHandle(moduleName);
            if (hModule != IntPtr.Zero)
                return TrainerApi.GetProcAddress(hModule, methodName) != IntPtr.Zero;
            return false;
        }


        //***************************************************************************************
        // Method:    GetModuleBaseAddress
        // Access:    public 
        // Returns:   IntPtr
        // Parameter: string ProcessName
        // Parameter: string ModuleName
        // Description: Gets the base address of a module loaded by a process
        //***************************************************************************************
        public IntPtr GetModuleBaseAddress(string ProcessName, string ModuleName)
        {
            IntPtr BaseAddress = IntPtr.Zero;
            ProcessModule procModule = null;

            //Function will not return module base address on x64 Operating Systems.
            //Unless both OS and Process/Module are x64 based.
            Process[] p = Process.GetProcessesByName(ProcessName);
            if (p.Length != 0)
            {
                ProcessModuleCollection procModuleCollection;
                procModuleCollection = p[0].Modules;

                try
                {
                    for (int i = 0; i < procModuleCollection.Count; i++)
                    {
                        procModule = procModuleCollection[i];

                        if(procModule.ModuleName.Contains(ModuleName))
                        {
                            BaseAddress = procModule.BaseAddress;
                            break;
                        }
                    }
                }
                catch
                {
                    return IntPtr.Zero; 
                }
            }
            return BaseAddress;
        }








        //***************************************************************************************
        // Method:    GetModuleSize
        // Access:    public 
        // Returns:   int
        // Parameter: string ProcessName
        // Parameter: string ModuleName
        // Description: Returns the size of a module contained in a process.
        //***************************************************************************************
        public int GetModuleSize(string ProcessName, string ModuleName)
        {
            IntPtr BaseAddress = IntPtr.Zero;

            ProcessModule procModule = null;

            if (ProcessName == string.Empty)
                return 0;

            if (ModuleName == string.Empty)
                return 0;

            Process[] p = Process.GetProcessesByName(ProcessName);
            if (p.Length != 0)
            {
                ProcessModuleCollection procModuleCollection;
                procModuleCollection = p[0].Modules;

                try
                {
                    for (int i = 0; i < procModuleCollection.Count; i++)
                    {
                        procModule = procModuleCollection[i];

                        if (procModule.ModuleName.Contains(ModuleName))
                        {
                            return procModule.ModuleMemorySize;
                        }
                    }
                }
                catch
                {
                    return 0;
                }
            }
            return 0;
        }






        //***************************************************************************************
        // Method:    DumpMemory
        // Access:    private
        // Returns:   bool
        // Description: Dumps all memory from a process into a byte array and returns a bool
        //***************************************************************************************
        private bool DumpMemory()
        {
            this.m_ProcessByteScan = this.ProcessActive;

            try
            {
                if (this.m_ProcessByteScan == null)
                    return false;
                if (this.m_ProcessByteScan.HasExited == true)
                    return false;
                if (this.m_vAddress == IntPtr.Zero)
                    return false;
                if (this.m_vSize == 0)
                    return false; 

                this.m_vDumpedRegion = new byte[this.m_vSize];

                IntPtr nBytesRead;
                TrainerApi.ReadProcessMemory(this.m_ProcessByteScan.Handle, this.m_vAddress, this.m_vDumpedRegion, (uint)this.m_vSize, out nBytesRead);

                if (nBytesRead == null || this.m_vDumpedRegion.Length == 0)
                {
                    return false;
                }
                return true;
            }
            catch (Exception Exception)
            {
                throw new Exception(Exception.ToString());
            }
        }


       

        //***************************************************************************************
        // Method:    MaskCheck
        // Access:    private 
        // Returns:   bool
        // Parameter: int nOffset
        // Parameter: byte[] btPattern
        // Parameter: string strMask
        // Description: Checks a pattern of bytes against the process memory
        //***************************************************************************************
        private bool MaskCheck(int nOffset, byte[] btPattern, string strMask)
        {
            for (int x = 0; x < btPattern.Length; x++)
            {
                if (strMask[x] == '?')
                    continue;
                if ((strMask[x] == 'x') && (btPattern[x] != this.m_vDumpedRegion[nOffset + x]))
                    return false;
            }
            return true;
        }


        //***************************************************************************************
        // Method:    FindBytePattern
        // Access:    public 
        // Returns:   IntPtr
        // Parameter: uint intAddress
        // Parameter: int intSize
        // Parameter: string strPattern
        // Parameter: string strMask
        // Parameter: int nOffset
        // Description: Finds a pattern of bytes in a process's memory
        //***************************************************************************************
        public IntPtr FindBytePattern(uint intAddress, int intSize, string strPattern, string strMask, int nOffset)
        {
            this.m_ProcessByteScan = null;
            this.m_vAddress = IntPtr.Zero;
            this.m_vSize = 0;
            this.m_vDumpedRegion = null; 

            this.Address = new IntPtr(intAddress);
            this.Size = intSize;

            int NumberChars = strPattern.Length;
            byte[] btPattern = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                btPattern[i / 2] = Convert.ToByte(strPattern.Substring(i, 2), 16);

            try
            {
                if (this.m_vDumpedRegion == null || this.m_vDumpedRegion.Length == 0)
                {
                    if (!this.DumpMemory())
                        return IntPtr.Zero;
                }  

                for (int x = 0; x < this.m_vDumpedRegion.Length; x++)
                {
                    if (this.MaskCheck(x, btPattern, strMask))
                    {
                        this.m_vDumpedRegion = null;
                        return new IntPtr((int)this.m_vAddress + (x + nOffset));
                    }
                }
                return IntPtr.Zero;
            }
            catch (Exception Exception)
            {
                throw new Exception(Exception.ToString());
            }
        }



        //***************************************************************************************
        // Method:    MemoryBlockToFile
        // Access:    public 
        // Returns:   bool
        // Parameter: string ProcessName
        // Parameter: string FileName
        // Parameter: IntPtr memAddress
        // Parameter: byte[] ByteArray
        // Description: Saves an array of bytes from memory to file
        //***************************************************************************************
        public bool MemoryBlockToFile(string ProcessName, string FileName, int memAddress, uint bytesLength)
        {
            byte[] byteDump = null;
            try
            {
                Process[] p = Process.GetProcessesByName(ProcessName);
                if (p.Length != 0)
                {
                    if (p[0].ProcessName == ProcessName)
                    {
                        byteDump = new byte[bytesLength];

                        IntPtr nBytesRead;
                        TrainerApi.ReadProcessMemory(p[0].Handle, (IntPtr)memAddress, byteDump, bytesLength, out nBytesRead);

                        FileStream FileStream = new FileStream(FileName, FileMode.Create, FileAccess.Write);
                        FileStream.Write(byteDump, 0, byteDump.Length);
                        FileStream.Close();
                        return true;
                    }
                }
                return false;
            }
            catch (Exception Exception)
            {
                throw new Exception(Exception.ToString());
            }
        }




        //***************************************************************************************
        // Method:    InjectDLL
        // Access:    public 
        // Returns:   bool
        // Parameter: string ProcessName
        // Parameter: string sDllPath
        // Description: Injects a DLL to porcess's memory
        //***************************************************************************************
        public  bool InjectDLL(string ProcessName, string sDllPath)
        {
            Process[] p = Process.GetProcessesByName(ProcessName);
            if (p.Length != 0)
            {
                if (!CreateRemoteThread(p[0], sDllPath))
                {
                    if (p[0].MainWindowHandle != (IntPtr)0)
                        this.CloseHandle(p[0].MainWindowHandle);
                        return false;
                 }
                 return true;
            }
            return false;
	    }



        //***************************************************************************************
        // Method:    CreateRemoteThread
        // Access:    private 
        // Returns:   bool
        // Parameter: process procToBeInjected
        // Parameter: string sDllPath
        // Description: Creates a remote thread in a process and writes dll
        //***************************************************************************************
        private static bool CreateRemoteThread(Process procToBeInjected, string sDllPath)
        {
            IntPtr lpLLAddress = IntPtr.Zero;
            IntPtr hndProc = TrainerApi.OpenProcess((0x2 | 0x8 | 0x10 | 0x20 | 0x400), 1, (uint)procToBeInjected.Id);
            if (hndProc == (IntPtr)0)
                return false;

            lpLLAddress = TrainerApi.GetProcAddress(TrainerApi.GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            if (lpLLAddress == (IntPtr)0)
                return false;
            
            IntPtr lpAddress = TrainerApi.VirtualAllocEx(hndProc, (IntPtr)null, (IntPtr)sDllPath.Length, (uint)TrainerApi.VAE_Enums.AllocationType.MEM_COMMIT | (uint)TrainerApi.VAE_Enums.AllocationType.MEM_RESERVE, (uint)TrainerApi.VAE_Enums.ProtectionConstants.PAGE_EXECUTE_READWRITE);
            if (lpAddress == (IntPtr)0)
                return false;

            byte[] bytes = System.Text.Encoding.ASCII.GetBytes(sDllPath);
            IntPtr ipTmp = IntPtr.Zero;

            TrainerApi.WriteProcessMemory(hndProc, lpAddress, bytes, (uint)bytes.Length, out ipTmp);
            if (ipTmp == (IntPtr)0)
                return false;

            IntPtr ipThread = TrainerApi.CreateRemoteThread(hndProc, (IntPtr)null, (IntPtr)0, lpLLAddress, lpAddress, 0, (IntPtr)null);
            if (ipThread == (IntPtr)0)
                return false;

            return true;
        }




        //***************************************************************************************
        // Method:    AllocateMemory
        // Access:    public 
        // Returns:   IntPtr
        // Parameter: int size
        // Description: Allocates a block of memory for use with code caves.
        //***************************************************************************************
        public IntPtr AllocateMemory(int size)
        {
            IntPtr hndProc = TrainerApi.OpenProcess((0x2 | 0x8 | 0x10 | 0x20 | 0x400), 1, (uint)ProcessActive.Id);
            if (hndProc == (IntPtr)0)
            {
                TrainerApi.CloseHandle(hndProc);
                return IntPtr.Zero;
            }

            IntPtr lpAddress = TrainerApi.VirtualAllocEx(hndProc, (IntPtr)null, (IntPtr)size, (uint)TrainerApi.VAE_Enums.AllocationType.MEM_COMMIT | (uint)TrainerApi.VAE_Enums.AllocationType.MEM_RESERVE, (uint)TrainerApi.VAE_Enums.ProtectionConstants.PAGE_EXECUTE_READWRITE);
            if (lpAddress == (IntPtr)0)
            {
                TrainerApi.CloseHandle(hndProc);
                return IntPtr.Zero;
            }

            TrainerApi.CloseHandle(hndProc);
            return lpAddress;
        }



        //***************************************************************************************
        // Method:    DeAllocateMemory
        // Access:    public 
        // Returns:   bool
        // Parameter: IntPtr address
        // Parameter: int size
        // Description: DeAllocates a block of memory previously allocated by AllocateMemory.
        //***************************************************************************************
        public bool DeAllocateMemory(IntPtr address, int size)
        {
            IntPtr hndProc = TrainerApi.OpenProcess((0x2 | 0x8 | 0x10 | 0x20 | 0x400), 1, (uint)ProcessActive.Id);
            if (hndProc == (IntPtr)0)
            {
                TrainerApi.CloseHandle(hndProc);
                return false;
            }

            bool released = TrainerApi.VirtualFreeEx(hndProc, address, size, TrainerApi.VAE_Enums.FreeType.MEM_DECOMMIT);
            TrainerApi.CloseHandle(hndProc);

            return released;
        }





        //***************************************************************************************
        // Method:    ExecuteCode
        // Access:    public 
        // Returns:   bool
        // Parameter: IntPtr lpAddress
        // Description: Executes a block of code located at specific memory address.
        //***************************************************************************************
        public bool ExecuteCode(IntPtr lpAddress)
        {
            IntPtr hndProc = TrainerApi.OpenProcess((0x2 | 0x8 | 0x10 | 0x20 | 0x400), 1, (uint)ProcessActive.Id);
            if (hndProc == (IntPtr)0)
            {
                TrainerApi.CloseHandle(hndProc);
                return false;
            }

            IntPtr ipThread = TrainerApi.CreateRemoteThread(hndProc, (IntPtr)null, (IntPtr)0, lpAddress, (IntPtr)null, 0, (IntPtr)null);
            if (ipThread == (IntPtr)0)
            {
                TrainerApi.CloseHandle(ipThread);
                TrainerApi.CloseHandle(hndProc);
                return false;
            }

            TrainerApi.CloseHandle(ipThread);
            TrainerApi.CloseHandle(hndProc);
            return true;
        }




        //***************************************************************************************
        // Method:    DoLeftMouseClick
        // Access:    public 
        // Returns:   none
        // Description: Simulates a left mouse click
        //***************************************************************************************
        public void LeftMouseClick()
        {
            TrainerApi.mouse_event((int)(TrainerApi.MouseEventFlags.LEFTDOWN), 0, 0, 0, 0);
            TrainerApi.mouse_event((int)(TrainerApi.MouseEventFlags.LEFTUP), 0, 0, 0, 0);
        }




        //***************************************************************************************
        // Method:    DoRightMouseClick
        // Access:    public 
        // Returns:   none
        // Description: Simulates a right mouse click
        //***************************************************************************************
        public void RightMouseClick()
        {
            TrainerApi.mouse_event((int)(TrainerApi.MouseEventFlags.RIGHTDOWN), 0, 0, 0, 0);
            TrainerApi.mouse_event((int)(TrainerApi.MouseEventFlags.RIGHTUP), 0, 0, 0, 0);
        }



        //***************************************************************************************
        // Method:    DoMiddleMouseClick
        // Access:    public 
        // Returns:   none
        // Description: Simulates a middle mouse click
        //***************************************************************************************
        public void MiddleMouseClick()
        {
            TrainerApi.mouse_event((int)(TrainerApi.MouseEventFlags.MIDDLEDOWN), 0, 0, 0, 0);
            TrainerApi.mouse_event((int)(TrainerApi.MouseEventFlags.MIDDLEUP), 0, 0, 0, 0);
        }



        //***************************************************************************************
        // Method:    DoubleMouseClick
        // Access:    public 
        // Returns:   none
        // Description: Simulates a double left mouse click
        //***************************************************************************************
        public void DoubleMouseClick()
        {
            TrainerApi.mouse_event((int)(TrainerApi.MouseEventFlags.LEFTDOWN), 0, 0, 0, 0);
            TrainerApi.mouse_event((int)(TrainerApi.MouseEventFlags.LEFTUP), 0, 0, 0, 0);
            Thread.Sleep(500);
            TrainerApi.mouse_event((int)(TrainerApi.MouseEventFlags.LEFTDOWN), 0, 0, 0, 0);
            TrainerApi.mouse_event((int)(TrainerApi.MouseEventFlags.LEFTUP), 0, 0, 0, 0);
        }



        //***************************************************************************************
        // Method:    DoubleMouseClick
        // Access:    public 
        // Returns:   none
        // Parameter: int x
        // Parameter: int y
        // Description: Simulates a double left mouse click at a certain location.
        //***************************************************************************************
        public void DoubleMouseClick(int x, int y)
        {
            Cursor.Position = new Point(x, y);
            TrainerApi.mouse_event((int)(TrainerApi.MouseEventFlags.LEFTDOWN), 0, 0, 0, 0);
            TrainerApi.mouse_event((int)(TrainerApi.MouseEventFlags.LEFTUP), 0, 0, 0, 0);
            Thread.Sleep(500);
            TrainerApi.mouse_event((int)(TrainerApi.MouseEventFlags.LEFTDOWN), 0, 0, 0, 0);
            TrainerApi.mouse_event((int)(TrainerApi.MouseEventFlags.LEFTUP), 0, 0, 0, 0);
        }



        //***************************************************************************************
        // Method:    LeftMouseClick
        // Access:    public 
        // Returns:   none
        // Parameter: int x
        // Parameter: int y
        // Description: Simulates a left mouse button click at certain position
        //***************************************************************************************
        public void LeftMouseClick(int x, int y)
        {
            Cursor.Position = new System.Drawing.Point(x, y);
            TrainerApi.mouse_event((int)(TrainerApi.MouseEventFlags.LEFTDOWN), 0, 0, 0, 0);
            TrainerApi.mouse_event((int)(TrainerApi.MouseEventFlags.LEFTUP), 0, 0, 0, 0);
        }


        //***************************************************************************************
        // Method:    RightMouseClick
        // Access:    public 
        // Returns:   none
        // Parameter: int x
        // Parameter: int y
        // Description: Simulates a right mouse button click at certain position
        //***************************************************************************************
        public void RightMouseClick(int x, int y)
        {
            Cursor.Position = new System.Drawing.Point(x, y);
            TrainerApi.mouse_event((int)(TrainerApi.MouseEventFlags.RIGHTDOWN), 0, 0, 0, 0);
            TrainerApi.mouse_event((int)(TrainerApi.MouseEventFlags.RIGHTUP), 0, 0, 0, 0);
        }


        //***************************************************************************************
        // Method:    MiddleMouseClick
        // Access:    public 
        // Returns:   none
        // Parameter: int x
        // Parameter: int y
        // Description: Simulates a middle mouse button click  at certain position
        //***************************************************************************************
        public void MiddleMouseClick(int x, int y)
        {
            Cursor.Position = new System.Drawing.Point(x, y);
            TrainerApi.mouse_event((int)(TrainerApi.MouseEventFlags.MIDDLEDOWN), 0, 0, 0, 0);
            TrainerApi.mouse_event((int)(TrainerApi.MouseEventFlags.MIDDLEUP), 0, 0, 0, 0);
        }


        //***************************************************************************************
        // Method:    MoveForm
        // Access:    public 
        // Returns:   none
        // Parameter: IntPtr HWND
        // Description: Moves a bordrless form
        //***************************************************************************************
        public void MoveForm(IntPtr HWND)
        {
            TrainerApi.ReleaseCapture();
            TrainerApi.SendMessage(HWND, 0xA1, 0x02, 0);
        }



        //***************************************************************************************
        // Method:    SendKeyString
        // Access:    public 
        // Returns:   none
        // Parameter: string ProcessName
        // Parameter: string strTextToWrite
        // Parameter: int miliSecDelay
        // Description: Sends a string of key strokes to a process
        //***************************************************************************************
        public void SendKeyString(string ProcessName, string strTextToWrite, int miliSecDelay)
        {
            Process[] p = Process.GetProcessesByName(ProcessName);
            if (p.Length != 0)
            {
                for (int b = 0; b < strTextToWrite.Length; b++)
                {
                    TrainerApi.SetFocus(p[0].MainWindowHandle);
                    TrainerApi.SetForegroundWindow(p[0].MainWindowHandle);
                    System.Windows.Forms.SendKeys.SendWait(strTextToWrite.Substring(b,1));
                    Thread.Sleep(miliSecDelay);
                }
            }
        }


        
        //***************************************************************************************
        // Method:    SendKey
        // Access:    public 
        // Returns:   none
        // Parameter: string ProcessName
        // Parameter: Keys keyToCheck
        // Parameter: bool holdShift
        // Parameter: int miliSecDelay
        // Description: Sends a keystroke to a process
        //***************************************************************************************
        public void SendKey(string ProcessName, Keys keyToCheck, bool holdShift, int miliSecDelay)
        {
            Process[] p = Process.GetProcessesByName(ProcessName);
            if (p.Length != 0)
            {
                if (holdShift == true && keyToCheck != Keys.Shift)
                {
                    TrainerApi.SetFocus(p[0].MainWindowHandle);
                    TrainerApi.SetForegroundWindow(p[0].MainWindowHandle);
                    TrainerApi.keybd_event(0x10, 0x45, 0x01 | 0, 0);                //Shift Down
                    TrainerApi.keybd_event((byte)keyToCheck, 0x45, 0x01 | 0, 0);    //Key Down
                    TrainerApi.keybd_event((byte)keyToCheck, 0x45, 0x01 | 0x02, 0); //Key Up
                    TrainerApi.keybd_event(0x10, 0x45, 0x01 | 0x02, 0);             //Shift Up
                    Thread.Sleep(miliSecDelay);
                }
                else
                {
                    TrainerApi.SetFocus(p[0].MainWindowHandle);
                    TrainerApi.SetForegroundWindow(p[0].MainWindowHandle);
                    TrainerApi.keybd_event((byte)keyToCheck, 0x45, 0x01 | 0, 0);    //Key Down
                    TrainerApi.keybd_event((byte)keyToCheck, 0x45, 0x01 | 0x02, 0); //Key Up
                    Thread.Sleep(miliSecDelay);
                }
            }
        }


        //***************************************************************************************
        // Method:    IsKeyPressed
        // Access:    public 
        // Returns:   bool
        // Parameter: Keys vKey
        // Description: Returns true or false if a keyboard key is pressed. (requiers timer or thread)
        //***************************************************************************************
        public bool IsKeyPressed(Keys vKey)
        {
            return 0 != (TrainerApi.GetAsyncKeyState((int)vKey) & 0x8000);
        }

        
        //***************************************************************************************
        // Method:    GetURLSource
        // Access:    public 
        // Returns:   string
        // Parameter: string urlLocation
        // Description: Returns the source of a document located on the net.
        //***************************************************************************************
        public string GetURLSource(string urlLocation)
        {
            try
            {
                WebClient webClient = new WebClient();
                String strData = webClient.DownloadString(urlLocation);
                return strData;
            }
            catch (Exception ee)
            {
                throw new Exception(ee.Message);
            }
        }


        //***************************************************************************************
        // Method:    DownloadFile
        // Access:    public 
        // Returns:   none
        // Parameter: string File
        // Parameter: string SaveLocation
        // Description: Starts an asynchronous download of a remote file.
        //***************************************************************************************
        public void DownloadFile(string File, string SaveLocation)
        {
            if(RemoteFileExists(File) == false)
                throw new Exception("Error occured while trying to download remote file.");

            DownloadComplete = false;
            DownloadProgress = 0;
            try
            {
                WebClient webClient = new WebClient();
                webClient.DownloadFileCompleted += new AsyncCompletedEventHandler(Completed);
                webClient.DownloadProgressChanged += new DownloadProgressChangedEventHandler(ProgressChanged);
                webClient.DownloadFileAsync(new Uri(File), SaveLocation);
            }
            catch (Exception ee)
            {
                throw new Exception(ee.Message);
            }
        }

        //***************************************************************************************
        // Method:    ProgressChanged
        // Access:    private 
        // Returns:   none
        // Parameter: object sender
        // Parameter: DownloadProgressChangedEventArgs e
        // Description: Updates value of download progress.
        //***************************************************************************************
        private void ProgressChanged(object sender, DownloadProgressChangedEventArgs e)
        {
            DownloadProgress = e.ProgressPercentage;
        }


        //***************************************************************************************
        // Method:    DownloadCompleted
        // Access:    private 
        // Returns:   none
        // Parameter: object sender
        // Parameter: AsyncCompletedEventArgs e
        // Description: Updates bool value of DownloadComplete.
        //***************************************************************************************
        private void Completed(object sender, AsyncCompletedEventArgs e)
        {
            DownloadComplete = true;
        }


        //***************************************************************************************
        // Method:    RemoteFileExists
        // Access:    public 
        // Returns:   bool
        // Parameter: string url
        // Description: Checks existance of remote file.
        //***************************************************************************************
        public bool RemoteFileExists(string url)
        {
            try
            {
                HttpWebRequest request = WebRequest.Create(url) as HttpWebRequest;
                request.Method = "HEAD";
                HttpWebResponse response = request.GetResponse() as HttpWebResponse;
                return (response.StatusCode == HttpStatusCode.OK);
            }
            catch
            {
                return false;
            }
        }



        //***************************************************************************************
        // Method:    PatchFile
        // Access:    public 
        // Returns:   bool
        // Parameter: int[] offsetData
        // Parameter: byte[] patchData
        // Parameter: string fileInput
        // Parameter: string fileOutput
        // Parameter: bool makeBackup
        // Description: Opens file and replaces data located at offsetData with patchData.
        //***************************************************************************************
        public bool PatchFile(int[] offsetData, byte[] patchData, string fileInput, string fileOutput, bool makeBackup)
        {
            try
            {

                if (offsetData.Length != patchData.Length)
                    return false;
                
                string isPatched = File.ReadAllText(@fileInput);
                if (isPatched.Contains("FilePatched"))
                    return false;

                if(makeBackup == true)
                    File.Copy(@fileInput, fileInput + ".bak");

                byte[] fileData = File.ReadAllBytes(@fileInput);
                for (int i = 0; i < fileData.Length; i++)
                    for (int p = 0; p < offsetData.Length; p++)
                        if (offsetData[p] == i)
                            fileData[i] = patchData[p];

                File.WriteAllBytes(@fileOutput, fileData);
                File.AppendAllText(@fileOutput, "FilePatched");
                return true;
            }
            catch (Exception ee) 
            {
                throw new Exception(ee.Message);
            }
        }


        //***************************************************************************************
        // Method:    IniWriteValue
        // Access:    public 
        // Returns:   none
        // Parameter: string filePath
        // Parameter: string Section
        // Parameter: string Key
        // Parameter: string Value
        // Description: Writes Data to a Ini file.
        //***************************************************************************************
        public void IniWriteValue(string filePath, string Section, string Key, string Value)
        {
            TrainerApi.WritePrivateProfileString(Section, Key, Value, filePath);
        }


        //***************************************************************************************
        // Method:    IniReadValue
        // Access:    public 
        // Returns:   string
        // Parameter: string filePath
        // Parameter: string Section
        // Parameter: string Key
        // Description: Reads Data from a Ini file.
        //***************************************************************************************
        public string IniReadValue(string filePath, string Section, string Key)
        {
            StringBuilder temp = new StringBuilder(255);
            string def = string.Empty;

            int i = TrainerApi.GetPrivateProfileString(Section, Key, def, temp, 255, filePath);
            return temp.ToString();
        }




        public void IniWriteSection(string filePath, string Section, string Key)
        {
            TrainerApi.WritePrivateProfileSection(Section, Key, filePath);
        }



        public List<string> IniGetKeys(string iniFile, string category)
        {

            byte[] buffer = new byte[2048];

            TrainerApi.GetPrivateProfileSection(category, buffer, 2048, iniFile);

            String[] tmp = Encoding.ASCII.GetString(buffer).Trim('\0').Split('\0');

            List<string> result = new List<string>();

            foreach (String entry in tmp)
            {
                result.Add(entry.Substring(0, entry.IndexOf("=")));
            }

            return result;
        }





        //***************************************************************************************
        // Method:    RegistryCreateSubKey
        // Access:    public 
        // Returns:   none
        // Parameter: string subKey
        // Description: Creates a subkey in the registry.
        //***************************************************************************************
        public void RegistryCreateSubKey(string subKey)
        {
            try
            {
                Registry.CurrentUser.CreateSubKey(@subKey);
                Registry.CurrentUser.Flush();    
            }
            catch(Exception ee) 
            {
                throw new Exception(ee.Message);
            }
        }



        //***************************************************************************************
        // Method:    RegistryDeleteSubKey
        // Access:    public 
        // Returns:   none
        // Parameter: string subKey
        // Description: Deletes a subkey in the registry.
        //***************************************************************************************
        public void RegistryDeleteSubKey(string subKey)
        {
            try
            {
                Registry.CurrentUser.DeleteSubKey(@subKey);
                Registry.CurrentUser.Flush();
            }
            catch (Exception ee)
            {
                throw new Exception(ee.Message);
            }
        }



        //***************************************************************************************
        // Method:    RegistryDeleteKey
        // Access:    public 
        // Returns:   none
        // Parameter: string subKey
        // Parameter: string keyName
        // Description: Deletes a key in the registry.
        //***************************************************************************************
        public void RegistryDeleteKey(string subKey, string keyName)
        {
            try
            {
                RegistryKey key = Registry.CurrentUser.OpenSubKey(subKey, true);
                key.DeleteValue(keyName);
                Registry.CurrentUser.Flush();
            }
            catch (Exception ee)
            {
                throw new Exception(ee.Message);
            }
        }




        //***************************************************************************************
        // Method:    RegistryReadBool
        // Access:    public 
        // Returns:   bool
        // Parameter: string subKey
        // Parameter: string keyName
        // Description: Returns a bool value from a registry key
        //***************************************************************************************
        public bool RegistryReadBool(string subKey, string keyName)
        {
            try
            {
                RegistryKey key = Registry.CurrentUser.OpenSubKey(subKey, true);
                bool b;
                Boolean.TryParse((((String)key.GetValue(keyName, "False"))), out b);
                return b;
            }
            catch (Exception ee)
            {
                throw new Exception(ee.Message);
            }
        }


        //***************************************************************************************
        // Method:    RegistryReadBool
        // Access:    public 
        // Returns:   none
        // Parameter: string subKey
        // Parameter: string keyName
        // Parameter: bool value
        // Description: Sets a bool value to a registry key
        //***************************************************************************************
        public void RegistryWriteBool(string subKey, string keyName, bool value)
        {
            try
            {
                RegistryKey key = Registry.CurrentUser.OpenSubKey(subKey, true);
                key.SetValue(keyName, value);
                Registry.CurrentUser.Flush();
            }
            catch (Exception ee)
            {
                throw new Exception(ee.Message);
            }
        }



        //***************************************************************************************
        // Method:    RegistryReadInt
        // Access:    public 
        // Returns:   int
        // Parameter: string subKey
        // Parameter: string keyName
        // Description: Returns a int value from a registry key
        //***************************************************************************************
        public int RegistryReadInt(string subKey, string keyName)
        {
            try
            {
                RegistryKey key = Registry.CurrentUser.OpenSubKey(subKey, true);
                return (int)key.GetValue(keyName, 0);
            }
            catch (Exception ee)
            {
                throw new Exception(ee.Message);
            }
        }


        //***************************************************************************************
        // Method:    RegistryWriteInt
        // Access:    public 
        // Returns:   none
        // Parameter: string subKey
        // Parameter: string keyName
        // Parameter: int value
        // Description: Sets a int value to a registry key
        //***************************************************************************************
        public void RegistryWriteInt(string subKey, string keyName, int value)
        {
            try
            {
                RegistryKey key = Registry.CurrentUser.OpenSubKey(subKey, true);
                key.SetValue(keyName, value);
                Registry.CurrentUser.Flush();
            }
            catch (Exception ee)
            {
                throw new Exception(ee.Message);
            }
        }


        //***************************************************************************************
        // Method:    RegistryReadString
        // Access:    public 
        // Returns:   string
        // Parameter: string subKey
        // Parameter: string keyName
        // Description: Returns a string value from a registry key
        //***************************************************************************************
        public string RegistryReadString(string subKey, string keyName)
        {
            try
            {
                RegistryKey key = Registry.CurrentUser.OpenSubKey(subKey, true);
                return (string)key.GetValue(keyName, "");
            }
            catch (Exception ee)
            {
                throw new Exception(ee.Message);
            }
        }


        //***************************************************************************************
        // Method:    RegistryWriteString
        // Access:    public 
        // Returns:   none
        // Parameter: string subKey
        // Parameter: string keyName
        // Parameter: string value
        // Description: Sets a string value to a registry key
        //***************************************************************************************
        public void RegistryWriteString(string subKey, string keyName, string value)
        {
            try
            {
                RegistryKey key = Registry.CurrentUser.OpenSubKey(subKey, true);
                key.SetValue(keyName, value);
                Registry.CurrentUser.Flush();
            }
            catch (Exception ee)
            {
                throw new Exception(ee.Message);
            }
        }



        //***************************************************************************************
        // Method:    RegistryReadBinary
        // Access:    public 
        // Returns:   byte[]
        // Parameter: string subKey
        // Parameter: string keyName
        // Description: Returns a byte[] value from a registry key
        //***************************************************************************************
        public byte[] RegistryReadBinary(string subKey, string keyName)
        {
            try
            {
                RegistryKey key = Registry.CurrentUser.OpenSubKey(subKey, true);
                return (byte[])key.GetValue(keyName, "");
            }
            catch (Exception ee)
            {
                throw new Exception(ee.Message);
            }
        }



        //***************************************************************************************
        // Method:    RegistryWriteBinary
        // Access:    public 
        // Returns:   none
        // Parameter: string subKey
        // Parameter: string keyName
        // Parameter: byte[] value
        // Description: Sets a byte[] value to a registry key
        //***************************************************************************************
        public void RegistryWriteBinary(string subKey, string keyName, byte[] value)
        {
            try
            {
                RegistryKey key = Registry.CurrentUser.OpenSubKey(subKey, true);
                key.SetValue(keyName, value);
                Registry.CurrentUser.Flush();
            }
            catch (Exception ee)
            {
                throw new Exception(ee.Message);
            }
        }
        

        //***************************************************************************************
        // Method:    PlayWav
        // Access:    public 
        // Returns:   none
        // Parameter: string fname
        // Description: Plays a wav file.
        //***************************************************************************************
        public void PlayWav(string fname)
        {
            TrainerApi.PlaySound(fname, 0, 0x00020000 | 0x0001);
        }


        //***************************************************************************************
        // Method:    StopWav
        // Access:    public 
        // Returns:   none
        // Description: Stops wav file from playing.
        //***************************************************************************************
        public void StopWav()
        {
            TrainerApi.PlaySound(null, 0, 0x0040);
        }


        //***************************************************************************************
        // Method:    calcMd5
        // Access:    public 
        // Returns:   string
        // Parameter: string value
        // Description: Turns string into MD5 Hash.
        //***************************************************************************************
        public string calcMd5(string value)
        {
            MD5CryptoServiceProvider encrypt = new MD5CryptoServiceProvider();
            byte[] bytes = Encoding.UTF8.GetBytes(value);

            bytes = encrypt.ComputeHash(bytes);
            
            StringBuilder strBuild = new StringBuilder();
                        
            foreach (byte byte_ in bytes)
                strBuild.Append(byte_.ToString("X2").ToLower());

            return strBuild.ToString();            
        }



        //***************************************************************************************
        // Method:    calcSha1
        // Access:    public 
        // Returns:   string
        // Parameter: string value
        // Description: Turns string into SHA1 Hash.
        //***************************************************************************************
        public string calcSha1(string value)
        {
            var data = Encoding.ASCII.GetBytes(value);
            var hashData = new SHA1Managed().ComputeHash(data);

            var hash = string.Empty;

            foreach (var b in hashData)
                hash += b.ToString("X2").ToLower();

            return hash;
        }


        //***************************************************************************************
        // Method:    calcCRC32
        // Access:    public 
        // Returns:   string
        // Parameter: string strFile
        // Description: Caclulates a Cyclic Redundancy Check hash based on file provided.
        //***************************************************************************************
        public string calcCRC32(string strFile)
        {
            byte[] Value;
            FileStream _FileStream = new FileStream(strFile, FileMode.Open, FileAccess.Read);
            BinaryReader _BinaryReader = new BinaryReader(_FileStream);
            long _TotalBytes = new FileInfo(strFile).Length;
            Value = _BinaryReader.ReadBytes((Int32)_TotalBytes);

            UInt32 CRCVal = 0xffffffff;
            for (int i = 0; i < Value.Length; i++)
                CRCVal = (CRCVal >> 8) ^ TrainerApi.CRCTable[(CRCVal & 0xff) ^ Value[i]];

            CRCVal ^= 0xffffffff;
            byte[] Result = new byte[4];

            Result[0] = (byte)(CRCVal >> 24);
            Result[1] = (byte)(CRCVal >> 16);
            Result[2] = (byte)(CRCVal >> 8);
            Result[3] = (byte)(CRCVal);

            return BitConverter.ToString(Result).Replace("-", string.Empty).ToLower();
        }






        //***************************************************************************************
        // Method:    Pause
        // Access:    public 
        // Returns:   none
        // Parameter: int length
        // Description: Pauses execution for a number of miliseconds, with out makign system sleep.
        //***************************************************************************************
        public void Pause(int length)
        {
            bool timerrunning = true;
            DateTime start = DateTime.Now;
            do 
            {
                TimeSpan duration = DateTime.Now - start;
                //Console.WriteLine(Math.Round(duration.TotalMilliseconds, 0));
                if (Math.Round(duration.TotalMilliseconds, 0) >= length)
                {
                    timerrunning = false;
                }
                Application.DoEvents();
            } while (timerrunning == true);
        }













        
        public string ASM_CALL_Address(uint callingaddress, uint address)
        {
            string filler = string.Empty;
            string dump = (callingaddress - address - 5).ToString("X"); //Get original bytes

            for (int i = 0; i < (8 - dump.Length); i++)
                filler += "0";

            dump = filler + dump + "E8"; //Add Call  

            byte[] hex = new byte[dump.Length / 2];
            for (int i = 0; i < hex.Length; i++)
                hex[i] = Convert.ToByte(dump.Substring(i * 2, 2), 16); //Set each byte to 2 chars

            Array.Reverse(hex); //Reverse byte array for use with Write()

            return BitConverter.ToString(hex).Replace("-", string.Empty);
        }



        public string ASM_JMP(uint to, uint from, bool nop)
        {
            string dump = (to - from - 5).ToString("X"); //Get original bytes

            if (dump.Length == 7) //Make sure we have 4 bytes
                dump = "0" + dump;

            dump = dump + "E9"; //Add JMP
            if (nop)
                dump = "90" + dump; //Add NOP if needed

            byte[] hex = new byte[dump.Length / 2];
            for (int i = 0; i < hex.Length; i++)
                hex[i] = Convert.ToByte(dump.Substring(i * 2, 2), 16); //Set each byte to 2 chars

            Array.Reverse(hex); //Reverse byte array for use with Write()

            return BitConverter.ToString(hex).Replace("-", string.Empty);
        }


        

        public string ASM_JE_SHORT(uint callingaddress, uint address)
        {
            string filler = string.Empty;
            string dump = (address - callingaddress - 2).ToString("X"); //Get original bytes

            for (int i = 0; i < (2 - dump.Length); i++)
                filler += "0";

            dump = filler + dump + "74"; //Add JE  

            byte[] hex = new byte[dump.Length / 2];
            for (int i = 0; i < hex.Length; i++)
                hex[i] = Convert.ToByte(dump.Substring(i * 2, 2), 16); //Set each byte to 2 chars

            Array.Reverse(hex); //Reverse byte array for use with Write()

            return BitConverter.ToString(hex).Replace("-", string.Empty);
        }




        public string ASM_JNZ_SHORT(uint callingaddress, uint address)
        {
            string filler = string.Empty;
            string dump = (address - callingaddress - 2).ToString("X"); //Get original bytes
            
            for (int i = 0; i < (2 - dump.Length); i++)
                filler += "0";

            dump = filler + dump + "75"; //Add JE   

            byte[] hex = new byte[dump.Length / 2];
            for (int i = 0; i < hex.Length; i++)
                hex[i] = Convert.ToByte(dump.Substring(i * 2, 2), 16); //Set each byte to 2 chars

            Array.Reverse(hex); //Reverse byte array for use with Write()

            return BitConverter.ToString(hex).Replace("-", string.Empty);
        }




        public string ASM_JLE_SHORT(uint callingaddress, uint address)
        {
            string filler = string.Empty;
            string dump = (address - callingaddress - 2).ToString("X"); //Get original bytes

            for (int i = 0; i < (2 - dump.Length); i++)
                filler += "0";

            dump = filler + dump + "7E"; //Add JLE  

            byte[] hex = new byte[dump.Length / 2];
            for (int i = 0; i < hex.Length; i++)
                hex[i] = Convert.ToByte(dump.Substring(i * 2, 2), 16); //Set each byte to 2 chars

            Array.Reverse(hex); //Reverse byte array for use with Write()

            return BitConverter.ToString(hex).Replace("-", string.Empty);
        }



        public string ASM_JGE_SHORT(uint callingaddress, uint address)
        {
            string filler = string.Empty;
            string dump = (address - callingaddress - 2).ToString("X"); //Get original bytes

            for (int i = 0; i < (2 - dump.Length); i++)
                filler += "0";

            dump = filler + dump + "7D"; //Add JGE  

            byte[] hex = new byte[dump.Length / 2];
            for (int i = 0; i < hex.Length; i++)
                hex[i] = Convert.ToByte(dump.Substring(i * 2, 2), 16); //Set each byte to 2 chars

            Array.Reverse(hex); //Reverse byte array for use with Write()

            return BitConverter.ToString(hex).Replace("-", string.Empty);
        }




        public string ASM_PUSH_Address(uint address)
        {
            byte[] hex = BitConverter.GetBytes(address);
            return "68" + BitConverter.ToString(hex).Replace("-", string.Empty);
        }        



        public string ASM_NOP()
        {
            return "90";
        }
        


        public string ASM_RETN()
        {
            return "C3";
        }



    }






    public class TrainerApi
    {
        [Flags]
        public enum ProcessAccessType
        {
            PROCESS_ALL = 0x001F0FFF,
            PROCESS_TERMINATE = 0x0001,
            PROCESS_CREATE_THREAD = 0x0002,
            PROCESS_SET_SESSIONID = 0x0004,
            PROCESS_VM_OPERATION = 0x0008,
            PROCESS_VM_READ = 0x0010,
            PROCESS_VM_WRITE = 0x0020,
            PROCESS_DUP_HANDLE = 0x0040,
            PROCESS_CREATE_PROCESS = 0x0080,
            PROCESS_SET_QUOTA = 0x0100,
            PROCESS_SET_INFORMATION = 0x0200,
            PROCESS_QUERY_INFORMATION = 0x0400
        }

        public static class VAE_Enums
        {
            public enum AllocationType
            {
                MEM_COMMIT = 0x1000,
                MEM_RESERVE = 0x2000,
                MEM_RESET = 0x80000,
            }

            public enum FreeType
            {
                MEM_DECOMMIT = 0x4000,
                MEM_RELEASE = 0x8000,
            }
            
            public enum ProtectionConstants
            {
                PAGE_EXECUTE = 0x10,
                PAGE_EXECUTE_READ = 0x20,
                PAGE_EXECUTE_READWRITE = 0x40,
                PAGE_EXECUTE_WRITECOPY = 0x80,
                PAGE_NOACCESS = 0x01
            }
        }


        [Flags]
        public enum MouseEventFlags
        {
            LEFTDOWN = 0x02,
            LEFTUP = 0x04,
            MIDDLEDOWN = 0x20,
            MIDDLEUP = 0x40,
            MOVE = 0x1,
            ABSOLUTE = 0x8000,
            RIGHTDOWN = 0x08,
            RIGHTUP = 0x10
        }

        
        public enum ASMOpCodes: int
        {
            CALL     = 0xE8, JMP       = 0xE9, RETN       = 0xC3, NOP       = 0x90, PUSH_BYTE = 0x6A,
            PUSHAD   = 0x60, PUSH_EAX  = 0x50, PUSH_ECX   = 0x51, PUSH_EDX  = 0x52, PUSH_EBX  = 0x53,
            PUSH_ESP = 0x54, PUSH_EBP  = 0x55, PUSH_ESI   = 0x56, PUSH_EDI  = 0x57, POPAD     = 0x61,
            POP_EAX  = 0x58, POP_ECX   = 0x59, POP_EDX    = 0x5A, POP_EBX   = 0x5B, POP_ESP   = 0x5C,
            POP_EBP  = 0x5D, POP_ESI   = 0x5E, POP_EDI    = 0x5F, CALL_FUNC = 0xE8, ADD_ESP   = 0xC483,
            JMP_LONG = 0xE9, JMP_SHORT = 0xEB, PUSH_DWORD = 0x68, PUSH_DWORD_PTR = 0x35FF
        }



        //Memory Access
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(UInt32 dwDesiredAccess, Int32 bInheritHandle, UInt32 dwProcessId);
        [DllImport("kernel32.dll")]
        public static extern Int32 CloseHandle(IntPtr hObject);
        [DllImport("kernel32.dll")]
        public static extern Int32 ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [In, Out] byte[] buffer, UInt32 size, out IntPtr lpNumberOfBytesRead);
        [DllImport("kernel32.dll")]
        public static extern Int32 WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [In, Out] byte[] buffer, UInt32 size, out IntPtr lpNumberOfBytesWritten);


        //Module Base Address
        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWow64Process(IntPtr hProcess);
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public extern static IntPtr GetProcAddress(IntPtr hModule, string methodName);
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public extern static IntPtr GetModuleHandle(string moduleName);


        //DLL Injection
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttribute, IntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, TrainerApi.VAE_Enums.FreeType dwFreeType);



        //Mouse Events
        [DllImport("user32.dll")]
        public static extern void mouse_event(int dwFlags, int dx, int dy, int dwData, int dwExtraInfo);
        [DllImportAttribute("user32.dll")]
        public static extern int SendMessage(IntPtr hWnd, int Msg, int wParam, int lParam);
        [DllImportAttribute("user32.dll")]
        public static extern bool ReleaseCapture();


        //Keyboard Events
        [DllImport("user32.dll")]
        public static extern IntPtr SetFocus(IntPtr hWnd);
        [DllImport("user32", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        public static extern bool SetForegroundWindow(IntPtr hwnd);
        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern bool PostMessage(int hhwnd, uint msg, IntPtr wparam, IntPtr lparam);
        [DllImport("user32.dll")]
        public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, int dwExtraInfo);
        [DllImport("user32.dll")]
        public static extern ushort GetAsyncKeyState(int vKey);

        //CodeCave Methods
        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);


        //Ini Files
        [DllImport("kernel32")]
        public static extern bool WritePrivateProfileString(string section, string key, string val, string filePath);
        [DllImport("kernel32")]
        public static extern int GetPrivateProfileString(string section, string key, string def, StringBuilder retVal, int size, string filePath);
        [DllImport("kernel32.dll")]
        public static extern int GetPrivateProfileSection(string lpAppName, byte[] lpReturnedString, int nSize, string lpFileName);
        [DllImport("kernel32.dll")]
        public static extern bool WritePrivateProfileSection(string lpAppName, string lpString, string lpFileName);

        //PlaySounds
        [DllImport("WinMM.dll")]
        public static extern bool PlaySound(string fname, int Mod, int flag);


        //Anti Debug
        [DllImport("Kernel32.dll", EntryPoint = "RtlZeroMemory", SetLastError = false)]
        public static extern void ZeroMemory(IntPtr dest, uint size);
        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        
        //Cyclic Redundancy Check Table
        public static readonly UInt32[] CRCTable =
        {
            0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419,
            0x706af48f, 0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4,
            0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07,
            0x90bf1d91, 0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
            0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7, 0x136c9856,
            0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
            0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4,
            0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
            0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3,
            0x45df5c75, 0xdcd60dcf, 0xabd13d59, 0x26d930ac, 0x51de003a,
            0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599,
            0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
            0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190,
            0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f,
            0x9fbfe4a5, 0xe8b8d433, 0x7807c9a2, 0x0f00f934, 0x9609a88e,
            0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
            0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed,
            0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
            0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3,
            0xfbd44c65, 0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
            0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a,
            0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5,
            0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa, 0xbe0b1010,
            0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
            0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17,
            0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6,
            0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615,
            0x73dc1683, 0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
            0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1, 0xf00f9344,
            0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
            0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a,
            0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
            0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1,
            0xa6bc5767, 0x3fb506dd, 0x48b2364b, 0xd80d2bda, 0xaf0a1b4c,
            0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef,
            0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
            0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe,
            0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31,
            0x2cd99e8b, 0x5bdeae1d, 0x9b64c2b0, 0xec63f226, 0x756aa39c,
            0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
            0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b,
            0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
            0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1,
            0x18b74777, 0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
            0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45, 0xa00ae278,
            0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7,
            0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc, 0x40df0b66,
            0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
            0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605,
            0xcdd70693, 0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8,
            0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b,
            0x2d02ef8d
        };

   }
}


/*
----------------------------------------------------------------------------------------------
Change Log
----------------------------------------------------------------------------------------------
v1.2
    1.  Added method to calculate a MD5 hash from a string.
    2.  Added method to calculate a SHA1 hash from a string.
    3.  Added method to calculate a CRC32 hash from a file.
    4.  Added method DeAllocateMemory to free memory used by AllocateMemory method.
    5.  Added method to get size of a module from a certain process.

----------------------------------------------------------------------------------------------
v1.1 
    1.  Changed SetProcess, SendKey, SendKeySring, InjectDll MemoryBlockToFile, GetModuleBaseAddress method's 
        so that process is retrieved by name instead of looping through each process.
    2.  Changed ReadByteArray, ReadMemory to return as a byte[] instead of a string.
    3.  Removed hard coded key enumeration from SendKey method & replaced with Keys Enum.
    4.  Added a IsKeyPressed method for use with hotkeys. (requires timer / new thread)
    5.  Added GetURLSource method to retrieve data from a webbased document.
    6.  Removed ByteLengthCheck method.
    7.  Added AllocateMemory method to get a block of unused memory.
    8.  Added ExecuteCode method to call a method in a specific memory block.
    9.  Added ASM constants for use with code cave's.
    10. Added DownloadFile method so users can download files.
    11. Added PatchFile method so users can byte patch files.
    12. Added IniRead/WriteValue methods.
    13. Added Registry Methods for access to the Windows Registry.
    14. Added PlaySound Method to allow use of wav sounds.
    15. Generalized code clean up.
 ----------------------------------------------------------------------------------------------
v1.0
    1.  Initial Release.
*/
