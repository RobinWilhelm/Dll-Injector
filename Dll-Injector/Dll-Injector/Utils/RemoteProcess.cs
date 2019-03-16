using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;
using System.ComponentModel;
using System.Collections;
using Microsoft.Win32.SafeHandles;
using Dll_Injector.Native;

namespace Dll_Injector.Utils
{
    public enum ProcessArchitecture
    {
        Unknown,
        x86,
        x64,        
    }

    public struct ModuleInformation
    {
        public IntPtr ImageBase;
        public UInt32 ImageSize;
        public string Name;
        public string Path;
    }

    public static class ProcessExtensions
    {
        public static SafeProcessHandle Open(this Process process, uint accessType)
        {
            SafeProcessHandle hProcess = Kernel32.OpenProcess(accessType, false, (uint)process.Id);
            if(hProcess.IsInvalid)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess failed on Process " + process.Id);
            }
            else
            {
                return hProcess;
            }
        }

        // opens a handle with PROCESS_QUERY_LIMITED_INFORMATION
        public static ProcessArchitecture GetArchitecture(this Process process)
        {
            try
            {
                SafeProcessHandle hProcess = process.Open((uint)ProcessAccessType.PROCESS_QUERY_LIMITED_INFORMATION);
                ProcessArchitecture arch = GetArchitecture(hProcess);
                hProcess.Close();
                return arch;
            }
            catch(Win32Exception e)
            {
                return ProcessArchitecture.Unknown;
            }           
        }

        // the handle will need PROCESS_QUERY_LIMITED_INFORMATION
        public static ProcessArchitecture GetArchitecture(SafeProcessHandle hProcess)
        {            
            bool x86Process;
            bool result = Kernel32.IsWow64Process(hProcess, out x86Process);
            if (!result)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "IsWow64Process Error");
            }
            return (x86Process) ? ProcessArchitecture.x86 : ProcessArchitecture.x64;                   
        }   

        // opens a handle with PROCESS_QUERY_LIMITED_INFORMATION
        public static IntegrityLevel GetIntegrityLevel(this Process process)
        {
            try
            {
                SafeProcessHandle hProcess = process.Open((uint)(ProcessAccessType.PROCESS_QUERY_LIMITED_INFORMATION));
                IntegrityLevel il = GetIntegrityLevel(hProcess);
                hProcess.Close();
                return il;
            }
            catch(Win32Exception e)
            {
                return IntegrityLevel.Unknown;
            }
        }

        // the handle will need PROCESS_QUERY_LIMITED_INFORMATION
        public static IntegrityLevel GetIntegrityLevel(SafeProcessHandle hProcess)
        {
            try
            {  
                SafeTokenHandle hToken;
                bool res = Advapi32.OpenProcessToken(hProcess, (uint)TokenAccessType.TOKEN_QUERY, out hToken);
                if (!res || hToken.IsInvalid)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken failed on Process " + Kernel32.GetProcessId(hProcess));
                }
             
                uint tokenrl = 0;
                res = Advapi32.GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, IntPtr.Zero, 0, out tokenrl);            
                    
                IntPtr pTokenIL = Marshal.AllocHGlobal((int)tokenrl);

                // Now we ask for the integrity level information again. This may fail
                // if an administrator has added this account to an additional group
                // between our first call to GetTokenInformation and this one.
                if (!Advapi32.GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, pTokenIL, tokenrl, out tokenrl))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "GetTokenInformation failed on Process " + Kernel32.GetProcessId(hProcess));
                }

                hToken.Dispose();                

                IntPtr pSid = Marshal.ReadIntPtr(pTokenIL);
                int dwIntegrityLevel = Marshal.ReadInt32(Advapi32.GetSidSubAuthority(pSid, (Marshal.ReadByte(Advapi32.GetSidSubAuthorityCount(pSid)) - 1U)));

                // Untrusted
                if (dwIntegrityLevel == Winnt.SECURITY_MANDATORY_UNTRUSTED_RID)
                    return IntegrityLevel.Untrusted;

                // Low Integrity
                else if (dwIntegrityLevel == Winnt.SECURITY_MANDATORY_LOW_RID)
                    return IntegrityLevel.Low;

                // Medium Integrity
                else if (dwIntegrityLevel >= Winnt.SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < Winnt.SECURITY_MANDATORY_HIGH_RID)
                    return IntegrityLevel.Medium;

                // High Integrity
                else if (dwIntegrityLevel >= Winnt.SECURITY_MANDATORY_HIGH_RID && dwIntegrityLevel < Winnt.SECURITY_MANDATORY_SYSTEM_RID)
                    return IntegrityLevel.High;

                // System Integrity
                else if (dwIntegrityLevel >= Winnt.SECURITY_MANDATORY_SYSTEM_RID)
                    return IntegrityLevel.System;

                else
                    return IntegrityLevel.Unknown;

            }
            catch (Win32Exception e)
            {
                return IntegrityLevel.Unknown;
            }              
        }

        #region ReadWriteMemory      

        // the given handle needs PROCESS_VM_READ 
        public static T ReadMemory<T>(SafeProcessHandle hProcess, IntPtr address)
        {
            byte[] buffer = new byte[TypeSize<T>.Size];
            bool result = Kernel32.ReadProcessMemory(hProcess, address, buffer, (uint)buffer.Length, 0);
            if (!result)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "ReadProcessMemory failed");
            }
            return BinaryConverter.Deserialize<T>(buffer);
        }

        // the given handle needs PROCESS_VM_WRITE 
        public static void WriteMemory<T>(SafeProcessHandle hProcess, ref T data, IntPtr address)
        {
            byte[] buffer = BinaryConverter.Serialize<T>(data);

            bool result = Kernel32.WriteProcessMemory(hProcess, address, buffer, (uint)buffer.Length, 0);
            if (!result)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "WriteProcessMemory failed");
            }
        }

        // the given handle needs PROCESS_VM_READ 
        public static byte[] ReadMemory(SafeProcessHandle hProcess, IntPtr address, uint size)
        {
            byte[] buffer = new byte[size];
            bool result = Kernel32.ReadProcessMemory(hProcess, address, buffer, size, 0);
            if (!result)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "ReadProcessMemory failed");
            }
            return buffer;
        }

        // the given handle needs PROCESS_VM_WRITE 
        public static void WriteMemory(SafeProcessHandle hProcess, byte[] data, IntPtr address)
        {
            bool result = Kernel32.WriteProcessMemory(hProcess, address, data, (uint)data.Length, 0);
            if (!result)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "WriteProcessMemory failed");
            }
        }
        #endregion ReadWriteMemory
        
        // does not open a handle
        public static bool GetModuleInformation(this Process target, string module_name, out ModuleInformation moduleInformation)
        {
            moduleInformation = new ModuleInformation();

            IntPtr p_rdi = Ntdll.RtlCreateQueryDebugBuffer(0, false);
            if ((IntPtr)p_rdi == IntPtr.Zero)
                return false;

            NtStatus result;
            if (target.Id == Injector.GetProcess().Id)
            {
                result = Ntdll.RtlQueryProcessDebugInformation((int)target.Id, (uint)RtlQueryProcessDebugInformationFunctionFlags.PDI_MODULES, (IntPtr)p_rdi);
            }
            else
            {
                if (Environment.Is64BitProcess)
                {
                    ulong flags = 0;
                    if (target.GetArchitecture() == ProcessArchitecture.x86)
                    {
                        flags = (ulong)(RtlQueryProcessDebugInformationFunctionFlags.PDI_WOW64_MODULES | RtlQueryProcessDebugInformationFunctionFlags.PDI_NONINVASIVE);
                    }
                    else if (target.GetArchitecture() == ProcessArchitecture.x64)
                    {
                        flags = (ulong)(RtlQueryProcessDebugInformationFunctionFlags.PDI_MODULES);
                    }

                    result = Ntdll.RtlQueryProcessDebugInformation((int)target.Id, (uint)flags, (IntPtr)p_rdi);
                }
                else
                {
                    result = Ntdll.RtlQueryProcessDebugInformation((int)target.Id, (uint)(RtlQueryProcessDebugInformationFunctionFlags.PDI_MODULES), (IntPtr)p_rdi);
                }
            }

            RTL_DEBUG_INFORMATION rdi = Marshal.PtrToStructure<RTL_DEBUG_INFORMATION>(p_rdi);
            if (result != NtStatus.Success || rdi.Modules == IntPtr.Zero)
            {
                Ntdll.RtlDestroyQueryDebugBuffer((IntPtr)p_rdi);
                return false;
            }

            DEBUG_MODULES_STRUCT modInfo = Marshal.PtrToStructure<DEBUG_MODULES_STRUCT>(rdi.Modules);

            bool found = false;
            DEBUG_MODULE_INFORMATION dmi = new DEBUG_MODULE_INFORMATION();
            for (int i = 0; i < (int)modInfo.Count; ++i)
            {
                // magic
                dmi = Marshal.PtrToStructure<DEBUG_MODULE_INFORMATION>(rdi.Modules + IntPtr.Size + (Marshal.SizeOf(typeof(DEBUG_MODULE_INFORMATION)) * i));

                // parse name and path
                string path = Encoding.UTF8.GetString(dmi.ImageName, 0, 256);
                int idx = path.IndexOf('\0');
                if (idx >= 0)
                    path = path.Substring(0, idx);

                string name = path.Substring(dmi.ModuleNameOffset, path.Length - dmi.ModuleNameOffset);
               
                if (name.ToUpper() == module_name.ToUpper())
                {
                    moduleInformation.ImageBase = dmi.ImageBase;
                    moduleInformation.ImageSize = dmi.ImageSize;
                    moduleInformation.Name = name;
                    moduleInformation.Path = path;
                    found = true;
                    break;
                }
            }

            Ntdll.RtlDestroyQueryDebugBuffer((IntPtr)p_rdi);  
            return found;
        }

        // does not open a handle
        public static IntPtr GetModuleAddress(this Process target, string module_name)
        {
            ModuleInformation modInfo;
            if (target.GetModuleInformation(module_name, out modInfo))
            {
                return modInfo.ImageBase;
            }
            else
            {
                return IntPtr.Zero;
            }
        }
        
        // will open a handle with PROCESS_VM_READ and PROCESS_QUERY_LIMITED_INFORMATION access rights        
        public static IntPtr GetFunctionAddress(this Process process, IntPtr hmodule, string func_name)
        {
            try
            {
                SafeProcessHandle hProcess = process.Open((uint)(ProcessAccessType.PROCESS_VM_READ | ProcessAccessType.PROCESS_QUERY_LIMITED_INFORMATION));
                IntPtr address = GetFunctionAddress(hProcess, hmodule, func_name);
                hProcess.Close();
                return address;
            }
            catch (Win32Exception e)
            {
                return IntPtr.Zero;
            }
        }

        // will need PROCESS_VM_READ and PROCESS_QUERY_LIMITED_INFORMATION access rights
        public static IntPtr GetFunctionAddress(SafeProcessHandle hProcess,IntPtr hmodule, string func_name)
        {
            if (hmodule == IntPtr.Zero)
                return IntPtr.Zero;

            try
            {
                Winnt.IMAGE_DOS_HEADER idh = ReadMemory<Winnt.IMAGE_DOS_HEADER>(hProcess, hmodule); // get image dos header

                if (idh.e_magic_byte != Winnt.IMAGE_DOS_SIGNATURE)
                {
                    return IntPtr.Zero;
                }

                Winnt.IMAGE_FILE_HEADER ifh = ReadMemory<Winnt.IMAGE_FILE_HEADER>(hProcess, hmodule + idh.e_lfanew); // get image file header

                if (ifh.Magic != Winnt.IMAGE_NT_SIGNATURE)
                {
                    return IntPtr.Zero;
                }

                IntPtr p_ioh = hmodule + idh.e_lfanew + Marshal.SizeOf(typeof(Winnt.IMAGE_FILE_HEADER)); // address of IMAGE_OPTIONAL_HEADER
                IntPtr p_et = IntPtr.Zero;

                switch (ProcessExtensions.GetArchitecture(hProcess))
                {
                    case ProcessArchitecture.x86:
                        Winnt.IMAGE_OPTIONAL_HEADER32 ioh32 = ReadMemory<Winnt.IMAGE_OPTIONAL_HEADER32>(hProcess, p_ioh);
                        p_et = hmodule + (int)ioh32.ExportTable.VirtualAddress;

                        break;
                    case ProcessArchitecture.x64:
                        Winnt.IMAGE_OPTIONAL_HEADER64 ioh64 = ReadMemory<Winnt.IMAGE_OPTIONAL_HEADER64>(hProcess, p_ioh);
                        p_et = hmodule + (int)ioh64.ExportTable.VirtualAddress;
                        break;
                    default:
                        return IntPtr.Zero;
                }

                if (p_et == IntPtr.Zero)
                {
                    hProcess.Close();
                    return IntPtr.Zero;
                }

                Winnt.IMAGE_EXPORT_DIRECTORY ied = ReadMemory<Winnt.IMAGE_EXPORT_DIRECTORY>(hProcess, p_et);

                IntPtr p_funcs = hmodule + (int)ied.AddressOfFunctions;
                IntPtr p_names = hmodule + (int)ied.AddressOfNames;
                IntPtr p_odinals = hmodule + (int)ied.AddressOfNameOrdinals;

                byte[] name_rva_table = new byte[ied.NumberOfNames * 4]; // 4 byte per rva
                Kernel32.ReadProcessMemory(hProcess, p_names, name_rva_table, (uint)name_rva_table.Length, 0);

                byte[] funcaddress_rva_table = new byte[ied.NumberOfFunctions * 4]; // 4 byte per rva
                Kernel32.ReadProcessMemory(hProcess, p_funcs, funcaddress_rva_table, (uint)funcaddress_rva_table.Length, 0);

                byte[] odinal_rva_table = new byte[ied.NumberOfNames * 2]; // 2 byte per index
                Kernel32.ReadProcessMemory(hProcess, p_odinals, odinal_rva_table, (uint)odinal_rva_table.Length, 0);

                // walk through the function names
                for (int i = 0; i < ied.NumberOfNames; i++)
                {
                    IntPtr p_funcname = hmodule + BitConverter.ToInt32(name_rva_table, i * 4);

                    byte[] namebuffer = new byte[64];
                    Kernel32.ReadProcessMemory(hProcess, p_funcname, namebuffer, (uint)namebuffer.Length, 0);


                    var str = System.Text.Encoding.Default.GetString(namebuffer);
                    int idx = str.IndexOf('\0');
                    if (idx >= 0) str = str.Substring(0, idx);

                    if (str == func_name)
                    {
                        ushort offset = BitConverter.ToUInt16(odinal_rva_table, i * 2);
                        int func_rva = BitConverter.ToInt32(funcaddress_rva_table, offset * 4);
                        hProcess.Close();
                        return hmodule + func_rva;
                    }
                }

                return IntPtr.Zero;
            }
            catch(Win32Exception e)
            {
                return IntPtr.Zero;
            } 
        }    
    }
}
