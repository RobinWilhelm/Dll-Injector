using Dll_Injector.Native;
using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace Dll_Injector.Utils
{
    public enum ProcessArchitecture
    {
        Unknown,
        x86,
        x64,        
    }

    public enum ThreadCreationMethod
    {
        CreateRemoteThread = 0,
        RtlCreateUserThread,
    }


    public struct ModuleInformation
    {
        public IntPtr ImageBase;
        public UInt32 ImageSize;
        public string Name;
        public string Path;
    }

    public static class RemoteProcessApi
    {
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

        public static SafeThreadHandle CreateThread(SafeProcessHandle hProcess, IntPtr startAddress, IntPtr lpParameter, ThreadCreationMethod method = ThreadCreationMethod.CreateRemoteThread)
        {
            IntPtr hThread = IntPtr.Zero;
            switch (method)
            {
                case ThreadCreationMethod.CreateRemoteThread:
                    IntPtr tmp;
                    hThread = Kernel32.CreateRemoteThread(hProcess, IntPtr.Zero, 0, startAddress, lpParameter, 0, out tmp);
                    if (hThread == IntPtr.Zero)
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateRemoteThread failed");
                    }
                    break;
                case ThreadCreationMethod.RtlCreateUserThread:
                    
                    NtStatus rcut_result = Ntdll.RtlCreateUserThread(hProcess, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, startAddress, lpParameter, ref hThread, IntPtr.Zero);
                    if (rcut_result != NtStatus.Success || hThread == IntPtr.Zero)
                    {
                        throw new Exception("RtlCreateUserThread failed with NtStatus: " + rcut_result.ToString());
                    }
                    break;              
            }
            return new SafeThreadHandle(hThread, true);
        }

        public static void SuspendProcess(SafeProcessHandle hProcess)
        {
            NtStatus status = Ntdll.NtSuspendProcess(hProcess);
            if (status != NtStatus.Success)
            {
                throw new Exception("NtSuspendProcess failed with NtStatus: " + status.ToString());
            }
        }

        public static void ResumeProcess(SafeProcessHandle hProcess)
        {
            NtStatus status = Ntdll.NtResumeProcess(hProcess);
            if (status != NtStatus.Success)
            {
                throw new Exception("NtResumeProcess failed with NtStatus: " + status.ToString());
            }
        }

        public static void SuspendThread(SafeThreadHandle hProcess)
        {
            NtStatus status = Ntdll.NtSuspendThread(hProcess, IntPtr.Zero);
            if (status != NtStatus.Success)
            {
                throw new Exception("NtSuspendThread failed with NtStatus: " + status.ToString());
            }
        }

        public static void ResumeThread(SafeThreadHandle hProcess)
        {
            NtStatus status = Ntdll.NtResumeThread(hProcess, IntPtr.Zero);
            if (status != NtStatus.Success)
            {
                throw new Exception("NtResumeThread failed with NtStatus: " + status.ToString());
            }
        }

        public static ThreadWaitReason GetThreadWaitReason(int procId, int threadId)
        {
            Process proc = Process.GetProcessById(procId);
            if(proc != null)
            {
                foreach(ProcessThread thread in proc.Threads)
                {
                    if(thread.Id == threadId)
                    {
                        if (thread.ThreadState == System.Diagnostics.ThreadState.Wait)
                            return thread.WaitReason;
                    }
                }
            }
            return ThreadWaitReason.Unknown;
        }

        /// <summary>
        /// Will use a thread in the target process to execute an arbitrary function that fulfills the following requirements:
        /// must be __stdcall,
        /// return value is maximal 4 bytes long,
        /// exactly one 4 byte argument
        /// 
        /// this function will return once the called function has returnedöö
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="target">target process</param>
        /// <param name="startAddress">address of function</param>
        /// <param name="param">parameter</param>
        /// <returns></returns>
        public static uint HijackThread(Process target, IntPtr startAddress, IntPtr param)
        {
            // not supported yet
            if (target.GetArchitecture() != ProcessArchitecture.x86)
                return 0;

            using (SafeProcessHandle hProcess = target.Open((uint)(ProcessAccessType.PROCESS_SUSPEND_RESUME | ProcessAccessType.PROCESS_VM_WRITE | ProcessAccessType.PROCESS_VM_READ | ProcessAccessType.PROCESS_VM_OPERATION)))
            {
                SuspendProcess(hProcess);

                IntPtr ht = IntPtr.Zero;
                ProcessThread capturedThread = null;

                foreach (ProcessThread thread in target.Threads)
                {
                    // We are just using the first Thread we find
                    ht = Kernel32.OpenThread((uint)(ThreadAccessType.THREAD_GET_CONTEXT | ThreadAccessType.THREAD_SET_CONTEXT | ThreadAccessType.THREAD_SUSPEND_RESUME), false, (uint)thread.Id);

                    // if that did not work try another thread
                    if (ht == IntPtr.Zero)
                        continue;

                    capturedThread = thread;
                    break;
                }

                if(ht == IntPtr.Zero)
                {
                    throw new Exception("Could not find a thread to capture");
                }

                SafeThreadHandle hThread = new SafeThreadHandle(ht, false);

                CONTEXT context = new CONTEXT();
                context.ContextFlags = (uint)CONTEXT_FLAGS.CONTEXT_FULL;

                if (!Kernel32.GetThreadContext(hThread.DangerousGetHandle(), ref context))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "GetThreadContext failed");
                }
                                
                IntPtr loadlibReturn = RemoteProcessApi.AllocateMemory(hProcess, IntPtr.Zero, 4, MemoryProtection.ReadWrite);
                IntPtr suspendThreadReturn = RemoteProcessApi.AllocateMemory(hProcess, IntPtr.Zero, 4, MemoryProtection.ReadWrite);

                IntPtr hmodule_kernel32 = Kernel32.GetModuleHandle("kernel32.dll");
                IntPtr suspendthreadfn = Kernel32.GetProcAddress(hmodule_kernel32, "SuspendThread");
                IntPtr getCurrentThreadfn = Kernel32.GetProcAddress(hmodule_kernel32, "GetCurrentThread");

                if (suspendthreadfn == IntPtr.Zero || getCurrentThreadfn == IntPtr.Zero)
                {
                    throw new Exception("Did not find function: SuspendThread");
                }

                byte[] shellcode = Shellcode.Shellcode.PrepareShellcodeForThreadHijackingx86((uint)startAddress, (uint)param, (uint)loadlibReturn, context.Eip, (uint)getCurrentThreadfn, (uint)suspendthreadfn, (uint)suspendThreadReturn);

                IntPtr shellcodeAddress = RemoteProcessApi.AllocateMemory(hProcess, IntPtr.Zero, (uint)shellcode.Length, MemoryProtection.ExecuteReadWrite);
                RemoteProcessApi.WriteMemory(hProcess, shellcode, shellcodeAddress);
                
                context.Eip = (UInt32)shellcodeAddress;

                if (!Kernel32.SetThreadContext(hThread.DangerousGetHandle(), ref context))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "SetThreadContext failed");
                }

                ResumeThread(hThread);

                // wait until the thread has finished executing our function
                do
                {
                    Thread.Sleep(100);
                    if(GetThreadWaitReason(target.Id, capturedThread.Id) == ThreadWaitReason.Suspended)
                    {
                        break;
                    }

                } while (true);

                ResumeProcess(hProcess);

                return RemoteProcessApi.ReadMemory<uint>(hProcess, loadlibReturn);               
            }
        }

        public static IntPtr AllocateMemory(SafeProcessHandle hProcess, IntPtr address, uint size, MemoryProtection protection)
        {
            IntPtr result = Kernel32.VirtualAllocEx(hProcess, address, size, (AllocationType.Reserve | AllocationType.Commit),protection);
            if(result == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "VirtualAllocEx failed");
            }
            return result;
        }

        public static void FreeMemory(SafeProcessHandle hProcess, IntPtr address, uint size)
        {
            bool result = Kernel32.VirtualFreeEx(hProcess, address, size, (AllocationType.Release));
            if (!result)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "VirtualFreeEx failed");
            }
        }

        // the given handle needs PROCESS_VM_READ 
        public static T ReadMemory<T>(SafeProcessHandle hProcess, IntPtr address)
        {
            byte[] buffer = new byte[Marshal.SizeOf<T>()];
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

        public static bool GetModuleInformation(int target_id, ProcessArchitecture target_arch ,string module_name, out ModuleInformation moduleInformation)
        {
            moduleInformation = new ModuleInformation();

            IntPtr p_rdi = Ntdll.RtlCreateQueryDebugBuffer(0, false);
            if ((IntPtr)p_rdi == IntPtr.Zero)
                return false;

            NtStatus result;
            if (target_id == Injector.GetProcess().Id)
            {
                result = Ntdll.RtlQueryProcessDebugInformation(target_id, (uint)RtlQueryProcessDebugInformationFunctionFlags.PDI_MODULES, (IntPtr)p_rdi);
            }
            else
            {
                if (Environment.Is64BitProcess)
                {
                    ulong flags = 0;
                    if (target_arch == ProcessArchitecture.x86)
                    {
                        flags = (ulong)(RtlQueryProcessDebugInformationFunctionFlags.PDI_WOW64_MODULES | RtlQueryProcessDebugInformationFunctionFlags.PDI_NONINVASIVE);
                    }
                    else if (target_arch == ProcessArchitecture.x64)
                    {
                        flags = (ulong)(RtlQueryProcessDebugInformationFunctionFlags.PDI_MODULES);
                    }

                    result = Ntdll.RtlQueryProcessDebugInformation(target_id, (uint)flags, (IntPtr)p_rdi);
                }
                else
                {
                    result = Ntdll.RtlQueryProcessDebugInformation(target_id, (uint)(RtlQueryProcessDebugInformationFunctionFlags.PDI_MODULES), (IntPtr)p_rdi);
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

                switch (GetArchitecture(hProcess))
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
