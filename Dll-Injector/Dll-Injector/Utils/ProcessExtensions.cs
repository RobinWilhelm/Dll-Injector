using Dll_Injector.Native;
using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Dll_Injector.Utils
{
    static class ProcessExtensions
    {
        // opens a handle with PROCESS_QUERY_LIMITED_INFORMATION
        public static IntegrityLevel GetIntegrityLevel(this Process process)
        {
            try
            {
                using (SafeProcessHandle hProcess = process.Open((uint)(ProcessAccessType.PROCESS_QUERY_LIMITED_INFORMATION)))
                {
                   return RemoteProcessApi.GetIntegrityLevel(hProcess);
                }           
            }
            catch (Win32Exception e)
            {
                return IntegrityLevel.Unknown;
            }
        }

        // opens and 
        public static SafeProcessHandle Open(this Process process, uint accessType)
        {
            SafeProcessHandle hProcess = Kernel32.OpenProcess(accessType, false, (uint)process.Id);
            if (hProcess.IsInvalid)
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
                using (SafeProcessHandle hProcess = process.Open((uint)ProcessAccessType.PROCESS_QUERY_LIMITED_INFORMATION))
                {
                    return RemoteProcessApi.GetArchitecture(hProcess);
                }
            }
            catch (Win32Exception e)
            {
                return ProcessArchitecture.Unknown;
            }
        }

        // does not open a handle
        public static bool GetModuleInformation(this Process target, string module_name, out ModuleInformation moduleInformation)
        {
            return RemoteProcessApi.GetModuleInformation(target.Id, target.GetArchitecture(), module_name, out moduleInformation);
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
                using (SafeProcessHandle hProcess = process.Open((uint)(ProcessAccessType.PROCESS_VM_READ | ProcessAccessType.PROCESS_QUERY_LIMITED_INFORMATION)))
                {
                    return RemoteProcessApi.GetFunctionAddress(hProcess, hmodule, func_name);
                }
            }
            catch (Win32Exception e)
            {
                return IntPtr.Zero;
            }
        }
    }
}
