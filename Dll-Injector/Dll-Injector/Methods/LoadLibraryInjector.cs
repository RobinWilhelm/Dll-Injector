using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Dll_Injector.Native;
using System.ComponentModel;

namespace Dll_Injector.Methods
{  
    class LoadLibrary : InjectonMethod
    {
        public enum Option
        {
            CreateRemoteThread = 0,
        };

        public LoadLibrary(Option option) : base()
        {
            m_option = option;
        }

        public override bool Inject(Process target, string dll_path)
        {
            switch (m_option)
            {
                case Option.CreateRemoteThread:
                    return CreateRemoteThread_LoadLibrary(target, dll_path);

                default:
                    return false;
            }
        }

        private bool CreateRemoteThread_LoadLibrary(Process target, string dll)
        {
            try
            {
                // 1 Verbindung zu Zielprozess herstellen (Handle)
                uint access = (uint)(ProcessAccessType.PROCESS_CREATE_THREAD | ProcessAccessType.PROCESS_VM_WRITE | ProcessAccessType.PROCESS_VM_OPERATION);
                SafeProcessHandle hProcess = target.Open(access);

                // 2 Speicheradresse der Funktion LoadLibrary bestimmen 
                IntPtr LoadLibraryFn = target.GetFunctionAddress(target.GetModuleAddress("kernel32.dll"), "LoadLibraryA");
                if (LoadLibraryFn == IntPtr.Zero)
                {
                    hProcess.Close();
                    return false;
                }

                // 3 Speicher im Zielprozess reservieren
                IntPtr address = Kernel32.VirtualAllocEx(hProcess, (IntPtr)null, Convert.ToUInt32(dll.Length), AllocationType.Reserve | AllocationType.Commit, MemoryProtection.ReadWrite);
                if (address == IntPtr.Zero)
                {
                    hProcess.Close();
                    throw new Win32Exception(Marshal.GetLastWin32Error());   
                }

                // 4 DLL Pfad in den reservierten Speicher schreiben
                byte[] buffer = Encoding.ASCII.GetBytes(dll);
                ProcessExtensions.WriteMemory(hProcess, ref buffer, address);                

                // 5 Thread im Zielprozess erstellen und dort LoadLibrary mit der Adresse als Parameter ausführen
                IntPtr tmp;
                IntPtr thread = Kernel32.CreateRemoteThread(hProcess, (IntPtr)null, 0, LoadLibraryFn, address, 0, out tmp);
                if (thread == IntPtr.Zero)
                {
                    hProcess.Close();
                    return false;
                }

                // 6 Verbindungen schließen
                Kernel32.CloseHandle(thread);
                hProcess.Close();
                return true;
            }
            catch(Win32Exception e)
            {
                return false;
            }        
        }

        private Option m_option;
    }
}
