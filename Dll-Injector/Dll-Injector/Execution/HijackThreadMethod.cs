using Dll_Injector.Native;
using Dll_Injector.Utils;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Dll_Injector.Execution
{
    class HijackThreadMethod : CodeExecutionMethod
    {
        ProcessThread capturedThread = null;
        IntPtr addressOfReturn;
        IntPtr shellcodeAddress;

        private void PrepareHijackingx86(SafeThreadHandle hThread, SafeProcessHandle hProcess, IntPtr start, IntPtr param)
        {
            CONTEXT context = new CONTEXT();
            context.ContextFlags = (uint)CONTEXT_FLAGS.CONTEXT_FULL;

            if (!Kernel32.GetThreadContext(hThread.DangerousGetHandle(), ref context))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "GetThreadContext failed");
            }

            addressOfReturn = RemoteProcessApi.AllocateMemory(hProcess, IntPtr.Zero, 4, MemoryProtection.ReadWrite);
            IntPtr suspendThreadReturn = RemoteProcessApi.AllocateMemory(hProcess, IntPtr.Zero, 4, MemoryProtection.ReadWrite);

            ModuleInformation modinfo = new ModuleInformation();
            RemoteProcessApi.GetModuleInformation(target.Id, target.GetArchitecture(), "kernel32.dll", out modinfo);

            IntPtr suspendthreadfn = modinfo.ImageBase + (int)PEFileHelper.GetFunctionOffsetFromDisk(modinfo.Path, "SuspendThread", true);
            IntPtr getCurrentThreadfn = modinfo.ImageBase + (int)PEFileHelper.GetFunctionOffsetFromDisk(modinfo.Path, "GetCurrentThread", true);

            if (suspendthreadfn == IntPtr.Zero || getCurrentThreadfn == IntPtr.Zero)
            {
                throw new Exception("Did not find function: SuspendThread");
            }

            byte[] shellcode = Shellcode.Shellcode.threadhijacking_shellcode_x86;

            // prepare shellcode
            BinaryConverter.CopyToByteArray(context.Eip, shellcode, 1);
            BinaryConverter.CopyToByteArray((uint)param, shellcode, 8);
            BinaryConverter.CopyToByteArray((uint)start, shellcode, 13);
            BinaryConverter.CopyToByteArray((uint)addressOfReturn, shellcode, 20);
            BinaryConverter.CopyToByteArray((uint)getCurrentThreadfn, shellcode, 25);
            BinaryConverter.CopyToByteArray((uint)suspendthreadfn, shellcode, 33);
            BinaryConverter.CopyToByteArray((uint)suspendThreadReturn, shellcode, 40);

            shellcodeAddress = RemoteProcessApi.AllocateMemory(hProcess, IntPtr.Zero, (uint)shellcode.Length, MemoryProtection.ExecuteReadWrite);
            RemoteProcessApi.WriteMemory(hProcess, shellcode, shellcodeAddress);

            context.Eip = (UInt32)shellcodeAddress;

            if (!Kernel32.SetThreadContext(hThread.DangerousGetHandle(), ref context))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "SetThreadContext failed");
            }
        }

        private void PrepareHijackingx64(SafeThreadHandle hThread, SafeProcessHandle hProcess, IntPtr start, IntPtr param)
        {
            CONTEXT64 context = new CONTEXT64();
            context.ContextFlags = CONTEXT_FLAGS.CONTEXT_FULL;

            if (!Kernel32.GetThreadContext(hThread.DangerousGetHandle(), ref context))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "GetThreadContext failed");
            }

            addressOfReturn = RemoteProcessApi.AllocateMemory(hProcess, IntPtr.Zero, 4, MemoryProtection.ReadWrite);
            IntPtr suspendThreadReturn = RemoteProcessApi.AllocateMemory(hProcess, IntPtr.Zero, 4, MemoryProtection.ReadWrite);

            ModuleInformation modinfo = new ModuleInformation();
            RemoteProcessApi.GetModuleInformation(target.Id, target.GetArchitecture(), "kernel32.dll", out modinfo);

            IntPtr suspendthreadfn = modinfo.ImageBase + (int)PEFileHelper.GetFunctionOffsetFromDisk(modinfo.Path, "SuspendThread", true);
            IntPtr getCurrentThreadfn = modinfo.ImageBase + (int)PEFileHelper.GetFunctionOffsetFromDisk(modinfo.Path, "GetCurrentThread", true);

            if (suspendthreadfn == IntPtr.Zero || getCurrentThreadfn == IntPtr.Zero)
            {
                throw new Exception("Did not find function: SuspendThread");
            }

            byte[] shellcode = Shellcode.Shellcode.threadhijacking_shellcode_x64;

            // prepare shellcode
            BinaryConverter.CopyToByteArray((UInt32)(context.Rip), shellcode, 7);
            BinaryConverter.CopyToByteArray((UInt32)((UInt64)context.Rip >> 32), shellcode, 15);
            BinaryConverter.CopyToByteArray((UInt64)start, shellcode, 42);
            BinaryConverter.CopyToByteArray((UInt64)param, shellcode, 52);
            BinaryConverter.CopyToByteArray((UInt64)addressOfReturn, shellcode, 84);
            BinaryConverter.CopyToByteArray((UInt64)getCurrentThreadfn, shellcode, 94);
            BinaryConverter.CopyToByteArray((UInt64)suspendthreadfn, shellcode, 109);
            BinaryConverter.CopyToByteArray((UInt64)suspendThreadReturn, shellcode, 121);

            shellcodeAddress = RemoteProcessApi.AllocateMemory(hProcess, IntPtr.Zero, (uint)shellcode.Length, MemoryProtection.ExecuteReadWrite);
            RemoteProcessApi.WriteMemory(hProcess, shellcode, shellcodeAddress);

            context.Rip = (UInt64)shellcodeAddress;

            if (!Kernel32.SetThreadContext(hThread.DangerousGetHandle(), ref context))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "SetThreadContext failed");
            }
        }
        

        public override SafeThreadHandle ExecuteNonBlocking(IntPtr start, IntPtr param)
        {
            // this method works only on x86 and only if injector process is x86 too (todo solution: http://www.nynaeve.net/Code/GetThreadWow64Context.cpp)
            if (target.GetArchitecture() != Injector.GetProcessArchitecture())
            {
                throw new NotSupportedException("only x86 -> x86 or x64 -> x64 supported for this method right now");
            }

            using (SafeProcessHandle hProcess = target.Open((uint)(ProcessAccessType.PROCESS_SUSPEND_RESUME | ProcessAccessType.PROCESS_VM_WRITE | ProcessAccessType.PROCESS_VM_READ | ProcessAccessType.PROCESS_VM_OPERATION)))
            {
                RemoteProcessApi.SuspendProcess(hProcess);

                IntPtr ht = IntPtr.Zero;
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



                if (ht == IntPtr.Zero)
                {
                    throw new Exception("Could not find a thread to capture");
                }

                SafeThreadHandle hThread = new SafeThreadHandle(ht, true);
               
                if(target.GetArchitecture() == ProcessArchitecture.x86)
                {
                    PrepareHijackingx86(hThread, hProcess, start, param);
                }
                else if(target.GetArchitecture() == ProcessArchitecture.x64)
                {
                    PrepareHijackingx64(hThread, hProcess, start, param);
                }

                RemoteProcessApi.ResumeThread(hThread);
                
        
               return hThread;
            }
        }

        public override uint WaitForReturn(SafeThreadHandle hThread, uint waittime)
        {
            if(capturedThread == null || shellcodeAddress == IntPtr.Zero)
            {
                throw new Exception("capturedhthread was null");
            }

            using (SafeProcessHandle hProcess = target.Open((uint)(ProcessAccessType.PROCESS_SUSPEND_RESUME | ProcessAccessType.PROCESS_VM_READ | ProcessAccessType.PROCESS_VM_OPERATION)))
            {
                // wait until the thread has finished executing our function
                do
                {
                    Thread.Sleep(10);
                    if (RemoteProcessApi.GetThreadWaitReason(target.Id, capturedThread.Id) == ThreadWaitReason.Suspended)
                    {
                        break;
                    }
                    waittime -= 10;
                } while (waittime > 0);
                                
                RemoteProcessApi.ResumeProcess(hProcess);
                RemoteProcessApi.FreeMemory(hProcess, shellcodeAddress, 0);

                // read and return the returnvalue
                return RemoteProcessApi.ReadMemory<uint>(hProcess, addressOfReturn);
            }            
        }
    }
}
