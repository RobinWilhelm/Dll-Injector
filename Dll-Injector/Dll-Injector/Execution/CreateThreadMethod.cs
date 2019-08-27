using Dll_Injector.Native;
using Dll_Injector.Utils;
using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Dll_Injector.Execution
{
    class CreateRemoteThreadMethod : CodeExecutionMethod
    {
        public CreateRemoteThreadMethod() : base()
        {
        }

        ~CreateRemoteThreadMethod()
        {
       
        }

        public override SafeThreadHandle ExecuteNonBlocking(IntPtr start, IntPtr param)
        {
            if (target == null || target.HasExited)
            {
                return null;
            }
            SafeThreadHandle hThread = null;
            using (SafeProcessHandle hProcess = Kernel32.OpenProcess((uint)ProcessAccessType.PROCESS_CREATE_THREAD, false, (uint)target.Id))
            {
                IntPtr tmp;
                IntPtr  thread = Kernel32.CreateRemoteThread(hProcess, IntPtr.Zero, 0, start, param, 0, out tmp);
                hThread = new SafeThreadHandle(thread, true);
                if (hThread.IsInvalid)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateRemoteThread failed");
                }
            }
            return hThread;
        }

        public override bool WaitForReturn(SafeThreadHandle hThread, uint waittime, out uint returnValue)
        {
            Kernel32.WaitForSingleObject(hThread, waittime);
            uint exitcode = 0;
            bool res = Kernel32.GetExitCodeThread(hThread, ref exitcode);            
            returnValue = exitcode;
            hThread.Close();
            return res;
        }
    }
}
