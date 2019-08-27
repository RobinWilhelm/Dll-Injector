using Dll_Injector.Native;
using Dll_Injector.Utils;
using Microsoft.Win32.SafeHandles;
using System;
using System.Diagnostics;

namespace Dll_Injector.Execution
{
    class RtlCreateUserThreadMethod : CodeExecutionMethod
    {

        public RtlCreateUserThreadMethod() : base()
        {

        }

        ~RtlCreateUserThreadMethod()
        {
        
        }
        
        public override SafeThreadHandle ExecuteNonBlocking(IntPtr start, IntPtr param)
        {
            if(target == null || target.HasExited)
            {
                return null;
            }
            SafeThreadHandle hThread = null;
            using (SafeProcessHandle hProcess = Kernel32.OpenProcess((uint)(ProcessAccessType.PROCESS_CREATE_THREAD | ProcessAccessType.PROCESS_VM_WRITE | ProcessAccessType.PROCESS_VM_OPERATION), false, (uint)target.Id))
            {
                IntPtr thread = IntPtr.Zero;
                NtStatus rcut_result = Ntdll.RtlCreateUserThread(hProcess, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, start, param, ref thread, IntPtr.Zero);
                hThread = new SafeThreadHandle(thread, true);

                if (rcut_result != NtStatus.Success || hThread.IsInvalid)
                {
                    throw new Exception("RtlCreateUserThread failed with NtStatus: " + rcut_result.ToString());
                }
            }
            return hThread;
        }

        public override bool WaitForReturn(SafeThreadHandle hThread, uint waittime, out uint returnValue)
        {
            Kernel32.WaitForSingleObject(hThread, waittime);
            uint exitcode = 0;
            bool res = Kernel32.GetExitCodeThread(hThread, ref exitcode);
            hThread.Dispose();
            returnValue = exitcode;
            return res;
        }
    }
}
