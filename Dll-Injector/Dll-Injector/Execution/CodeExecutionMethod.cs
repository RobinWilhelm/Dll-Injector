using Dll_Injector.Utils;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Dll_Injector.Execution
{
    class CodeExecutionMethod
    {
        protected Process target;

        protected CodeExecutionMethod()
        {
        }

        public Process Target { get => target; set => target = value; }

        public virtual SafeThreadHandle ExecuteNonBlocking(IntPtr start, IntPtr param)
        {
            throw new NotImplementedException();
        }

        public virtual uint WaitForReturn(SafeThreadHandle hThread, uint waittime)
        {
            throw new NotImplementedException();
        }
    }
}
