using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace Dll_Injector.Native
{
    public sealed class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeTokenHandle()  : base(true)
        {

        }
        protected override bool ReleaseHandle()
        {
            return Kernel32.CloseHandle(handle);
        }
    }   
}

