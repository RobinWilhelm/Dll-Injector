using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Dll_Injector.Native
{
    public enum EnumProcessModulesExFilter : uint
    {
        LIST_MODULES_32BIT = (0x01),
        LIST_MODULES_64BIT = (0x02),
        LIST_MODULES_ALL = (0x03),
        LIST_MODULES_DEFAULT = (0x00)
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MODULEINFO
    {
        public IntPtr lpBaseOfDll;
        public uint SizeOfImage;
        public IntPtr EntryPoint;
    }

    class Psapi
    {
        [DllImport("psapi.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumProcessModulesEx(SafeProcessHandle hProcess, [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)] [In][Out] IntPtr[] lphModule, uint cb, [MarshalAs(UnmanagedType.U4)]  uint lpcbNeeded, uint dwFilterFlag);

        [DllImport("psapi.dll", SetLastError = true)]
        public static extern uint GetModuleFileNameEx(SafeProcessHandle hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, [In] [MarshalAs(UnmanagedType.U4)] uint nSize);

        [DllImport("psapi.dll", SetLastError = true)]
        static extern bool GetModuleInformation(SafeProcessHandle hProcess, IntPtr hModule, out MODULEINFO lpmodinfo, uint cb);
    }
}
