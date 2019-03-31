using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using Dll_Injector.Utils;
using Microsoft.Win32.SafeHandles;

namespace Dll_Injector.Native
{

enum RtlQueryProcessDebugInformationFunctionFlags : uint
    {
        PDI_MODULES = 0x01,
        PDI_BACKTRACE = 0x02,
        PDI_HEAPS =	0x04,
        PDI_HEAP_TAGS =	0x08,
        PDI_HEAP_BLOCKS = 0x10,
        PDI_LOCKS = 0x20,
        PDI_WOW64_MODULES =	0x40,
        PDI_VERIFIER_OPTIONS = 0x80,
        PDI_MODULES_EX = 0x100,
        PDI_HEAP_ENTRIES_EX = 0x200,
        PDI_CS_OWNER = 0x400,
        PDI_NONINVASIVE = 0x80000000,
    }

    [StructLayout(LayoutKind.Sequential)]
    struct DEBUG_MODULE_INFORMATION
    {
        public IntPtr Section;
        public IntPtr MappedBase;
        public IntPtr ImageBase;
        public uint ImageSize;
        public uint ImageFlags;
        public ushort LoadOrderIndex;
        public ushort InitOrderIndex;
        public ushort LoadCount;
        public ushort ModuleNameOffset;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte [] ImageName;

        // size of the structure
        public static int StructureSize = Marshal.SizeOf<DEBUG_MODULE_INFORMATION>();
    }

    [StructLayout(LayoutKind.Sequential)]
    struct DEBUG_MODULES_STRUCT
    {
        public uint Count;
        public DEBUG_MODULE_INFORMATION DbgModInfo; // It is actually an array of DEBUG_MODULE_INFORMATION, but i dont think it is possible to build that in c#

        // size of the structure
        public static int StructureSize = Marshal.SizeOf<DEBUG_MODULES_STRUCT>();
    }
  


    [StructLayout(LayoutKind.Sequential)]
    struct RTL_DEBUG_INFORMATION
    {
        public IntPtr SectionHandleClient;
        public IntPtr ViewBaseClient;
        public IntPtr ViewBaseTarget;
        public IntPtr ViewBaseDelta;
        public IntPtr EventPairClient;
        public IntPtr EventPairTarget;
        public IntPtr TargetProcessId;
        public IntPtr TargetThreadHandle;
        public uint Flags;
        public IntPtr OffsetFree;
        public IntPtr CommitSize;
        public IntPtr ViewSize;

        // We have two types module information structures. 
        public IntPtr Modules;
        //PRTL_PROCESS_MODULE_INFORMATION_EX ModulesEx;

        public IntPtr BackTraces;
        public IntPtr Heaps; // x86 offset should be 0x38, x64 offset should be 0x70.
        public IntPtr Locks;
        public IntPtr SpecificHeap;
        public IntPtr TargetProcessHandle;
        public IntPtr VerifierOptions;
        public IntPtr ProcessHeap;
        public IntPtr CriticalSectionHandle;
        public IntPtr CriticalSectionOwnerThread;
        public IntPtr Reserved1;
        public IntPtr Reserved2;
        public IntPtr Reserved3;
        public IntPtr Reserved4;

        // size of the structure
        public static int StructureSize = Marshal.SizeOf<RTL_DEBUG_INFORMATION>();
    }

    [StructLayout(LayoutKind.Sequential)]
    struct CLIENT_ID
    {
        IntPtr UniqueProcess;
        IntPtr UniqueThread;
    };

    class Ntdll
    {
        [DllImport("ntdll.dll")]
        public static extern IntPtr RtlCreateQueryDebugBuffer(uint Size, bool EventPair);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlDestroyQueryDebugBuffer(IntPtr DebugBuffer);

        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlQueryProcessDebugInformation(int ProcessId, uint DebugInfoClassMask, IntPtr DebugBuffer);
      
        [DllImport("ntdll.dll")]
        public static extern NtStatus RtlCreateUserThread(SafeProcessHandle ProcessHandle, IntPtr SecurityDescriptor,  bool CreateSuspended, uint StackZeroBits, IntPtr StackReserved, IntPtr StackCommit, IntPtr StartAddress, IntPtr StartParameter, ref IntPtr ThreadHandle, IntPtr ClientID);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSuspendProcess(SafeProcessHandle hProcess);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtResumeProcess(SafeProcessHandle hProcess);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtSuspendThread(SafeThreadHandle hThread, IntPtr PreviousSuspendCount);

        [DllImport("ntdll.dll")]
        public static extern NtStatus NtResumeThread(SafeThreadHandle hThread, IntPtr SuspendCount);
    }
}
