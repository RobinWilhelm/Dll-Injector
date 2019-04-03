using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.IO;
using Dll_Injector.Utils;
using Dll_Injector.Native;
using Microsoft.Win32.SafeHandles;
using System.Windows.Forms;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Dll_Injector.Methods
{
    [StructLayout(LayoutKind.Sequential)]
    struct ShellcodeInformation32
    {
        public UInt32 raw_module_destination;
        public UInt32 fnLoadLibrary;
        public UInt32 fnGetProcAddress;
        public UInt32 fnVirtualAlloc;
        public UInt32 fnVirtualFree;
        public UInt32 fnVirtualProtect;
        // size of the structure
        public static int StructureSize = Marshal.SizeOf<ShellcodeInformation32>();
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ShellcodeInformation64
    {
        public UInt64 raw_module_destination;
        public UInt64 fnLoadLibrary;
        public UInt64 fnGetProcAddress;
        public UInt64 fnVirtualAlloc;
        public UInt64 fnVirtualFree;
        public UInt64 fnVirtualProtect;
        // size of the structure
        public static int StructureSize = Marshal.SizeOf<ShellcodeInformation64>();
    }

    struct ReflectiveLoaderInfo
    {
        public Process target;
        public SafeProcessHandle hProcess;
        public IntPtr rawModuleAddress;       
        public IntPtr shellcodeAddress;
        public IntPtr shellcodeInfoAddress;
    }

    class ReflectiveInjection : InjectonMethod
    {
        private TextBox tbLoadFnName;
        private RadioButton rbUseExportedFunction;
        private RadioButton rbUseShellcode;

        private Panel threadpanel;
        private RadioButton rbCreateThread;
        private RadioButton rbHijackThread;


        public ReflectiveInjection() : base()
        {
            tbLoadFnName = new TextBox();
            rbUseExportedFunction = new RadioButton();
            rbUseShellcode = new RadioButton();

            threadpanel = new Panel();
            threadpanel.Location = new System.Drawing.Point(0, 10);
            threadpanel.Name = "threadpanel";
            threadpanel.Size = new System.Drawing.Size(336, 100);
            threadpanel.TabIndex = 0;

            rbCreateThread = new RadioButton();
            rbCreateThread.AutoSize = true;
            rbCreateThread.Location = new System.Drawing.Point(7, 20);
            rbCreateThread.Name = "rbCreateRemoteThread";
            rbCreateThread.Size = new System.Drawing.Size(127, 17);
            rbCreateThread.TabIndex = 0;
            rbCreateThread.TabStop = true;
            rbCreateThread.Text = "Create Thread";
            rbCreateThread.UseVisualStyleBackColor = true;
            // this method is used by default
            rbCreateThread.Checked = true;

            rbHijackThread = new RadioButton();
            rbHijackThread.AutoSize = true;
            rbHijackThread.Location = new System.Drawing.Point(7, 40);
            rbHijackThread.Name = "rbHijackThread";
            rbHijackThread.Size = new System.Drawing.Size(127, 17);
            rbHijackThread.TabIndex = 0;
            rbHijackThread.TabStop = true;
            rbHijackThread.Text = "Capture Thread";
            rbHijackThread.UseVisualStyleBackColor = true;

            threadpanel.Controls.Add(rbCreateThread);
            threadpanel.Controls.Add(rbHijackThread);

            // 
            // tbLoadFnName
            // 
            tbLoadFnName.Location = new System.Drawing.Point(7, 105);
            tbLoadFnName.Name = "tbLoadFnName";
            tbLoadFnName.Size = new System.Drawing.Size(324, 20);
            tbLoadFnName.TabIndex = 2;
            tbLoadFnName.Text = "Function Name";
            // 
            // rbUseExportedFunction
            // 
            rbUseExportedFunction.AutoSize = true;
            rbUseExportedFunction.Location = new System.Drawing.Point(7,80);
            rbUseExportedFunction.Name = "rbUseExportedFunction";
            rbUseExportedFunction.Size = new System.Drawing.Size(160, 17);
            rbUseExportedFunction.TabIndex = 0;
            rbUseExportedFunction.Text = "Use Exported Load Function";
            rbUseExportedFunction.UseVisualStyleBackColor = true;
            // 
            // rbUseShellcode
            // 
            rbUseShellcode.AutoSize = true;
            rbUseShellcode.Checked = true;
            rbUseShellcode.Location = new System.Drawing.Point(7, 130);
            rbUseShellcode.Name = "rbUseShellcode";
            rbUseShellcode.Size = new System.Drawing.Size(94, 17);
            rbUseShellcode.TabIndex = 3;
            rbUseShellcode.TabStop = true;
            rbUseShellcode.Text = "Use Shellcode";
            rbUseShellcode.UseVisualStyleBackColor = true;
        }
        
        public override bool Execute(Process target, string dll_path)
        {
            try
            {
                if (rbUseExportedFunction.Checked)
                {
                    return ReflectiveInject_with_LoadFunction(target, dll_path);
                }
                else if(rbUseShellcode.Checked)
                {
                    return ReflectiveInject_with_Shellcode(target, dll_path);
                }

            }
            catch(Win32Exception e)
            {
                MessageBox.Show(e.Message, "Aborting Injection");
                return false;
            }
            return false;
        }

        private void PrepareInjectionx64(ref ReflectiveLoaderInfo loaderinfo)
        {           
            loaderinfo.shellcodeAddress = RemoteProcessApi.AllocateMemory(loaderinfo.hProcess, IntPtr.Zero, (uint)Shellcode.Shellcode.reflectiveloader_shellcode_x64.Length, MemoryProtection.ExecuteReadWrite);
            loaderinfo.shellcodeInfoAddress = RemoteProcessApi.AllocateMemory(loaderinfo.hProcess, IntPtr.Zero, (uint)ShellcodeInformation64.StructureSize, MemoryProtection.ReadWrite);
              
            RemoteProcessApi.WriteMemory(loaderinfo.hProcess, Shellcode.Shellcode.reflectiveloader_shellcode_x64, loaderinfo.shellcodeAddress);
            ShellcodeInformation64 infos = new ShellcodeInformation64();
            ModuleInformation modinfo = new ModuleInformation();

            if(!loaderinfo.target.GetModuleInformation("kernel32.dll", out modinfo))
            {
                throw new Exception("Could not find kernel32.dll in target");
            }

            infos.raw_module_destination = (UInt64)loaderinfo.rawModuleAddress; 
            infos.fnLoadLibrary          = PEFileHelper.GetFunctionOffsetFromDisk(modinfo.Path, "LoadLibraryA", true);
            infos.fnVirtualAlloc         = PEFileHelper.GetFunctionOffsetFromDisk(modinfo.Path, "VirtualAlloc", true);
            infos.fnVirtualFree          = PEFileHelper.GetFunctionOffsetFromDisk(modinfo.Path, "VirtualFree", true);
            infos.fnGetProcAddress       = PEFileHelper.GetFunctionOffsetFromDisk(modinfo.Path, "GetProcAddress", true);
            infos.fnVirtualProtect       = PEFileHelper.GetFunctionOffsetFromDisk(modinfo.Path, "VirtualProtect", true);

            if (infos.fnLoadLibrary == 0 || infos.fnVirtualAlloc == 0 || infos.fnVirtualFree == 0 || infos.fnGetProcAddress == 0 || infos.fnVirtualProtect == 0)
            {
                throw new Exception("Could not find a required function");
            }

            infos.fnLoadLibrary         += (UInt64)modinfo.ImageBase;
            infos.fnVirtualAlloc        += (UInt64)modinfo.ImageBase;
            infos.fnVirtualFree         += (UInt64)modinfo.ImageBase;
            infos.fnGetProcAddress      += (UInt64)modinfo.ImageBase;
            infos.fnVirtualProtect      += (UInt64)modinfo.ImageBase;

            RemoteProcessApi.WriteMemory<ShellcodeInformation64>(loaderinfo.hProcess, ref infos, loaderinfo.shellcodeInfoAddress); 
        }

        private void PrepareInjectionx86(ref ReflectiveLoaderInfo loaderinfo)
        {            
            loaderinfo.shellcodeAddress     = RemoteProcessApi.AllocateMemory(loaderinfo.hProcess, IntPtr.Zero, (uint)Shellcode.Shellcode.reflectiveloader_shellcode_x86.Length, MemoryProtection.ExecuteReadWrite);
            loaderinfo.shellcodeInfoAddress = RemoteProcessApi.AllocateMemory(loaderinfo.hProcess, IntPtr.Zero, (uint)ShellcodeInformation32.StructureSize, MemoryProtection.ReadWrite);
              
            RemoteProcessApi.WriteMemory(loaderinfo.hProcess, Shellcode.Shellcode.reflectiveloader_shellcode_x86, loaderinfo.shellcodeAddress);
            ShellcodeInformation32 infos    = new ShellcodeInformation32();
            ModuleInformation modinfo       = new ModuleInformation();

            if (!loaderinfo.target.GetModuleInformation("kernel32.dll", out modinfo))
            {
                throw new Exception("Could not find kernel32.dll in target");
            }

            infos.raw_module_destination = (UInt32)loaderinfo.rawModuleAddress;
            infos.fnLoadLibrary          = PEFileHelper.GetFunctionOffsetFromDisk(modinfo.Path, "LoadLibraryA", true);
            infos.fnVirtualAlloc         = PEFileHelper.GetFunctionOffsetFromDisk(modinfo.Path, "VirtualAlloc", true);
            infos.fnVirtualFree          = PEFileHelper.GetFunctionOffsetFromDisk(modinfo.Path, "VirtualFree", true);
            infos.fnGetProcAddress       = PEFileHelper.GetFunctionOffsetFromDisk(modinfo.Path, "GetProcAddress", true);
            infos.fnVirtualProtect       = PEFileHelper.GetFunctionOffsetFromDisk(modinfo.Path, "VirtualProtect", true);
            
            if (infos.fnLoadLibrary == 0 || infos.fnVirtualAlloc == 0 || infos.fnVirtualFree == 0 || infos.fnGetProcAddress == 0 || infos.fnVirtualProtect == 0)
            {
                throw new Exception("Could not find a required function");
            }

            infos.fnLoadLibrary      += (UInt32)modinfo.ImageBase;
            infos.fnVirtualAlloc     += (UInt32)modinfo.ImageBase;
            infos.fnVirtualFree      += (UInt32)modinfo.ImageBase;
            infos.fnGetProcAddress   += (UInt32)modinfo.ImageBase;
            infos.fnVirtualProtect   += (UInt32)modinfo.ImageBase;

            RemoteProcessApi.WriteMemory<ShellcodeInformation32>(loaderinfo.hProcess, ref infos, loaderinfo.shellcodeInfoAddress);
        }

        private bool ReflectiveInject_with_Shellcode(Process target, string dll_path)
        {
            ReflectiveLoaderInfo loaderinfo = new ReflectiveLoaderInfo();
            loaderinfo.target = target;
            byte[] rawmodule = File.ReadAllBytes(dll_path);
            bool success = false;

            try
            {
                using (loaderinfo.hProcess = target.Open((uint)(ProcessAccessType.PROCESS_VM_OPERATION | ProcessAccessType.PROCESS_VM_WRITE | ProcessAccessType.PROCESS_VM_READ | ProcessAccessType.PROCESS_CREATE_THREAD)))
                {
                    loaderinfo.rawModuleAddress = RemoteProcessApi.AllocateMemory(loaderinfo.hProcess, IntPtr.Zero, (uint)rawmodule.Length, MemoryProtection.ReadWrite);

                    RemoteProcessApi.WriteMemory(loaderinfo.hProcess, rawmodule, loaderinfo.rawModuleAddress);

                    switch (target.GetArchitecture())
                    {
                        case ProcessArchitecture.Unknown:
                            return false;
                            break;
                        case ProcessArchitecture.x86:
                            PrepareInjectionx86(ref loaderinfo);
                            break;
                        case ProcessArchitecture.x64:
                            PrepareInjectionx64(ref loaderinfo);
                            break;
                    }            

                    if(rbCreateThread.Checked)
                    {
                        SafeThreadHandle hthread = RemoteProcessApi.CreateThread(loaderinfo.hProcess, loaderinfo.shellcodeAddress, loaderinfo.shellcodeInfoAddress, ThreadCreationMethod.RtlCreateUserThread);

                        // check for success
                        Kernel32.WaitForSingleObject(hthread, 3000);
                        uint exitcode = 0;
                        bool res = Kernel32.GetExitCodeThread(hthread, ref exitcode);
                        if (res && exitcode != 0)
                        {
                            success = true;
                        }
                    }
                    else if(rbHijackThread.Checked)
                    {
                        if(RemoteProcessApi.HijackThread(target, loaderinfo.shellcodeAddress, loaderinfo.shellcodeInfoAddress) != 0)
                            success = true;
                    }                                   

                    // remove traces
                    RemoteProcessApi.FreeMemory(loaderinfo.hProcess, loaderinfo.rawModuleAddress, 0);
                    RemoteProcessApi.FreeMemory(loaderinfo.hProcess, loaderinfo.shellcodeInfoAddress, 0);
                    RemoteProcessApi.FreeMemory(loaderinfo.hProcess, loaderinfo.shellcodeAddress, 0);
                }
            }
            catch (Exception e)
            {
                MessageBox.Show(e.Message, "Exception occured in ReflectiveInject_with_Shellcode");
                return success;
            }
            return success;
        }

        private bool ReflectiveInject_with_LoadFunction(Process target, string dll_path)
        {
            byte[] modulebytes = File.ReadAllBytes(dll_path);

            // check if we can find the load function
            int loaderFnOffset = (int)PEFileHelper.GetFunctionOffsetFromBytes(modulebytes, tbLoadFnName.Text);
            if (loaderFnOffset == 0)
            {
                MessageBox.Show("Could not locate the Loader Function", "Aborting Injection");
                return false;
            }

            SafeProcessHandle hProcess = target.Open((uint)(ProcessAccessType.PROCESS_VM_OPERATION | ProcessAccessType.PROCESS_VM_WRITE));

            IntPtr hmodule = Kernel32.VirtualAllocEx(hProcess, IntPtr.Zero, (uint)modulebytes.Length,(AllocationType.Commit | AllocationType.Reserve), MemoryProtection.ExecuteReadWrite);
            RemoteProcessApi.WriteMemory(hProcess, modulebytes, hmodule);

            IntPtr loadFnAddress = hmodule + loaderFnOffset;

            IntPtr tmp;
            IntPtr hthread = Kernel32.CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadFnAddress, IntPtr.Zero, 0, out tmp);

            if (hthread != IntPtr.Zero)
                return true;
            else
                return false;
        }

        public override void PopulateUI(Control control)
        {
            control.Controls.Add(tbLoadFnName);
            control.Controls.Add(rbUseExportedFunction);
            control.Controls.Add(rbUseShellcode);
            control.Controls.Add(threadpanel);
        }
    }
}
