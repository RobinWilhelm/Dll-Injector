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
using Dll_Injector.Utils;
using System.Windows.Forms;

namespace Dll_Injector.Methods
{

    class LoadLibraryInjection : InjectonMethod
    {
        private RadioButton rbCreateRemoteThread;
        private RadioButton rbRtlCreateUserThread;

        public LoadLibraryInjection() : base()
        {
            rbCreateRemoteThread = new RadioButton();
            rbCreateRemoteThread.AutoSize = true;
            rbCreateRemoteThread.Location = new System.Drawing.Point(7, 20);
            rbCreateRemoteThread.Name = "rbCreateRemoteThread";
            rbCreateRemoteThread.Size = new System.Drawing.Size(127, 17);
            rbCreateRemoteThread.TabIndex = 0;
            rbCreateRemoteThread.TabStop = true;
            rbCreateRemoteThread.Text = "CreateRemoteThread";
            rbCreateRemoteThread.UseVisualStyleBackColor = true;
            // this method is used by default
            rbCreateRemoteThread.Checked = true;

            rbRtlCreateUserThread = new RadioButton();
            rbRtlCreateUserThread.AutoSize = true;
            rbRtlCreateUserThread.Location = new System.Drawing.Point(7, 40);
            rbRtlCreateUserThread.Name = "rbRtlCreateUserThread";
            rbRtlCreateUserThread.Size = new System.Drawing.Size(127, 17);
            rbRtlCreateUserThread.TabIndex = 0;
            rbRtlCreateUserThread.TabStop = true;
            rbRtlCreateUserThread.Text = "RtlCreateUserThread";
            rbRtlCreateUserThread.UseVisualStyleBackColor = true;
            // this method is used by default
            rbRtlCreateUserThread.Checked = false;
        }
        
        public override bool Execute(Process target, string dll_path)
        {
            try
            {
                // 1 Verbindung zu Zielprozess herstellen (Handle)
                uint access = (uint)(ProcessAccessType.PROCESS_CREATE_THREAD | ProcessAccessType.PROCESS_VM_WRITE | ProcessAccessType.PROCESS_VM_OPERATION);
                using (SafeProcessHandle hProcess = target.Open(access))
                {
                    // 2 Speicheradresse der Funktion LoadLibrary bestimmen 
                    ModuleInformation modinfo = new ModuleInformation();
                    target.GetModuleInformation("kernel32.dll", out modinfo);

                    IntPtr LoadLibraryFn = modinfo.ImageBase + (int)PEFileHelper.GetFunctionOffsetFromDisk(modinfo.Path, "LoadLibraryA", true);
                    if (LoadLibraryFn == IntPtr.Zero)
                    {
                        throw new Exception("Could not find Function: LoadLibraryA");
                    }

                    // 3 Speicher im Zielprozess reservieren
                    IntPtr address = RemoteProcessApi.AllocateMemory(hProcess, (IntPtr)null, Convert.ToUInt32(dll_path.Length), MemoryProtection.ReadWrite);

                    // 4 DLL Pfad in den reservierten Speicher schreiben
                    byte[] buffer = Encoding.ASCII.GetBytes(dll_path);
                    RemoteProcessApi.WriteMemory(hProcess, buffer, address);
                    
                    // 5 Thread im Zielprozess erstellen und dort LoadLibrary mit der Adresse als Parameter ausführen
                    ThreadCreationMethod threadcreationmethod = 0;
                    if(rbCreateRemoteThread.Checked)
                    {
                        threadcreationmethod = ThreadCreationMethod.CreateRemoteThread;
                    }
                    else if(rbRtlCreateUserThread.Checked)
                    {
                        threadcreationmethod = ThreadCreationMethod.RtlCreateUserThread;
                    }

                    using (SafeThreadHandle hthread = RemoteProcessApi.CreateThread(hProcess, LoadLibraryFn, address, threadcreationmethod))
                    {
                        // check for success
                        Kernel32.WaitForSingleObject(hthread, 3000);
                        uint exitcode = 0;
                        bool res = Kernel32.GetExitCodeThread(hthread, ref exitcode);

                        if (res && exitcode != 0)
                        {
                            return true;
                        }
                        else
                        {
                            return false;
                        }
                    }
                }
            }
            catch (Win32Exception e)
            {
                return false;
            }
        }

        public override void PopulateUI(Control control)
        {            
            control.Controls.Add(rbCreateRemoteThread);
            control.Controls.Add(rbRtlCreateUserThread);
        }           
    }
}
