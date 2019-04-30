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
using Dll_Injector.Execution;

namespace Dll_Injector.Methods
{

    class LoadLibraryInjection : InjectonMethod
    {
        private RadioButton rbCreateThread;
        private RadioButton rbHijackThread;
        private CheckBox cbUnlinkFromPeb;
        private CodeExecutionMethod executionMethod;

        public LoadLibraryInjection() : base()
        {
            rbCreateThread = new RadioButton();
            rbCreateThread.AutoSize = true;
            rbCreateThread.Location = new System.Drawing.Point(7, 20);
            rbCreateThread.Name = "rbCreateRemoteThread";
            rbCreateThread.Size = new System.Drawing.Size(127, 17);
            rbCreateThread.TabIndex = 0;
            rbCreateThread.TabStop = true;
            rbCreateThread.Text = "Create Thread";
            rbCreateThread.UseVisualStyleBackColor = true;
            rbCreateThread.Click += rbCreateThread_Click;

            rbHijackThread = new RadioButton();
            rbHijackThread.AutoSize = true;
            rbHijackThread.Location = new System.Drawing.Point(7, 40);
            rbHijackThread.Name = "rbHijackThread";
            rbHijackThread.Size = new System.Drawing.Size(127, 17);
            rbHijackThread.TabIndex = 0;
            rbHijackThread.TabStop = true;
            rbHijackThread.Text = "Capture Thread";
            rbHijackThread.UseVisualStyleBackColor = true;
            rbHijackThread.Click += rbHijackThread_Click;

            SetDefaultSettings();
        }

        public void SetDefaultSettings()
        {
            rbCreateThread.Checked = true;
            executionMethod = new RtlCreateUserThreadMethod();
        }

        private void rbCreateThread_Click(object sender, EventArgs e)
        {
            executionMethod = new RtlCreateUserThreadMethod();
        }

        private void rbHijackThread_Click(object sender, EventArgs e)
        {
            executionMethod = new HijackThreadMethod();
        }

        public override bool Execute(Process target, string dll_path)
        {          
            try
            {
                if (executionMethod == null)
                {
                    throw new Exception("executionMethod was null");
                }

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
                    executionMethod.Target = target;
                    using (SafeThreadHandle hThread = executionMethod.ExecuteNonBlocking(LoadLibraryFn, address))
                    {
                        if (!hThread.IsInvalid)
                        {
                            // imagebase of loaded module
                            uint hmod = executionMethod.WaitForReturn(hThread, 3000);
                            if (hmod != 0)
                                return true;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                MessageBox.Show(e.Message, "Loadlibrary Injection failed");
                return false;
            }

            return false;
        }

        public override void PopulateUI(Control control)
        {            
            control.Controls.Add(rbCreateThread);
            control.Controls.Add(rbHijackThread);
        }           
    }
}
