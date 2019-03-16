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

namespace Dll_Injector.Methods
{
    class ReflectiveInjection : InjectonMethod
    {
        private Label lbLoadFnName;
        private TextBox tbLoadFnName;


        public ReflectiveInjection() : base()
        {

        }
        
        public override bool Execute(Process target, string dll_path)
        {
            try
            {
                byte[] modulebytes = File.ReadAllBytes(dll_path);

                // check if we can find the load function
                int loaderFnOffset = (int)PEFileHelper.GetFunctionOffsetFromBytes(modulebytes, tbLoadFnName.Text);
                if (loaderFnOffset == 0)
                {
                    MessageBox.Show("Could not find Load Function", "Aborting Injection");
                    return false;
                }

                SafeProcessHandle hProcess = target.Open((uint)(ProcessAccessType.PROCESS_VM_OPERATION | ProcessAccessType.PROCESS_VM_WRITE));

                IntPtr hmodule = Kernel32.VirtualAllocEx(hProcess, IntPtr.Zero, (uint)modulebytes.Length, AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ExecuteReadWrite);
                ProcessExtensions.WriteMemory(hProcess, modulebytes, hmodule);

                IntPtr loadFnAddress = hmodule + loaderFnOffset;

                IntPtr tmp;
                IntPtr hthread = Kernel32.CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadFnAddress, IntPtr.Zero, 0, out tmp);
            }
            catch(Win32Exception e)
            {
                MessageBox.Show(e.Message, "Aborting Injection");
                return false;
            }

            return true;
        }

        public override void PopulateUI(Control control)
        {
            lbLoadFnName = new Label();
            lbLoadFnName.AutoSize = true;
            lbLoadFnName.Location = new System.Drawing.Point(6, 16);
            lbLoadFnName.Name = "lbLoadFnName";
            lbLoadFnName.Size = new System.Drawing.Size(109, 13);
            lbLoadFnName.TabIndex = 1;
            lbLoadFnName.Text = "Load Function Name:";
            control.Controls.Add(lbLoadFnName);

            tbLoadFnName = new TextBox();      
            tbLoadFnName.Location = new System.Drawing.Point(9, 32);
            tbLoadFnName.Name = "tbLoadFnName";
            tbLoadFnName.Size = new System.Drawing.Size(321, 20);
            tbLoadFnName.TabIndex = 0;
            tbLoadFnName.Text = "ReflectiveLoader";
            control.Controls.Add(tbLoadFnName);           
        }
    }
}
