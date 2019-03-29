using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Diagnostics;
using System.IO;
using System.Threading;
using Microsoft.Win32.SafeHandles;
using Dll_Injector.Native;
using Dll_Injector.Methods;
using Dll_Injector.Utils;
using System.Runtime.InteropServices;

namespace Dll_Injector
{
    public partial class Injector : Form
    {
        private static Process injectorprocess;
        private List<Process> processList = new List<Process>();
        private string selectedDll;
        ProcessArchitecture pa_dll = ProcessArchitecture.Unknown;
        InjectonMethod injection;
                
        public static Process GetProcess()
        {
            return injectorprocess;
        }

        public Injector()
        {
            InitializeComponent();

            injectorprocess = Process.GetCurrentProcess();

            InitListView();

            if ((GetProcessArchitecture() == ProcessArchitecture.x86))
                Text += " - 32Bit";

            if (injectorprocess.GetIntegrityLevel() == IntegrityLevel.High)
                Text += " - Privileged";

            RefreshProcesslist();
        }

        private void InitListView()
        {
            lvProcessList.Clear();
            lvProcessList.View = View.Details;
            lvProcessList.Columns.Add("ProcessId", -2);
            lvProcessList.Columns.Add("ProcessName", 240);
            lvProcessList.Columns.Add("Arch", -2);
            lvProcessList.Columns.Add("ILevel", -2);
        }

        private void btRefreshProcesses_Click(object sender, EventArgs e)
        {
            RefreshProcesslist();
        }

        private void btSelectDll_Click(object sender, EventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();

            openFileDialog.InitialDirectory = "c:\\";
            openFileDialog.Filter = "DLL files | *.dll";
            openFileDialog.FilterIndex = 2;
            openFileDialog.RestoreDirectory = true;
            openFileDialog.Multiselect = false;

            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                selectedDll = openFileDialog.FileName;
                tbSelectedDll.Text = openFileDialog.SafeFileName;
            }

            pa_dll = PEFileHelper.GetArchitecture(selectedDll);
            tbDllArchitecture.Text = pa_dll.ToString();
        }
           
        private ProcessArchitecture GetProcessArchitecture()
        {  
            return (Environment.Is64BitProcess) ? ProcessArchitecture.x64 : ProcessArchitecture.x86;
        }        

        private void RefreshProcesslist()
        {
            lbInjectionreturn.Text = "";
            lvProcessList.Items.Clear();
            processList.Clear();

            Process[] processes = Process.GetProcesses();
            foreach (Process process in processes)
            {
                using (SafeProcessHandle hProcess = Kernel32.OpenProcess((uint)ProcessAccessType.PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)process.Id))
                {
                    if (hProcess.IsInvalid)
                        continue;

                    ProcessArchitecture arch = RemoteProcessApi.GetArchitecture(hProcess);
                    
                    // no x86 -> x64 injection, it is too complicated and unnecessesary
                    if (arch == ProcessArchitecture.x64)
                    {
                        if (GetProcessArchitecture() == ProcessArchitecture.x86)
                            continue;
                    }

                    // check if process has any windows
                    if (cbOnlyWindowed.Checked)
                    {
                        if (process.MainWindowHandle == IntPtr.Zero)
                            continue;
                    }

                    // too many of those
                    if (process.ProcessName == "svchost")
                        continue;

                    // skip the injector process
                    if (process.Id == Kernel32.GetCurrentProcessId())
                        continue;

                    processList.Add(process);

                    ListViewItem lvm = new ListViewItem(new[] { process.Id.ToString(), process.ProcessName, arch.ToString(), RemoteProcessApi.GetIntegrityLevel(hProcess).ToString() });
                    lvProcessList.Items.Add(lvm);           
                }
            }
        }        
        
        private void btInject_Click(object sender, EventArgs e)
        {
            if (selectedDll == null || injection == null) return;
            
            foreach (ListViewItem lvm in lvProcessList.CheckedItems)
            {
                if (pa_dll != processList[lvm.Index].GetArchitecture())
                {
                    MessageBox.Show("One or more architectures dont match", "Aborting injection");
                    return;
                }
            }

            int failedcounter = 0;
            foreach(ListViewItem lvm in lvProcessList.CheckedItems)
            {
                if(!injection.Execute(processList[lvm.Index], selectedDll))
                {
                    failedcounter++;
                }
            }

            if(failedcounter == 0)
            {
                lbInjectionreturn.ForeColor = Color.Green;
                lbInjectionreturn.Text = "Success";
            }
            else
            {
                lbInjectionreturn.ForeColor = Color.Red;
                lbInjectionreturn.Text = "Failures: " + failedcounter.ToString();
            }
        }
            

        // DEBUGGING ONLY
        private void button1_Click(object sender, EventArgs e)
        { 
            foreach (ListViewItem lvm in lvProcessList.CheckedItems)
            {
                ModuleInformation modInfo;
                processList[lvm.Index].GetModuleInformation("kernel32.dll", out modInfo);
                IntPtr gfa1 = modInfo.ImageBase + (int)PEFileHelper.GetFunctionOffsetFromDisk(modInfo.Path, "LoadLibraryA");
            }
        }

        private void rbLoadLibrary_CheckedChanged(object sender, EventArgs e)
        {
            if(rbLoadLibrary.Checked ==  true)
            {
                this.gbInjectionOptions.Controls.Clear();
                injection = new LoadLibraryInjection();
                injection.PopulateUI(this.gbInjectionOptions);
            }      
        }
            
        private void rbReflective_CheckedChanged(object sender, EventArgs e)
        {
            if(rbReflective.Checked == true)
            {
                this.gbInjectionOptions.Controls.Clear();
                injection = new ReflectiveInjection();
                injection.PopulateUI(this.gbInjectionOptions);
            }
        }
              
    }
}
