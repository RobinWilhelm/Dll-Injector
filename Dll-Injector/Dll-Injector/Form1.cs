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

namespace Dll_Injector
{
    public partial class Form1 : Form
    {
        private static Process m_injectorprocess;
        private List<Process> processList = new List<Process>();
        private string selectedDll;
        ProcessArchitecture pa_dll = ProcessArchitecture.Unknown;
                
        public static Process GetProcess()
        {
            return m_injectorprocess;
        }

        public Form1()
        {
            InitializeComponent();
            m_injectorprocess = Process.GetCurrentProcess();

            InitListView();

            if ((GetProcessArchitecture() == ProcessArchitecture.x86))
                Text += " - 32Bit";

            if (m_injectorprocess.GetIntegrityLevel() == IntegrityLevel.High)
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
            return (IntPtr.Size == 4) ? ProcessArchitecture.x86 : ProcessArchitecture.x64;
        }
        

        private void RefreshProcesslist()
        {
            lvProcessList.Items.Clear();
            processList.Clear();

            Process[] processes = Process.GetProcesses();
            foreach (Process process in processes)
            {
                SafeProcessHandle hProcess = Kernel32.OpenProcess((uint)ProcessAccessType.PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)process.Id);
                if (hProcess.IsInvalid)
                    continue;

                ProcessArchitecture arch = ProcessExtensions.GetArchitecture(hProcess);

        
                // no x86 -> x64 injection, it is complicated and unnecessesary
                if (arch == ProcessArchitecture.x64) { 
                    if (GetProcessArchitecture() == ProcessArchitecture.x86)
                        continue;
                }

                // check if process has any windows
                if(cbOnlyWindowed.Checked){
                    if(process.MainWindowHandle == (IntPtr)0)
                        continue;                    
                }
                                
                // too many of those
                if (process.ProcessName == "svchost")
                    continue;

                // skip the injector process
                if (process.Id == Kernel32.GetCurrentProcessId())
                    continue;

                processList.Add(process);

                ListViewItem lvm = new ListViewItem(new[] { process.Id.ToString(), process.ProcessName, arch.ToString(), ProcessExtensions.GetIntegrityLevel(hProcess).ToString()});
                lvProcessList.Items.Add(lvm);
                hProcess.Close();
            }
        }        


        private void btInject_Click(object sender, EventArgs e)
        {
            if (selectedDll == null) return;

            foreach (ListViewItem lvm in lvProcessList.CheckedItems)
            {
                if (pa_dll != processList[lvm.Index].GetArchitecture())
                {
                    MessageBox.Show("One ore more architectures dont match", "Aborting injection");
                    return;
                }
            }

            InjectonMethod method = new LoadLibrary(LoadLibrary.Option.CreateRemoteThread);

            btInject.Enabled = false;
            foreach(ListViewItem lvm in lvProcessList.CheckedItems)
            {
                method.Inject(processList[lvm.Index], selectedDll);  
            }
            Thread.Sleep(100);
            btInject.Enabled = true;
        }

        private void button1_Click(object sender, EventArgs e)
        {
            foreach (ListViewItem lvm in lvProcessList.CheckedItems)
            {
                ModuleInformation modInfo;
                processList[lvm.Index].GetModuleInformation("kernel32.dll", out modInfo);
                IntPtr ll = PEFileHelper.GetFunctionAddress(modInfo, "LoadLibraryA");
            }
        }

    
    }
}
