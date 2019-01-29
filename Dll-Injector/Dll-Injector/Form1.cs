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

namespace Dll_Injector
{
    public partial class Form1 : Form
    {
        private List<Process> processList = new List<Process>();
        private string selectedDll;

        public Form1()
        {
            InitializeComponent();
            Text += (IsX86Injector()) ? " 32Bit Mode" : " 64Bit Mode";

            RefreshProcesslist();
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
        }

        private void clbProcesslist_ItemCheck(object sender, ItemCheckEventArgs e)
        {
            if (e.NewValue == CheckState.Checked)
                for (int ix = 0; ix < clbProcesslist.Items.Count; ++ix)
                    if (e.Index != ix) clbProcesslist.SetItemChecked(ix, false);
        }   

        private bool IsX86Injector()
        {
            return (IntPtr.Size == 4);
        }

        private void RefreshProcesslist()
        {
            clbProcesslist.DataSource = null;
            processList.Clear();

            Process[] processes = Process.GetProcesses();
            foreach (Process p in processes)
            {
                IntPtr handle = Kernel32.OpenProcess((uint)Kernel32.ProcessAccessType.PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)p.Id);
                bool x86Process;
                Kernel32.IsWow64Process(handle, out x86Process);
                Kernel32.CloseHandle(handle);

                if (!(IsX86Injector() == x86Process))
                {
                    continue;
                }

                if(cbOnlyWindowed.Checked)
                {
                    if(p.MainWindowHandle == (IntPtr)0)
                    {
                        continue;
                    }
                }

                // too many of these
                if (p.ProcessName == "svchost")
                    continue;

                processList.Add(p);
            }

            ((ListBox)clbProcesslist).DataSource = processList;
            ((ListBox)clbProcesslist).DisplayMember = "ProcessName";
            ((ListBox)clbProcesslist).ValueMember = "Id";  
        }        

        

        private void btInject_Click(object sender, EventArgs e)
        {
            if (selectedDll == null) return;

            foreach(Process target in clbProcesslist.CheckedItems)
            {            
                // 1 Verbindung zu Zielprozess herstellen (Handle)
                uint access = (uint)(Kernel32.ProcessAccessType.PROCESS_CREATE_THREAD | 
                    Kernel32.ProcessAccessType.PROCESS_VM_WRITE | Kernel32.ProcessAccessType.PROCESS_VM_OPERATION);
                IntPtr handle = Kernel32.OpenProcess(access, false, (uint)target.Id);
                if (handle == null) continue;

                // 2 Speicheradresse der Funktion LoadLibrary bestimmen 
                IntPtr LoadLibraryFn = Kernel32.GetProcAddress(Kernel32.GetModuleHandle("kernel32.dll"), "LoadLibraryA");
                if (LoadLibraryFn == null)
                {
                    Kernel32.CloseHandle(handle);
                    continue;
                }                

                // 3 Speicher im Zielprozess reservieren
                IntPtr address = Kernel32.VirtualAllocEx(handle, (IntPtr)null, Convert.ToUInt32(selectedDll.Length), 
                    Kernel32.AllocationType.Reserve | Kernel32.AllocationType.Commit, Kernel32.MemoryProtection.ReadWrite);
                if (address == null)
                {
                    Kernel32.CloseHandle(handle);
                    continue;
                }

                // 4 DLL Pfad in den reservierten Speicher schreiben
                byte[] buffer = Encoding.ASCII.GetBytes(selectedDll);
                bool success = Kernel32.WriteProcessMemory(handle, address, buffer, (uint)buffer.Length, 0);
                if (!success)
                {
                    Kernel32.CloseHandle(handle);
                    continue;
                }

                // 5 Thread im Zielprozess erstellen und dort LoadLibrary mit der Adresse als Parameter ausführen
                IntPtr tmp;
                IntPtr thread = Kernel32.CreateRemoteThread(handle, (IntPtr)null, 0, LoadLibraryFn, address, 0, out tmp);
                if (thread == null)
                {
                    Kernel32.CloseHandle(handle);
                    continue;
                }

                // 6 Verbindungen schließen
                Kernel32.CloseHandle(thread);
                Kernel32.CloseHandle(handle);
            }           
        }       
    }
}
