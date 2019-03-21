using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using Dll_Injector.Native;


namespace Dll_Injector.Methods
{
    class ManualMapInjection : InjectonMethod
    {
        public ManualMapInjection()
        {
        }

        public override bool Execute(Process target, string dll_path)
        {
            byte[] modulebytes = File.ReadAllBytes(dll_path);

        }

        public override void PopulateUI(Control control)
        {
            
        }
    }
}
