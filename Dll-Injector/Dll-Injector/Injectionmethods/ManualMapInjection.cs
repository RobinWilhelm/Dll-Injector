using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Dll_Injector.Methods
{
    class ManualMapInjection : InjectonMethod
    {
        public ManualMapInjection() : base()
        {
        }

        public override bool Execute(Process target, string dll_path)
        {
            return base.Execute(target, dll_path);
        }

        public override void PopulateUI(Control control)
        {
            base.PopulateUI(control);
        }
    }
}
