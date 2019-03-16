using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Windows.Forms;
using System.Drawing;

namespace Dll_Injector.Methods
{
    class InjectonMethod
    {
        protected InjectonMethod()
        {
            
        }

        public virtual void PopulateUI(Control control)
        {
            throw new NotImplementedException();
        }     

        public virtual bool Execute(Process target, string dll_path)
        {
            throw new NotImplementedException();
        }        
    }
}
