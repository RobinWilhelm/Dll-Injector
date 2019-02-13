using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace Dll_Injector.Methods
{
    class InjectonMethod
    {
        protected InjectonMethod()
        {

        }
               
        public virtual bool Inject(Process target, string dll_path)
        {
            throw new NotImplementedException();
        }
    }
}
