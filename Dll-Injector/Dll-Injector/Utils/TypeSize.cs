using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Emit;
using System.Text;
using System.Threading.Tasks;

namespace Dll_Injector.Utils
{
    /* Dont use
     public static class TypeSize<T>
    {
        public readonly static int Size;

        static TypeSize()
        {
            var dm = new DynamicMethod("SizeOfType", typeof(int), new Type[] { });
            ILGenerator il = dm.GetILGenerator();
            il.Emit(OpCodes.Sizeof, typeof(T));
            il.Emit(OpCodes.Ret);
            Size = (int)dm.Invoke(null, null);
        }
    }
    */
}
