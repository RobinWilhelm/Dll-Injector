using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.IO;

namespace Dll_Injector.Utils
{
    static class BinaryConverter
    {
        public static byte[] Serialize<T>(T data)
        {
            var size = Marshal.SizeOf<T>();
            var array = new byte[size];
            var ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(data, ptr, true);
            Marshal.Copy(ptr, array, 0, size);
            Marshal.FreeHGlobal(ptr);
            return array;
        }

        public static T Deserialize<T>(byte[] bytes)
        {
            var size = Marshal.SizeOf<T>();
            var ptr = Marshal.AllocHGlobal(size);
            Marshal.Copy(bytes, 0, ptr, size);
            var s = (T)Marshal.PtrToStructure(ptr, typeof(T));
            Marshal.FreeHGlobal(ptr);
            return s;          
        }        

        public static T StreamToType<T>(Stream stream)
        {
            int size = Marshal.SizeOf<T>();
            byte[] bytes = new byte[size];

            if (stream.Read(bytes, 0, size) < size)
            {
                throw new Exception();
            }                

            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();

            return theStructure;                                   
        }    
    }
}
