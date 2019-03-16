using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Dll_Injector.Native;

namespace Dll_Injector.Utils
{
    class PEHeader
    {
        Winnt.IMAGE_DOS_HEADER dos_header;
        Winnt.IMAGE_FILE_HEADER file_header;
        Winnt.IMAGE_OPTIONAL_HEADER32 optional_header32;
        Winnt.IMAGE_OPTIONAL_HEADER64 optional_header64;
        List<Winnt.IMAGE_SECTION_HEADER> section_headers;

        internal Winnt.IMAGE_DOS_HEADER Dos_header { get => dos_header; }
        internal Winnt.IMAGE_FILE_HEADER File_header { get => file_header; }
        internal Winnt.IMAGE_OPTIONAL_HEADER32 Optional_header32 { get => optional_header32; }
        internal Winnt.IMAGE_OPTIONAL_HEADER64 Optional_header64 { get => optional_header64; }
        internal List<Winnt.IMAGE_SECTION_HEADER> Section_headers { get => section_headers; }

        private PEHeader()
        {
            section_headers = new List<Winnt.IMAGE_SECTION_HEADER>();
        }

        public ProcessArchitecture GetArchitecture()
        {
            switch (file_header.Machine)
            {
                case Winnt.MachineType.I386:
                    return ProcessArchitecture.x86;
                case Winnt.MachineType.x64:
                    return ProcessArchitecture.x64;
                default:
                    return ProcessArchitecture.Unknown;
            }
        }

        public uint ConvertRVAtoPhysical(uint rva)
        {
            foreach (var section in section_headers)
            {
                if (rva >= section.VirtualAddress && rva <= section.VirtualAddress + section.VirtualSize)
                {
                    // bingo
                    return rva - section.VirtualAddress + section.PointerToRawData;
                }
            }
            return 0;
        }

        public static PEHeader CreateFromByteArray(byte[] data)
        {
            PEHeader peheader = new PEHeader();

            peheader.dos_header = BinaryConverter.Deserialize<Winnt.IMAGE_DOS_HEADER>(data.SubArray<byte>(0, Winnt.IMAGE_DOS_HEADER.StructureSize));
            if (peheader.dos_header.e_magic_byte != Winnt.IMAGE_DOS_SIGNATURE)
                return null;

            peheader.file_header = BinaryConverter.Deserialize<Winnt.IMAGE_FILE_HEADER>(data.SubArray<byte>(peheader.dos_header.e_lfanew, Winnt.IMAGE_FILE_HEADER.StructureSize));
            if (peheader.file_header.Magic != Winnt.IMAGE_NT_SIGNATURE)
                return null;

            int offset_of_optional_headers = peheader.dos_header.e_lfanew + Winnt.IMAGE_FILE_HEADER.StructureSize;
            int offset_of_section_headers = 0;

            switch (peheader.file_header.Machine)
            {
                case Winnt.MachineType.I386:
                    peheader.optional_header32 = BinaryConverter.Deserialize<Winnt.IMAGE_OPTIONAL_HEADER32>(data.SubArray<byte>(offset_of_optional_headers, Winnt.IMAGE_OPTIONAL_HEADER32.StructureSize));
                    offset_of_section_headers = offset_of_optional_headers + Winnt.IMAGE_OPTIONAL_HEADER32.StructureSize;
                    break;
                case Winnt.MachineType.x64:
                    peheader.optional_header64 = BinaryConverter.Deserialize<Winnt.IMAGE_OPTIONAL_HEADER64>(data.SubArray<byte>(offset_of_optional_headers, Winnt.IMAGE_OPTIONAL_HEADER64.StructureSize));
                    offset_of_section_headers = offset_of_optional_headers + Winnt.IMAGE_OPTIONAL_HEADER64.StructureSize;
                    break;
                default:
                    return null;
            }

            for (int section_counter = 0; ; section_counter++)
            {
                Winnt.IMAGE_SECTION_HEADER ish = BinaryConverter.Deserialize<Winnt.IMAGE_SECTION_HEADER>(data.SubArray<byte>(offset_of_section_headers + (section_counter * Winnt.IMAGE_SECTION_HEADER.StructureSize), Winnt.IMAGE_SECTION_HEADER.StructureSize));

                if (ish.Name[0] == '\0') // we have reached the end
                {
                    break;
                }
                else
                {
                    peheader.section_headers.Add(ish);
                }
            }

            return peheader;
        }

        public static PEHeader CreateFromStream(Stream data)
        {
            if (!data.CanRead || !data.CanSeek)
                return null;

            PEHeader peheader = new PEHeader();

            data.Seek(0, SeekOrigin.Begin);
            peheader.dos_header = BinaryConverter.StreamToType<Winnt.IMAGE_DOS_HEADER>(data);
            if (peheader.dos_header.e_magic_byte != Winnt.IMAGE_DOS_SIGNATURE)
                return null;

            data.Seek(peheader.dos_header.e_lfanew, SeekOrigin.Begin);
            peheader.file_header = BinaryConverter.StreamToType<Winnt.IMAGE_FILE_HEADER>(data);
            if (peheader.file_header.Magic != Winnt.IMAGE_NT_SIGNATURE)
                return null;

            int offset_of_optional_headers = peheader.dos_header.e_lfanew + Winnt.IMAGE_FILE_HEADER.StructureSize;
            int offset_of_section_headers = 0;
            data.Seek(offset_of_optional_headers, SeekOrigin.Begin);

            switch (peheader.file_header.Machine)
            {
                case Winnt.MachineType.I386:
                    peheader.optional_header32 = BinaryConverter.StreamToType<Winnt.IMAGE_OPTIONAL_HEADER32>(data);
                    offset_of_section_headers = offset_of_optional_headers + Winnt.IMAGE_OPTIONAL_HEADER32.StructureSize;
                    break;
                case Winnt.MachineType.x64:
                    peheader.optional_header64 = BinaryConverter.StreamToType<Winnt.IMAGE_OPTIONAL_HEADER64>(data);
                    offset_of_section_headers = offset_of_optional_headers + Winnt.IMAGE_OPTIONAL_HEADER64.StructureSize;
                    break;
                default:
                    return null;
            }

            for (int section_counter = 0; ; section_counter++)
            {
                data.Seek(offset_of_section_headers + (section_counter * Winnt.IMAGE_SECTION_HEADER.StructureSize), SeekOrigin.Begin);
                Winnt.IMAGE_SECTION_HEADER ish = BinaryConverter.StreamToType<Winnt.IMAGE_SECTION_HEADER>(data);

                if (ish.Name[0] == '\0') // we have reached the end
                {
                    break;
                }
                else
                {
                    peheader.section_headers.Add(ish);
                }
            }

            return peheader;
        }
    }
}
