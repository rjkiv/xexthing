using System.Diagnostics;
using System.Reflection.PortableExecutable;

class Program {
    static void Main(string[] args) {
        if (args.Length < 1) {
            Console.WriteLine("need a file");
            return;
        }

        string filePath = args[0];
        string groundTruth = args[1];
        Console.WriteLine(filePath);
        Console.WriteLine(groundTruth);
        byte[] fileData = File.ReadAllBytes(filePath);

        // 1. read in the xex, and get the resulting exe
        BEBinaryReader br = new BEBinaryReader(new MemoryStream(fileData));
        Xex xex = new Xex();
        xex.Read(br);

        // 2. take the exe, and reformat it around the "virtual address" hacks
        PEReader pr = new PEReader(new MemoryStream(xex.xexHeader.peImage));

        var headers = pr.PEHeaders;

        List<byte> peAdjusted = new();

        // duplicate the bytes up til the first section's PointerToRawData
        for (int i = 0; i < headers.SectionHeaders[0].VirtualAddress; i++) {
            peAdjusted.Add(xex.xexHeader.peImage[i]);
        }
        //Console.WriteLine($"Bytes 0 through 0x{headers.SectionHeaders[0].VirtualAddress:X} have been duplicated!");

        for(int i = 0; i < headers.SectionHeaders.Length; i++) {
            var section = headers.SectionHeaders[i];
            //Console.WriteLine($"For section {section.Name}, I need to grab jeff.exe's data at 0x{section.VirtualAddress:X8}," +
            //    $"and write the next 0x{section.SizeOfRawData:X8} bytes from it to the adjusted PE.\n" +
            //    $"We're expecting the current index to write to to be 0x{section.PointerToRawData:X8}");
            Debug.Assert(peAdjusted.Count == section.PointerToRawData, "Unexpected PE size at this point!");
            List<byte> sectionBytes = new();
            for(int j = 0; j < section.SizeOfRawData; j++) {
                if(j + section.VirtualAddress >= xex.xexHeader.peImage.Length) {
                    sectionBytes.Add(0);
                }
                else sectionBytes.Add(xex.xexHeader.peImage[j + section.VirtualAddress]);
            }
            peAdjusted.AddRange(sectionBytes);
        }

        // 3. analyze the reloc table
        PEReader prGroundTruth = new PEReader(new MemoryStream(File.ReadAllBytes(groundTruth)));
        var groundTruthRelocs = prGroundTruth.GetSectionData(".reloc");
        var relocBytes = groundTruthRelocs.GetContent().ToArray();
        Console.WriteLine($".reloc section size: 0x{relocBytes.Length:X} bytes");
        BinaryReader relocReader = new BinaryReader(new MemoryStream(relocBytes));


        while(relocReader.BaseStream.Position < relocReader.BaseStream.Length) {
            var curPos = relocReader.BaseStream.Position;
            uint pageRVA = relocReader.ReadUInt32();
            uint blockSize = relocReader.ReadUInt32();

            if (blockSize < 8 || relocReader.BaseStream.Position + blockSize > relocReader.BaseStream.Length) {
                break; // invalid block, stop parsing
            }

            int entryCount = (int)((blockSize - 8) / 2);
            Console.WriteLine($"Page RVA: 0x{pageRVA:X8}, Block Size: {blockSize}, Entry count: {entryCount}");

            for(int i = 0; i < entryCount; i++) {
                ushort entry = relocReader.ReadUInt16();
                int type = entry >> 12;
                int relocOffset = entry & 0xFFF;

                if(pageRVA == 0x1000 || pageRVA == 0x2000)
                    Console.WriteLine($"  Entry[{i}]: Type={type}, Offset=0x{relocOffset:X4}");
            }
            relocReader.BaseStream.Seek(curPos + blockSize, SeekOrigin.Begin);

        }

        //int offset = 0;
        //while (offset < relocBytes.Length) {

        //    uint pageRVA = BitConverter.ToUInt32(relocBytes, offset);
        //    uint blockSize = BitConverter.ToUInt32(relocBytes, offset + 4);

        //    if (blockSize < 8 || offset + blockSize > relocBytes.Length)
        //        break; // invalid block, stop parsing

        //    int entryCount = (int)((blockSize - 8) / 2);
        //    Console.WriteLine($"Page RVA: 0x{pageRVA:X8}, Block Size: {blockSize}, Entry count: {entryCount}");

        //    for (int i = 0; i < entryCount; i++) {
        //        ushort entry = BitConverter.ToUInt16(relocBytes, offset + 8 + i * 2);
        //        int type = entry >> 12;
        //        int relocOffset = entry & 0xFFF;

        //        Console.WriteLine($"  Entry[{i}]: Type={type}, Offset=0x{relocOffset:X4}");
        //    }

        //    offset += (int)blockSize;
        //}


        //// Print Machine type
        //Console.WriteLine($"Machine enum: 0x{(ushort)headers.CoffHeader.Machine:X}");

        //// Print PE header info
        //var coffHeader = headers.CoffHeader;
        //Console.WriteLine($"COFF Header NumberOfSections: {coffHeader.NumberOfSections}");
        //Console.WriteLine($"COFF Header TimeDateStamp: {DateTimeOffset.FromUnixTimeSeconds(coffHeader.TimeDateStamp)}");

        //// Optional: Print optional header info (if present)
        //var optionalHeader = headers.PEHeader;
        //if (optionalHeader != null) {
        //    Console.WriteLine($"Optional Header Magic: 0x{(uint)optionalHeader.Magic:X4}");
        //    Console.WriteLine($"AddressOfEntryPoint: 0x{optionalHeader.AddressOfEntryPoint:X8}");
        //    Console.WriteLine($"ImageBase: 0x{optionalHeader.ImageBase:X8}");
        //    Console.WriteLine($"Subsystem: {optionalHeader.Subsystem}");
        //}

        ////byte[] groundTruthData = File.ReadAllBytes(groundTruth);

        //// Print section headers
        //Console.WriteLine("\nSections:");
        //foreach (var section in headers.SectionHeaders) {
        //    Console.WriteLine($"Name: {section.Name}");
        //    Console.WriteLine($"  VirtualSize: 0x{section.VirtualSize:X8}");
        //    Console.WriteLine($"  VirtualAddress: 0x{section.VirtualAddress:X8}");
        //    Console.WriteLine($"  SizeOfRawData: 0x{section.SizeOfRawData:X8}");
        //    Console.WriteLine($"  PointerToRawData: 0x{section.PointerToRawData:X8}");
        //    Console.WriteLine($"  Characteristics: {section.SectionCharacteristics}");
        //    Console.WriteLine();
        //}

        //File.WriteAllBytes("D:\\DC3 Debug\\Gamepad\\Debug\\jeff_adjusted.exe", peAdjusted.ToArray());
    }
}