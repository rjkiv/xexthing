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

        BEBinaryReader br = new BEBinaryReader(new MemoryStream(fileData));
        Xex xex = new Xex();
        xex.Read(br);

        PEReader pr = new PEReader(new MemoryStream(xex.xexHeader.peImage));

        var headers = pr.PEHeaders;

        List<byte> peAdjusted = new();

        // duplicate the bytes up til the first section's PointerToRawData
        for (int i = 0; i < headers.SectionHeaders[0].VirtualAddress; i++) {
            peAdjusted.Add(xex.xexHeader.peImage[i]);
        }
        Console.WriteLine($"Bytes 0 through 0x{headers.SectionHeaders[0].VirtualAddress:X} have been duplicated!");

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

        // Print Machine type
        Console.WriteLine($"Machine enum: 0x{(ushort)headers.CoffHeader.Machine:X}");

        // Print PE header info
        var coffHeader = headers.CoffHeader;
        Console.WriteLine($"COFF Header NumberOfSections: {coffHeader.NumberOfSections}");
        Console.WriteLine($"COFF Header TimeDateStamp: {DateTimeOffset.FromUnixTimeSeconds(coffHeader.TimeDateStamp)}");

        // Optional: Print optional header info (if present)
        var optionalHeader = headers.PEHeader;
        if (optionalHeader != null) {
            Console.WriteLine($"Optional Header Magic: 0x{(uint)optionalHeader.Magic:X4}");
            Console.WriteLine($"AddressOfEntryPoint: 0x{optionalHeader.AddressOfEntryPoint:X8}");
            Console.WriteLine($"ImageBase: 0x{optionalHeader.ImageBase:X8}");
            Console.WriteLine($"Subsystem: {optionalHeader.Subsystem}");
        }

        //byte[] groundTruthData = File.ReadAllBytes(groundTruth);

        // Print section headers
        Console.WriteLine("\nSections:");
        foreach (var section in headers.SectionHeaders) {
            Console.WriteLine($"Name: {section.Name}");
            Console.WriteLine($"  VirtualSize: 0x{section.VirtualSize:X8}");
            Console.WriteLine($"  VirtualAddress: 0x{section.VirtualAddress:X8}");
            Console.WriteLine($"  SizeOfRawData: 0x{section.SizeOfRawData:X8}");
            Console.WriteLine($"  PointerToRawData: 0x{section.PointerToRawData:X8}");
            Console.WriteLine($"  Characteristics: {section.SectionCharacteristics}");
            Console.WriteLine();
        }

        File.WriteAllBytes("D:\\DC3 Debug\\Gamepad\\Debug\\jeff_adjusted.exe", peAdjusted.ToArray());
    }
}