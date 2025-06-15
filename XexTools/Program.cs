using System;
using System.Diagnostics;
using System.IO;
using System.Reflection.PortableExecutable;

class Program {
    static void Main(string[] args) {
        // we are now assuming you pass in a directory that contains an xex, (optional) exe, (optional) map
        if (args.Length < 1 || !Directory.Exists(args[0])) {
            Console.WriteLine("need a directory");
            return;
        }

        string xexFile = "";
        string exeFile = "";
        string mapFile = "";

        string[] files = Directory.GetFiles(args[0]);
        // assuming you only have one of each file type
        foreach(string file in files) {
            if (file.EndsWith(".xex")) xexFile = file;
            else if (file.EndsWith(".exe")) exeFile = file;
            else if(file.EndsWith(".map")) mapFile = file;
        }

        Console.WriteLine("Xex: " + xexFile);
        Console.WriteLine("Exe: " + exeFile);
        Console.WriteLine("Map: " + mapFile);
        byte[] fileData = File.ReadAllBytes(xexFile);

        //PEReader pr = new PEReader(new MemoryStream(File.ReadAllBytes(groundTruth)));
        //var textSection = pr.GetSectionData(".text");
        //Console.WriteLine(textSection);
        //var reader = textSection.GetReader();
        //Console.WriteLine(reader.ReadUInt32());
        XexMap xexMap = new XexMap(mapFile);

        // 1. read in the xex, and get the resulting exe
        BEBinaryReader br = new BEBinaryReader(new MemoryStream(fileData));
        Xex xex = new Xex();
        xex.Read(br);

        // 2. take the exe, and reformat it around the "virtual address" hacks
        XexPE xexPE = new XexPE();
        xexPE.ImportExeFromXex(xex.xexHeader.peImage);

        // 3. Control Flow Analysis
        xexPE.FindFunctionBoundaries();
        xexPE.VerifyAgainstMap(xexMap);

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

        //File.WriteAllBytes("D:\\DC3 Debug\\Gamepad\\Debug\\jeff_adjusted.exe", xexPE.exeBytes);
    }
}