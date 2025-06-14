using System;
using System.Diagnostics;
using System.IO;
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

        //PEReader pr = new PEReader(new MemoryStream(File.ReadAllBytes(groundTruth)));
        //var textSection = pr.GetSectionData(".text");
        //Console.WriteLine(textSection);
        //var reader = textSection.GetReader();
        //Console.WriteLine(reader.ReadUInt32());

        // 1. read in the xex, and get the resulting exe
        BEBinaryReader br = new BEBinaryReader(new MemoryStream(fileData));
        Xex xex = new Xex();
        xex.Read(br);

        // 2. take the exe, and reformat it around the "virtual address" hacks
        XexPE xexPE = new XexPE();
        xexPE.ImportExeFromXex(xex.xexHeader.peImage);

        // 3. Control Flow Analysis
        xexPE.FindFunctionBoundaries();

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