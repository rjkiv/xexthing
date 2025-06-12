using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Reflection.PortableExecutable;
using System.Diagnostics;

class XexPE {
    public class Function {
        public string name;
        public bool analyzed;
        public uint rawByteArrayStart;
        public uint rawByteArrayEnd;
        // TODO: how do you calculate these?
        public uint addressStart;
        public uint addressEnd;

        public Function() { }

        public Function(string name, bool analyzed, uint rawByteArrayStart, uint rawByteArrayEnd, uint addressStart, uint addressEnd) {
            this.name = name;
            this.analyzed = analyzed;
            this.rawByteArrayStart = rawByteArrayStart;
            this.rawByteArrayEnd = rawByteArrayEnd;
            this.addressStart = addressStart;
            this.addressEnd = addressEnd;
        }
    }

    public void ImportExeFromXex(byte[] xexPEImage) {
        PEReader pr = new PEReader(new MemoryStream(xexPEImage));
        var headers = pr.PEHeaders;

        var optionalHeader = headers.PEHeader;
        if(optionalHeader != null) {
            Console.WriteLine($"AddressOfEntryPoint: 0x{optionalHeader.AddressOfEntryPoint:X8}");
            Console.WriteLine($"ImageBase: 0x{optionalHeader.ImageBase:X8}");
            entryPointAddress = (uint)optionalHeader.AddressOfEntryPoint;
            imageBase = (uint)optionalHeader.ImageBase;
        }
        else {
            throw new Exception("No optional header found. Is that even possible for an xex?");
        }

        List<byte> peAdjusted = new();

        for(int i = 0; i < headers.SectionHeaders[0].VirtualAddress; i++) {
            peAdjusted.Add(xexPEImage[i]);
        }

        for(int i = 0; i < headers.SectionHeaders.Length; i++) {
            var section = headers.SectionHeaders[i];
            if(section.Name == ".text") {
                textSectionStart = (uint)section.PointerToRawData;
                textSectionEnd = textSectionStart + (uint)section.SizeOfRawData;
            }
            Debug.Assert(peAdjusted.Count == section.PointerToRawData, "Unexpected PE size at this point!");
            List<byte> sectionBytes = new();
            for (int j = 0; j < section.SizeOfRawData; j++) {
                if (j + section.VirtualAddress >= xexPEImage.Length) {
                    sectionBytes.Add(0);
                }
                else sectionBytes.Add(xexPEImage[j + section.VirtualAddress]);
            }
            peAdjusted.AddRange(sectionBytes);
        }

        exeBytes = peAdjusted.ToArray();
    }

    private void FindSaveAndRestoreRegisterFuncs() {
        // the asm corresponding to savegprlrs 14-17 and savefprs 14-17
        // stands to reason that if we find these in sequence, 18-31 will be right behind
        byte[] saveGPRasm = { 0xf9, 0xc1, 0xff, 0x68, 0xf9, 0xe1, 0xff, 0x70, 0xfa, 0x01, 0xff, 0x78, 0xfa, 0x21, 0xff, 0x80 };
        byte[] saveFPRasm = { 0xd9, 0xcc, 0xff, 0x70, 0xd9, 0xec, 0xff, 0x78, 0xda, 0x0c, 0xff, 0x80, 0xda, 0x2c, 0xff, 0x88 };

        int theSaveGPRIdx = -1;

        for(int i = (int)textSectionStart; i < textSectionEnd - saveGPRasm.Length; i++) {
            if (exeBytes.Skip(i).Take(saveGPRasm.Length).SequenceEqual(saveGPRasm)) {
                //Console.WriteLine($"Found the savegpr funcs! They're at i = 0x{i:X}");
                // evil hack: if we find the saveGPR sequence multiple times, take the last instance
                theSaveGPRIdx = i;
            }
        }

        if(theSaveGPRIdx == -1) {
            throw new Exception("Save gpr compiler intrinsics not found. Is that even possible for an xex?");
        }

        for(int i = 14; i <= 31; i++, theSaveGPRIdx += 4) {
            Function saveFunc = new Function($"__savegprlr_{i}", true, (uint)theSaveGPRIdx, (uint)theSaveGPRIdx + 4, 0, 0);
            Function restoreFunc = new Function($"__restgprlr_{i}", true, (uint)theSaveGPRIdx + 0x48, (uint)theSaveGPRIdx + 0x4C, 0, 0);
            functionBoundaries.Add(saveFunc);
            functionBoundaries.Add(restoreFunc);
        }

        int theSaveFPRIdx = -1;

        for (int i = (int)textSectionStart; i < textSectionEnd - saveFPRasm.Length; i++) {
            if (exeBytes.Skip(i).Take(saveGPRasm.Length).SequenceEqual(saveFPRasm)) {
                //Console.WriteLine($"Found the savefpr funcs! They're at i = 0x{i:X}");
                // evil hack: if we find the saveFPR sequence multiple times, take the last instance
                theSaveFPRIdx = i;
            }
        }

        if (theSaveFPRIdx == -1) {
            throw new Exception("Save fpr compiler intrinsics not found. Is that even possible for an xex?");
        }

        for (int i = 14; i <= 31; i++, theSaveFPRIdx += 4) {
            Function saveFunc = new Function($"__savefpr_{i}", true, (uint)theSaveFPRIdx, (uint)theSaveFPRIdx + 4, 0, 0);
            Function restoreFunc = new Function($"__restfpr_{i}", true, (uint)theSaveFPRIdx + 0x48, (uint)theSaveFPRIdx + 0x4C, 0, 0);
            functionBoundaries.Add(saveFunc);
            functionBoundaries.Add(restoreFunc);
        }
    }

    public void FindFunctionBoundaries() {
        // initial sweep to find and label the save/restore reg funcs
        FindSaveAndRestoreRegisterFuncs();
        BEBinaryReader br = new BEBinaryReader(new MemoryStream(exeBytes));
        br.BaseStream.Seek(textSectionStart, SeekOrigin.Begin);

        functionBoundaries.Sort((a, b) => a.rawByteArrayStart.CompareTo(b.rawByteArrayStart));
        foreach (var func in functionBoundaries) {
            Console.WriteLine($"Found {func.name} at byte offset 0x{func.rawByteArrayStart:X}");
        }

        // find function prologues to get known start addresses

        // blr: 4e 80 00 20

        //      -name: b
        //  pattern: 0x48000000

        //- name: bc
        //  pattern: 0x40000000

        //- name: bcctr
        //  pattern: 0x4c000420

        //- name: bclr
        //  pattern: 0x4c000020

        // this is where you try to find function boundaries

        // so when you just have a giant.text section with a bunch of instructions, the most important thing is to determine function boundaries
        // so CFA in this case means following the instructions control flow(branches, etc)
        // with mwcc we know any bl target is the start of another function
        // so we follow the control flow of a function until every path ends in a return (or, sometimes, a tail call)
        // tail calls make things hard because they're just a b like you'd get with inner-function jumps, but they're actually pointing to a different fn
        // dunno if you'll have to deal with tail call optimization with msvc 

        // recursively going through and noting down every bl target
        //the other part is following inner - function branches / jumps to find the end of the function
        //and also resolving jump tables
    }

    public byte[] exeBytes;
    public uint entryPointAddress;
    public uint imageBase;
    public uint textSectionStart;
    public uint textSectionEnd;
    public List<Function> functionBoundaries = new();
}