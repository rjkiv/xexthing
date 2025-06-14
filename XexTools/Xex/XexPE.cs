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
        public uint addressStart;
        public uint addressEnd;

        public Function(string name, bool analyzed, uint addressStart, uint addressEnd) {
            this.name = name;
            this.analyzed = analyzed;
            this.addressStart = addressStart;
            this.addressEnd = addressEnd;
        }

        // note: addr should already be calculated (i.e. not a raw byte offset)
        public bool CheckBounds(uint addr) {
            return addr >= addressStart && addr < addressEnd;
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

        for (int i = 0; i < headers.SectionHeaders.Length; i++) {
            var section = headers.SectionHeaders[i];
            peSections.Add(section);
            if(section.Name == ".text") {
                textSectionIndex = (uint)i;
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

    private void AddFunction(Function func) {
        // make sure a function with the raw byte start idx isn't already in here
        int index = functionBoundaries.BinarySearch(func, Comparer<Function>.Create((x, y) => x.addressStart.CompareTo(y.addressStart)));

        if (index >= 0) return;
        // if there's no such function, insert it according to the raw byte start address
        // insert it in a sorted manner now so we don't have to keep re-sorting as we add batches of functions
        index = ~index;
        functionBoundaries.Insert(index, func);
    }

    private Function GetFunction(uint addr) {
        return functionBoundaries.Find(x => addr >= x.addressStart && addr < x.addressEnd);
    }

    private Function GetFunction(string name) {
        return functionBoundaries.Find(x => x.name == name);
    }

    private SectionHeader CalcSectionFromRawByteOffset(uint offset) {
        foreach(var section in peSections) {
            if(offset >= section.PointerToRawData && offset < section.PointerToRawData + section.SizeOfRawData) {
                return section;
            }
        }
        throw new Exception($"Raw byte offset 0x{offset:X} is not part of the exe!");
    }

    private uint CalcAddrFromRawByteOffset(uint offset) {
        SectionHeader section = CalcSectionFromRawByteOffset(offset);
        // offset is like, raw byte offset of the whole exe, not just the section
        return offset - (uint)section.PointerToRawData + imageBase + (uint)section.VirtualAddress;
    }

    // for both b and bl, AA is 0, so the << 2 op stays the same
    private uint CalculateBranchTarget(uint pc, uint instr) {
        // BL layout:
        // bits value
        // 0 - 5     18
        // 6 - 29    LI
        // 30      AA(0)
        // 31      LK(1)
        int li = (int)((instr >> 2) & 0x00FFFFFF);
        if ((li & 0x00800000) != 0) // if the 24th bit is set (sign bit)
        {
            li |= unchecked((int)0xFF000000); // sign-extend to 32 bits
        }
        int offset = unchecked(li << 2);
        //Console.WriteLine($"PC: 0x{CalcAddrFromRawByteOffset(pc):X}, offset 0x{offset:X}, target: 0x{CalcAddrFromRawByteOffset((uint)(pc + offset)):X}");
        return CalcAddrFromRawByteOffset((uint)(pc + offset));
    }

    private bool IsOffsetPartOfKnownFunc(uint offset) {
        uint addr = CalcAddrFromRawByteOffset(offset);
        foreach(var func in functionBoundaries) {
            if(func.CheckBounds(addr)) return true;
        }
        return false;
    }

    private void FindSaveAndRestoreRegisterFuncs() {
        // the asm corresponding to savegprlrs 14-17 and savefprs 14-17
        // stands to reason that if we find these in sequence, 18-31 will be right behind
        byte[] saveGPRasm = { 0xf9, 0xc1, 0xff, 0x68, 0xf9, 0xe1, 0xff, 0x70, 0xfa, 0x01, 0xff, 0x78, 0xfa, 0x21, 0xff, 0x80 };
        byte[] saveFPRasm = { 0xd9, 0xcc, 0xff, 0x70, 0xd9, 0xec, 0xff, 0x78, 0xda, 0x0c, 0xff, 0x80, 0xda, 0x2c, 0xff, 0x88 };

        int theSaveGPRIdx = -1;

        SectionHeader section = peSections[(int)textSectionIndex];

        for(int i = section.VirtualAddress; i < (section.VirtualAddress + section.SizeOfRawData) - saveGPRasm.Length; i++) {
            if (exeBytes.Skip(i).Take(saveGPRasm.Length).SequenceEqual(saveGPRasm)) {
                theSaveGPRIdx = i;
                break;
            }
        }

        if(theSaveGPRIdx == -1) {
            throw new Exception("Save gpr compiler intrinsics not found. Is that even possible for an xex?");
        }

        for(int i = 14; i <= 31; i++, theSaveGPRIdx += 4) {
            Function saveFunc = new Function($"__savegprlr_{i}", true,
                CalcAddrFromRawByteOffset((uint)theSaveGPRIdx), CalcAddrFromRawByteOffset((uint)theSaveGPRIdx + 4));
            Function restoreFunc = new Function($"__restgprlr_{i}", true,
                CalcAddrFromRawByteOffset((uint)theSaveGPRIdx + 0x50), CalcAddrFromRawByteOffset((uint)theSaveGPRIdx + 0x54));
            AddFunction(saveFunc);
            AddFunction(restoreFunc);
        }

        int theSaveFPRIdx = -1;

        for (int i = section.VirtualAddress; i < (section.VirtualAddress + section.SizeOfRawData) - saveGPRasm.Length; i++) {
            if (exeBytes.Skip(i).Take(saveGPRasm.Length).SequenceEqual(saveFPRasm)) {
                theSaveFPRIdx = i;
                break;
            }
        }

        if (theSaveFPRIdx == -1) {
            throw new Exception("Save fpr compiler intrinsics not found. Is that even possible for an xex?");
        }

        for (int i = 14; i <= 31; i++, theSaveFPRIdx += 4) {
            Function saveFunc = new Function($"__savefpr_{i}", true, 
                CalcAddrFromRawByteOffset((uint)theSaveFPRIdx), CalcAddrFromRawByteOffset((uint)theSaveFPRIdx + 4));
            Function restoreFunc = new Function($"__restfpr_{i}", true, 
                CalcAddrFromRawByteOffset((uint)theSaveFPRIdx + 0x4C), CalcAddrFromRawByteOffset((uint)theSaveFPRIdx + 0x50));
            AddFunction(saveFunc);
            AddFunction(restoreFunc);
        }
    }

    private bool AddrIsText(uint addr) {
        SectionHeader textSection = peSections[(int)textSectionIndex];
        uint textBegin = (uint)textSection.VirtualAddress + imageBase;
        uint textEnd = textBegin + (uint)textSection.VirtualSize;
        return addr >= textBegin && addr < textEnd;
    }

    private List<uint> SweepForKnownFuncStartAddrs() {
        HashSet<uint> knownAddrs = new();
        SectionHeader textSection = peSections[(int)textSectionIndex];
        uint textBegin = (uint)textSection.VirtualAddress + imageBase;
        uint textEnd = textBegin + (uint)textSection.VirtualSize;

        BEBinaryReader br = new BEBinaryReader(new MemoryStream(exeBytes));
        br.BaseStream.Seek(textSection.PointerToRawData, SeekOrigin.Begin);

        while(br.BaseStream.Position < textSection.PointerToRawData + textSection.SizeOfRawData) {
            var curPos = br.BaseStream.Position;
            uint curInst = br.ReadUInt32();
            // if this is a bl, note down the branch target
            if (PPCHelper.IsBL(curInst)) {
                uint branchTarget = CalculateBranchTarget((uint)curPos, curInst);
                if(branchTarget >= textBegin && branchTarget < textEnd && knownAddrs.Add(branchTarget)) {
                    //Console.WriteLine($"Added new func start: 0x{branchTarget:X}");
                }
            }
            // else, if this is subi r31, r12, XXXX
            else if((curInst & 0xFC1F8000) == 0x3F8C000) {
                var subiPos = br.BaseStream.Position;
                uint mfsprCheck = br.ReadUInt32();
                // and if the next instr is mfspr r12, LR
                if(mfsprCheck == 0x7D8802A6) {
                    if(knownAddrs.Add(CalcAddrFromRawByteOffset((uint)curPos))) {
                        //Console.WriteLine($"Added new func start: 0x{CalcAddrFromRawByteOffset((uint)curPos):X}");
                    }
                }
                else {
                    // this wasn't an unwind prologue, takesies backsies on the stream position then
                    br.BaseStream.Seek(subiPos, SeekOrigin.Begin);
                }
            }
            // else if this is mfspr r12, LR
            else if(curInst == 0x7D8802A6) {
                if (knownAddrs.Add(CalcAddrFromRawByteOffset((uint)curPos))) {
                    //Console.WriteLine($"Added new func start: 0x{CalcAddrFromRawByteOffset((uint)curPos):X}");
                }
            }
        }

        List<uint> sortedAddrs = knownAddrs.ToList();
        sortedAddrs.Sort();
        return sortedAddrs;
    }

    private uint NextKnownStartAddr(uint addr) {
        SectionHeader textSection = peSections[(int)textSectionIndex];
        uint textBegin = (uint)textSection.VirtualAddress + imageBase;
        uint textEnd = textBegin + (uint)textSection.VirtualSize;
        foreach(var knownAddr in knownStartAddrs) {
            if (knownAddr > addr) return knownAddr;
        }
        return textEnd;
    }

    public void FindFunctionBoundaries() {
        // initial sweep to find and label the save/restore reg funcs
        FindSaveAndRestoreRegisterFuncs();
        // do a sweep to find known start addresses from
        // 1. bl targets
        // 2. any funcs that start with stwu/mfspr, or just mfspr
        knownStartAddrs = SweepForKnownFuncStartAddrs();

        BEBinaryReader br = new BEBinaryReader(new MemoryStream(exeBytes));
        SectionHeader textSection = peSections[(int)textSectionIndex];
        br.BaseStream.Seek(textSection.PointerToRawData, SeekOrigin.Begin);
        while(br.BaseStream.Position < textSection.PointerToRawData + textSection.SizeOfRawData) {
            var curPos = br.BaseStream.Position;
            uint curAddr = CalcAddrFromRawByteOffset((uint)curPos);
            Console.WriteLine($"Current PC: 0x{curAddr:X}");
            Console.WriteLine($"The func is from 0x{curAddr:X} til up to 0x{NextKnownStartAddr(curAddr):X}");
            // TODO: CFA the func that starts at curAddr
        }


        //foreach(var addr in knownStartAddrs) {
        //    Console.WriteLine($"Func start addr: 0x{addr:X}");
        //}

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
    public uint textSectionIndex;
    public List<uint> knownStartAddrs = new();
    public List<SectionHeader> peSections = new();
    public List<Function> functionBoundaries = new();
}