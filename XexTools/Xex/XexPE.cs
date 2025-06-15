using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Reflection.PortableExecutable;
using System.Diagnostics;
using System.IO;

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

        public bool IsGPRIntrinsic() {
            return name.Contains("__savegprlr") || name.Contains("__restgprlr");
        }

        public bool IsFPRIntrinsic() {
            return name.Contains("__savefpr") || name.Contains("__restfpr");
        }

        public bool IsVMXIntrinsic() {
            return name.Contains("__savevmx") || name.Contains("__restvmx");
        }

        public bool IsRegIntrinsic() {
            return IsGPRIntrinsic() || IsFPRIntrinsic() || IsVMXIntrinsic();
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
    // for bc and bcl
    private uint CalculateConditionalBranchTarget(uint pc, uint instr) {
        short bd = (short)((instr >> 2) & 0x3FFF);
        if((bd & 0x2000) != 0) {
            bd |= unchecked((short)0xE000);
        }
        bd = unchecked((short)(bd << 2));
        return CalcAddrFromRawByteOffset((uint)(pc + bd));
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

        // TODO: find and mark vmx save/restore funcs
        // the asm corresponding to savevmx's 14-17
        // stands to reason that if we find these in sequence, the others will be right behind
        byte[] saveVMXasm = { 0x39, 0x60, 0xfe, 0xe0, 0x7d, 0xcb, 0x61, 0xce, 0x39, 0x60, 0xfe, 0xf0, 0x7d, 0xeb, 0x61, 0xce,
                              0x39, 0x60, 0xff, 0x00, 0x7e, 0x0b, 0x61, 0xce, 0x39, 0x60, 0xff, 0x10, 0x7e, 0x2b, 0x61, 0xce};

        int theSaveVMXIdx = -1;

        for (int i = section.VirtualAddress; i < (section.VirtualAddress + section.SizeOfRawData) - saveVMXasm.Length; i++) {
            if (exeBytes.Skip(i).Take(saveVMXasm.Length).SequenceEqual(saveVMXasm)) {
                theSaveVMXIdx = i;
                break;
            }
        }

        if (theSaveVMXIdx == -1) {
            throw new Exception("Save vmx compiler intrinsics not found. Is that even possible for an xex?");
        }

        // the order goes: save 14-31, then 64-127, with each func taking up 8 bytes
        for(int i = 14; i <= 31; i++, theSaveVMXIdx += 8) {
            //Console.WriteLine($"Found __savevmx_{i} at 0x{CalcAddrFromRawByteOffset((uint)theSaveVMXIdx):X}");
            Function saveFunc = new Function($"__savevmx_{i}", true,
                CalcAddrFromRawByteOffset((uint)theSaveVMXIdx), CalcAddrFromRawByteOffset((uint)theSaveVMXIdx + 8));
            AddFunction(saveFunc);
        }
        theSaveVMXIdx += 4;
        for (int i = 64; i <= 127; i++, theSaveVMXIdx += 8) {
            //Console.WriteLine($"Found __savevmx_{i} at 0x{CalcAddrFromRawByteOffset((uint)theSaveVMXIdx):X}");
            Function saveFunc = new Function($"__savevmx_{i}", true,
                CalcAddrFromRawByteOffset((uint)theSaveVMXIdx), CalcAddrFromRawByteOffset((uint)theSaveVMXIdx + 8));
            AddFunction(saveFunc);
        }
        theSaveVMXIdx += 4;
        for (int i = 14; i <= 31; i++, theSaveVMXIdx += 8) {
            //Console.WriteLine($"Found __restvmx_{i} at 0x{CalcAddrFromRawByteOffset((uint)theSaveVMXIdx):X}");
            Function restoreFunc = new Function($"__restvmx_{i}", true,
                CalcAddrFromRawByteOffset((uint)theSaveVMXIdx), CalcAddrFromRawByteOffset((uint)theSaveVMXIdx + 8));
            AddFunction(restoreFunc);
        }
        theSaveVMXIdx += 4;
        for (int i = 64; i <= 127; i++, theSaveVMXIdx += 8) {
            //Console.WriteLine($"Found __restvmx_{i} at 0x{CalcAddrFromRawByteOffset((uint)theSaveVMXIdx):X}");
            Function restoreFunc = new Function($"__restvmx_{i}", true,
                CalcAddrFromRawByteOffset((uint)theSaveVMXIdx), CalcAddrFromRawByteOffset((uint)theSaveVMXIdx + 8));
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
                uint mfsprCheck = br.PeekUInt32();
                // and if the next instr is mfspr r12, LR
                if(mfsprCheck == 0x7D8802A6) {
                    if(knownAddrs.Add(CalcAddrFromRawByteOffset((uint)curPos))) {
                        //Console.WriteLine($"Added new func start: 0x{CalcAddrFromRawByteOffset((uint)curPos):X}");
                    }
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

    private uint FindFunctionEnd(BEBinaryReader br, uint startAddr, uint maxAddr) {
        var worklist = new Queue<uint>();
        var visited = new HashSet<uint>();
        uint highestAddr = startAddr;
        SectionHeader textSection = peSections[(int)textSectionIndex];
        uint textSectionBegin = (uint)textSection.VirtualAddress + imageBase;
        uint textSectionEnd = textSectionBegin + (uint)textSection.SizeOfRawData;
        var originalPos = br.BaseStream.Position; // the position in the BR corresponding to the start of the func

        worklist.Enqueue(startAddr);

        while(worklist.Count > 0) {
            uint addr = worklist.Dequeue();

            if(visited.Contains(addr) || addr >= maxAddr || addr < textSectionBegin)
                continue;

            visited.Add(addr);
            if (addr > highestAddr)
                highestAddr = addr;

            int offset = textSection.PointerToRawData + (int)(addr - textSectionBegin);
            if (offset + 4 > textSectionEnd) continue;

            br.BaseStream.Seek(offset, SeekOrigin.Begin);
            uint instr = br.PeekUInt32();

            // if we somehow managed to have a 0 slip through the cracks, stop, this is the end
            if (instr == 0) {
                highestAddr -= 4;
                break;
            }

            // if blr
            if (PPCHelper.IsBLR(instr)) continue;

            // if unconditional branch (b or bl)
            if(PPCHelper.IsBranch(instr) || PPCHelper.IsBL(instr)) {
                uint target = CalculateBranchTarget((uint)offset, instr);
                // if the target is within the bounds of (startAddr, maxAddr), add it to our analysis queue
                if(target >= textSectionBegin && target > startAddr && target < maxAddr) {
                    worklist.Enqueue(target);
                }
                else {
                    // else, if this is a b, this *might* be a tail call
                    // TODO: handle additional logic to determine if this b is a tail call or not
                    if (PPCHelper.IsBranch(instr)) {

                        br.BaseStream.Seek(4, SeekOrigin.Current);
                        uint nextInst = br.PeekUInt32();
                        // if the next instruction over is all 0's, this is definitely a tail call
                        if (nextInst == 0) {
                            break;
                        }
                        // if the next instruction over's addr == maxAddr, tail call
                        else if(addr + 4 == maxAddr) {
                            break;
                        }
                        // if the next instruction over's addr < highestAddr + 4, it's NOT a tail call
                        // use addr + 4 for this
                        else if (addr + 4 < highestAddr + 4) {
                            // NOT a tail call, don't do anything
                        }
                        // if addr + 4 == highestAddr + 4 AND highestAddr + 4 is in the workList, don't mark it as a tail call, because we don't know for sure
                        // explorer that inst first instead of coming to a concrete conclusion
                        else if((addr + 4 == highestAddr + 4) && worklist.Contains(addr + 4)) {
                            // we don't know for sure, so don't do anything
                        }
                        // if the target is part of a known, non-reg intrinsic function, tail call
                        else if(GetFunction(target) != null && !GetFunction(target).IsRegIntrinsic()) {
                            break;
                        }
                        // if the target is NOT part of a known function
                        else if (GetFunction(target) == null) {
                            // if the b target is past the known start addr of this func, definitely a tail call
                            if (target < startAddr) {
                                break;
                            }
                            // if the b target is at or past the known start addr of a later func, definitely a tail call
                            if (target >= maxAddr) {
                                break;
                            }
                        }
                        else {
                            //Console.WriteLine($"Branch at 0x{addr:X} might be a tail call!");
                        }
                    }
                }

                if (PPCHelper.IsBL(instr)) {
                    worklist.Enqueue(addr + 4);
                }
                continue;
            }

            // if conditional branch (bc or bcl)
            // TODO: add extra logic to check for bgt's to jump tables
            if(PPCHelper.IsConditionalBranch(instr)) {
                uint target = CalculateConditionalBranchTarget((uint)offset, instr);
                if (target >= textSectionBegin && target > startAddr && target < maxAddr)
                    worklist.Enqueue(target);

                worklist.Enqueue(addr + 4); // fallthrough path
                continue;
            }

            // this current inst ain't nothin special, just go ahead and add the next addr over
            worklist.Enqueue(addr + 4);
        }

        //Console.WriteLine($"Func that starts at 0x{startAddr:X}, ends at 0x{highestAddr + 4:X}");
        // now that we know where the end is, move the reader ahead up to that point
        br.BaseStream.Seek(originalPos + (highestAddr + 4 - startAddr), SeekOrigin.Begin);
        return highestAddr + 4;
    }

    private void DumpFuncs() {
        string funcsDump = "";
        foreach (var func in functionBoundaries) {
            funcsDump += $"{func.name}: 0x{func.addressStart:X} - 0x{func.addressEnd:X}\n";
        }
        File.WriteAllText("D:\\DC3 Debug\\Gamepad\\Debug\\jeff_funcs_cfa.txt", funcsDump);
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
            // note current PC and virtual addr
            var curPos = br.BaseStream.Position;
            uint curAddr = CalcAddrFromRawByteOffset((uint)curPos);

            // ignore zero-padding
            if (br.PeekUInt32() == 0) {
                br.BaseStream.Seek(4, SeekOrigin.Current);
                continue;
            }
            // ignore the save/restore reg funcs we found earlier
            else if (GetFunction(curAddr) != null) {
                Function func = GetFunction(curAddr);
                if(func.IsGPRIntrinsic()) {
                    Function lastRestoreFunc = GetFunction("__restgprlr_31");
                    br.BaseStream.Seek(lastRestoreFunc.addressEnd - curAddr, SeekOrigin.Current);
                    continue;
                }
                else if(func.IsFPRIntrinsic()) {
                    Function lastRestoreFunc = GetFunction("__restfpr_31");
                    br.BaseStream.Seek(lastRestoreFunc.addressEnd - curAddr, SeekOrigin.Current);
                    continue;
                }
                else if (func.IsVMXIntrinsic()) {
                    Function lastRestoreFunc = GetFunction("__restvmx_127");
                    br.BaseStream.Seek(lastRestoreFunc.addressEnd - curAddr, SeekOrigin.Current);
                    continue;
                }
            }
            //// ignore random branches to xidata (or should we be ignoring these?)
            //else {
            //    var maybeBranchPC = br.BaseStream.Position;
            //    uint maybeBranchInstr = br.PeekUInt32();
            //    if(PPCHelper.IsBranch(maybeBranchInstr)) {
            //        uint target = CalculateBranchTarget((uint)maybeBranchPC, maybeBranchInstr);
            //        if (!AddrIsText(target)) {
            //            br.BaseStream.Seek(4, SeekOrigin.Current);
            //            continue;
            //        }
            //    }
            //}

            uint nextKnownStartAddr = NextKnownStartAddr(curAddr);
            //Console.WriteLine($"The func is from 0x{curAddr:X} til up to 0x{nextKnownStartAddr:X}");
            uint funcEnd = FindFunctionEnd(br, curAddr, nextKnownStartAddr);
            AddFunction(new Function($"fn_{curAddr:X}", true, curAddr, funcEnd));
        }

        Console.WriteLine($"Found {functionBoundaries.Count} functions");
        DumpFuncs();
        // need to resolve jump tables
    }

    // debug only: just to check that at the very minimum, we found the function boundaries that the map knows of
    public void VerifyAgainstMap(XexMap xexMap) {
        foreach(var entry in xexMap.entries) {
            if (AddrIsText(entry.vaddr)) {
                Function func = GetFunction(entry.vaddr);
                if(func != null && func.addressStart == entry.vaddr) {
                    // all good!
                }
                else {
                    Console.WriteLine($"WARNING: could not find function at 0x{entry.vaddr:X}");
                }
            }
        }
    }

    public byte[] exeBytes;
    public uint entryPointAddress;
    public uint imageBase;
    public uint textSectionIndex;
    public List<uint> knownStartAddrs = new();
    public List<SectionHeader> peSections = new();
    public List<Function> functionBoundaries = new();
}