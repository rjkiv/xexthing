using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Reflection.PortableExecutable;
using System.Diagnostics;
using System.IO;
using Gee.External.Capstone;
using System.Net.WebSockets;

class XexPE {
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

        pDataSectionIndex = -1;
        for (int i = 0; i < headers.SectionHeaders.Length; i++) {
            var section = headers.SectionHeaders[i];
            peSections.Add(section);
            if(section.Name == ".text") {
                textSectionIndex = i;
            }
            else if(section.Name == ".pdata") {
                pDataSectionIndex = i;
            }
            // if this is bss, don't add any extra bytes
            if (section.SectionCharacteristics.HasFlag(SectionCharacteristics.ContainsUninitializedData)) {
                continue;
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

    private Function? GetFunctionFromBounds(uint addr) {
        foreach (var f in functionBoundaries)
            if (addr >= f.addressStart && addr < f.addressEnd)
                return f;
        return null;
    }

    private Function? GetFunctionFromStartAddr(uint addr) {
        foreach (var f in functionBoundaries)
            if (f.addressStart == addr)
                return f;
        return null;
    }

    private Function? GetFunctionFromName(string name) {
        foreach (var f in functionBoundaries)
            if (f.name == name)
                return f;
        return null;
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

    //private bool IsOffsetPartOfKnownFunc(uint offset) {
    //    uint addr = CalcAddrFromRawByteOffset(offset);
    //    foreach(var func in functionBoundaries) {
    //        if(func.CheckBounds(addr)) return true;
    //    }
    //    return false;
    //}

    private bool AddrIsText(uint addr) {
        SectionHeader textSection = peSections[textSectionIndex];
        uint textBegin = (uint)textSection.VirtualAddress + imageBase;
        uint textEnd = textBegin + (uint)textSection.VirtualSize;
        return addr >= textBegin && addr < textEnd;
    }

    private uint NextKnownStartAddr(uint addr) {
        SectionHeader textSection = peSections[textSectionIndex];
        uint textBegin = (uint)textSection.VirtualAddress + imageBase;
        uint textEnd = textBegin + (uint)textSection.VirtualSize;

        uint nextKnownAddr = textEnd;

        // find the first established func whose start address > addr
        foreach(var func in functionBoundaries) {
            if(func.addressStart > addr) {
                nextKnownAddr = func.addressStart;
                break;
            }
        }

        // then, search our known start addresses
        foreach (var knownAddr in knownStartAddrs) {
            // if we find a known start address that's > addr
            if (knownAddr > addr) {
                // if our found knownAddr is smaller than our established nextKnownAddr from the func search
                if (nextKnownAddr > knownAddr) {
                    // that's our new smallest next known addr
                    nextKnownAddr = knownAddr;
                }
                break;
            }
        }
        return nextKnownAddr;
    }

    //private uint FindFunctionEnd(BEBinaryReader br, uint startAddr, uint maxAddr) {
    //    var worklist = new Queue<uint>();
    //    var visited = new HashSet<uint>();
    //    uint highestAddr = startAddr;
    //    SectionHeader textSection = peSections[textSectionIndex];
    //    uint textSectionBegin = (uint)textSection.VirtualAddress + imageBase;
    //    uint textSectionEnd = textSectionBegin + (uint)textSection.SizeOfRawData;
    //    var originalPos = br.BaseStream.Position; // the position in the BR corresponding to the start of the func

    //    worklist.Enqueue(startAddr);

    //    while(worklist.Count > 0) {
    //        uint addr = worklist.Dequeue();

    //        if(visited.Contains(addr) || addr >= maxAddr || addr < textSectionBegin)
    //            continue;

    //        visited.Add(addr);
    //        if (addr > highestAddr)
    //            highestAddr = addr;

    //        int offset = textSection.PointerToRawData + (int)(addr - textSectionBegin);
    //        if (offset + 4 > textSectionEnd) continue;

    //        br.BaseStream.Seek(offset, SeekOrigin.Begin);
    //        uint instr = br.PeekUInt32();

    //        // if we somehow managed to have a 0 slip through the cracks, stop, this is the end
    //        if (instr == 0) {
    //            highestAddr -= 4;
    //            break;
    //        }

    //        // if blr
    //        if (PPCHelper.IsBLR(instr)) continue;

    //        // if unconditional branch (b or bl)
    //        if(PPCHelper.IsBranch(instr) || PPCHelper.IsBL(instr)) {
    //            uint target = CalculateBranchTarget((uint)offset, instr);
    //            // if the target is within the bounds of (startAddr, maxAddr), add it to our analysis queue
    //            if(target >= textSectionBegin && target > startAddr && target < maxAddr) {
    //                worklist.Enqueue(target);
    //            }
    //            else {
    //                // else, if this is a b, this *might* be a tail call
    //                // TODO: handle additional logic to determine if this b is a tail call or not
    //                if (PPCHelper.IsBranch(instr)) {

    //                    br.BaseStream.Seek(4, SeekOrigin.Current);
    //                    uint nextInst = br.PeekUInt32();
    //                    // if the next instruction over is all 0's, this is definitely a tail call
    //                    if (nextInst == 0) {
    //                        break;
    //                    }
    //                    // if the next instruction over's addr == maxAddr, tail call
    //                    else if(addr + 4 == maxAddr) {
    //                        break;
    //                    }
    //                    // if the next instruction over's addr < highestAddr + 4, it's NOT a tail call
    //                    // use addr + 4 for this
    //                    else if (addr + 4 < highestAddr + 4) {
    //                        // NOT a tail call, don't do anything
    //                    }
    //                    // if addr + 4 == highestAddr + 4 AND highestAddr + 4 is in the workList, don't mark it as a tail call, because we don't know for sure
    //                    // explorer that inst first instead of coming to a concrete conclusion
    //                    else if((addr + 4 == highestAddr + 4) && worklist.Contains(addr + 4)) {
    //                        // we don't know for sure, so don't do anything
    //                    }
    //                    // if the target is part of a known, non-reg intrinsic function, tail call
    //                    else if(GetFunctionFromBounds(target) != null && !GetFunctionFromBounds(target).IsRegIntrinsic()) {
    //                        break;
    //                    }
    //                    // if the target is NOT part of a known function
    //                    else if (GetFunctionFromBounds(target) == null) {
    //                        // if the b target is past the known start addr of this func, definitely a tail call
    //                        if (target < startAddr) {
    //                            break;
    //                        }
    //                        // if the b target is at or past the known start addr of a later func, definitely a tail call
    //                        if (target >= maxAddr) {
    //                            break;
    //                        }
    //                    }
    //                    else {
    //                        //Console.WriteLine($"Branch at 0x{addr:X} might be a tail call!");
    //                    }
    //                }
    //            }

    //            if (PPCHelper.IsBL(instr)) {
    //                worklist.Enqueue(addr + 4);
    //            }
    //            continue;
    //        }

    //        // if conditional branch (bc or bcl)
    //        // TODO: add extra logic to check for bgt's to jump tables
    //        if(PPCHelper.IsConditionalBranch(instr)) {
    //            uint target = CalculateConditionalBranchTarget((uint)offset, instr);
    //            if (target >= textSectionBegin && target > startAddr && target < maxAddr)
    //                worklist.Enqueue(target);

    //            worklist.Enqueue(addr + 4); // fallthrough path
    //            continue;
    //        }

    //        // this current inst ain't nothin special, just go ahead and add the next addr over
    //        worklist.Enqueue(addr + 4);
    //    }

    //    //Console.WriteLine($"Func that starts at 0x{startAddr:X}, ends at 0x{highestAddr + 4:X}");
    //    // now that we know where the end is, move the reader ahead up to that point
    //    br.BaseStream.Seek(originalPos + (highestAddr + 4 - startAddr), SeekOrigin.Begin);
    //    return highestAddr + 4;
    //}

    private void DumpFuncs() {
        string funcsDump = "";
        foreach (var func in functionBoundaries) {
            funcsDump += $"{func.name}: 0x{func.addressStart:X} - 0x{func.addressEnd:X}\n";
        }
        File.WriteAllText("D:\\DC3 Debug\\Gamepad\\Debug\\jeff_funcs.txt", funcsDump);
    }

    private void BrowsePData() {
        if (pDataSectionIndex == -1)
            throw new Exception(".pdata section not found. Is that even possible for an xex?");

        SectionHeader pDataSection = peSections[pDataSectionIndex];
        BEBinaryReader br = new BEBinaryReader(new MemoryStream(exeBytes));
        br.BaseStream.Seek(pDataSection.PointerToRawData, SeekOrigin.Begin);
        //Console.WriteLine($".pdata begins at 0x{CalcAddrFromRawByteOffset((uint)pDataSection.PointerToRawData):X}");
        while (br.BaseStream.Position < pDataSection.PointerToRawData + pDataSection.SizeOfRawData) {
            uint beginAddr = br.ReadUInt32();
            if (beginAddr == 0) break; // if we encounter 0's, that's the end of usable pdata entries
            uint theRest = br.ReadUInt32();

            uint numPrologueInsts = theRest & 0xFF;
            uint numInstsInFunc = (theRest >> 8) & 0x3FFFFF;
            bool flag32Bit = (theRest & 0x4000) != 0;
            bool exceptionFlag = (theRest & 0x8000) != 0;

            // using a sorted set to not worry about duplicates (like the reg intrinsics or XAPI calls)
            if (functionBoundaries.Add(new Function(beginAddr, beginAddr + (numInstsInFunc * 4), exceptionFlag))) {
                //Console.WriteLine($"Func found: 0x{beginAddr:X} - 0x{beginAddr + (numInstsInFunc * 4):X}");
            }
        }
    }

    private void CreateSpeculativeFunctions() {
        HashSet<uint> knownAddrs = new();
        SectionHeader textSection = peSections[textSectionIndex];
        uint textBegin = (uint)textSection.VirtualAddress + imageBase;
        uint textEnd = textBegin + (uint)textSection.VirtualSize;

        var disasm = CapstoneDisassembler.CreatePowerPcDisassembler(Gee.External.Capstone.PowerPc.PowerPcDisassembleMode.BigEndian);
        disasm.EnableInstructionDetails = true;

        BEBinaryReader br = new BEBinaryReader(new MemoryStream(exeBytes));
        br.BaseStream.Seek(textSection.PointerToRawData, SeekOrigin.Begin);
        // sweep the .text section for any bl's, so we can note their branch target
        while (br.BaseStream.Position < textSection.PointerToRawData + textSection.SizeOfRawData) {
            var curPos = br.BaseStream.Position; // because we want the position BEFORE the 4 bytes are read
            uint curInst = br.ReadUInt32();

            if (PPCHelper.IsBL(curInst)) {
                byte[] instBytes = BitConverter.GetBytes(curInst);
                Array.Reverse(instBytes);
                var inst = disasm.Disassemble(instBytes, CalcAddrFromRawByteOffset((uint)curPos))[0];
                Debug.Assert(inst.Mnemonic == "bl", "Not a bl instruction...somehow");
                uint branchTarget = Convert.ToUInt32(inst.Operand, 16);
                if (branchTarget >= textBegin && branchTarget < textEnd && GetFunctionFromBounds(branchTarget) == null && knownAddrs.Add(branchTarget)) {
                    //Console.WriteLine($"Added new func start (branch target): 0x{branchTarget:X}");
                }
            }
        }

        // once we've completed our sweep, sort the branch targets in ascending order
        List<uint> sortedAddrs = knownAddrs.ToList();
        sortedAddrs.Sort();
        knownStartAddrs = sortedAddrs;
        // then, for each branch target, create a Function from bounds (branch target, next known start addr)
        foreach (var addr in sortedAddrs) {
            functionBoundaries.Add(new Function(addr, NextKnownStartAddr(addr)));
        }
        knownStartAddrs.Clear();
    }

    private void BreakFuncsDownIntoBlocks() {
        // perform CFA on any remaining necessary funcs
        BEBinaryReader br = new BEBinaryReader(new MemoryStream(exeBytes));
        SectionHeader textSection = peSections[textSectionIndex];
        br.BaseStream.Seek(textSection.PointerToRawData, SeekOrigin.Begin);
        while (br.BaseStream.Position < textSection.PointerToRawData + textSection.SizeOfRawData) {
            // note current PC and virtual addr
            var curPos = br.BaseStream.Position;
            uint curAddr = CalcAddrFromRawByteOffset((uint)curPos);

            // ignore zero-padding
            if (br.PeekUInt32() == 0) {
                br.BaseStream.Seek(4, SeekOrigin.Current);
                continue;
            }
            // if this is an established func, refine its boundaries and create basic blocks
            else {
                Function? func = GetFunctionFromStartAddr(curAddr);
                if (func != null) {
                    func.FindBasicBlocks(br);
                    //Console.WriteLine($"{func.name} from 0x{func.addressStart:X} - 0x{func.addressEnd:X}");
                    br.BaseStream.Seek(curPos + (func.addressEnd - func.addressStart), SeekOrigin.Begin);
                    // skip the br to this func's determined end
                    // then, continue
                }
                // if we've reached this block, we have a possible start of a function we didn't find
                else {
                    uint next = NextKnownStartAddr(curAddr);
                    Function newFunc = new Function(curAddr, next);
                    newFunc.FindBasicBlocks(br);
                    functionBoundaries.Add(newFunc);
                    //Console.WriteLine($"{newFunc.name} from 0x{newFunc.addressStart:X} - 0x{newFunc.addressEnd:X}");
                    br.BaseStream.Seek(curPos + (newFunc.addressEnd - newFunc.addressStart), SeekOrigin.Begin);
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
        }

        Console.WriteLine($"Found {functionBoundaries.Count} functions");
    }

    public void Disassemble() {
        Intrinsics.FindRegIntrinsics(exeBytes, peSections[textSectionIndex], imageBase, ref functionBoundaries);
        Intrinsics.FindXCalls(exeBytes, peSections[textSectionIndex], imageBase, ref functionBoundaries);
        BrowsePData();
        // sweep for more start addresses using bl targets
        CreateSpeculativeFunctions();
        BreakFuncsDownIntoBlocks();
        DumpFuncs();
    }

    public void FindFunctionBoundaries() {
        //// new iteration:
        //// initial sweep to find and label the save/restore reg funcs
        //// sweep to find XAPI calls too! starting with XamInputGetCapabilities: e.g. 0x01000190020001907d6903a64e800420
        //// go through .pdata, but for each Function you find, analyze it for .data, jump tables, and funcptrs to more .text starts: Analyze(Function), used for if you know the func bounds
        //// rework the CFA func? to maybe Analyze(Function& func)? or Analyze(int funcIndex)? we're gonna need the start address, next known start address, and BEBinaryReader

        //// after .pdata has completed iteration,
        //// do a sweep to find any still-unaccounted-for func start addresses
        //// this can be achieved with: branch targets, any vtables you found

        //// initial sweep to find and label the save/restore reg funcs
        //FindSaveAndRestoreRegisterFuncs();
        //// go through .pdata and add Function entries for each one you find
        //BrowsePData();
        //// do a sweep to find any still-unaccounted-for func start addresses
        //knownStartAddrs = SweepForKnownFuncStartAddrs();

        //// and then search for func start addrs from vtables
        //// to find a vtable, search for r11 and a combo of lis, addi, and stw addr, 0x0(RX)
        //// go to that address, and mark every entry that is within the .text bounds
        //// TODO: if we have a map, add those start addresses too

        //// perform CFA on any remaining necessary funcs
        //BEBinaryReader br = new BEBinaryReader(new MemoryStream(exeBytes));
        //SectionHeader textSection = peSections[textSectionIndex];
        //br.BaseStream.Seek(textSection.PointerToRawData, SeekOrigin.Begin);
        //while(br.BaseStream.Position < textSection.PointerToRawData + textSection.SizeOfRawData) {
        //    // note current PC and virtual addr
        //    var curPos = br.BaseStream.Position;
        //    uint curAddr = CalcAddrFromRawByteOffset((uint)curPos);

        //    // ignore zero-padding
        //    if (br.PeekUInt32() == 0) {
        //        br.BaseStream.Seek(4, SeekOrigin.Current);
        //        continue;
        //    }
        //    // ignore the funcs we found earlier
        //    else if (GetFunctionFromBounds(curAddr) != null) {
        //        Function func = GetFunctionFromBounds(curAddr);
        //        //Console.WriteLine($"Encountered {func.name} at {curAddr:X}, skipping forward to...0x{func.addressEnd:X}");
        //        if(func.IsGPRIntrinsic()) {
        //            Function lastRestoreFunc = GetFunctionFromName("__restgprlr_31");
        //            br.BaseStream.Seek(lastRestoreFunc.addressEnd - curAddr, SeekOrigin.Current);
        //            continue;
        //        }
        //        else if(func.IsFPRIntrinsic()) {
        //            Function lastRestoreFunc = GetFunctionFromName("__restfpr_31");
        //            br.BaseStream.Seek(lastRestoreFunc.addressEnd - curAddr, SeekOrigin.Current);
        //            continue;
        //        }
        //        else if (func.IsVMXIntrinsic()) {
        //            Function lastRestoreFunc = GetFunctionFromName("__restvmx_127");
        //            br.BaseStream.Seek(lastRestoreFunc.addressEnd - curAddr, SeekOrigin.Current);
        //            continue;
        //        }
        //        else {
        //            br.BaseStream.Seek(func.addressEnd - curAddr, SeekOrigin.Current);
        //            continue;
        //        }
        //    }
        //    //// ignore random branches to xidata (or should we be ignoring these?)
        //    //else {
        //    //    var maybeBranchPC = br.BaseStream.Position;
        //    //    uint maybeBranchInstr = br.PeekUInt32();
        //    //    if(PPCHelper.IsBranch(maybeBranchInstr)) {
        //    //        uint target = CalculateBranchTarget((uint)maybeBranchPC, maybeBranchInstr);
        //    //        if (!AddrIsText(target)) {
        //    //            br.BaseStream.Seek(4, SeekOrigin.Current);
        //    //            continue;
        //    //        }
        //    //    }
        //    //}

        //    uint nextKnownStartAddr = NextKnownStartAddr(curAddr);
        //    //Console.WriteLine($"The func is from 0x{curAddr:X} til up to 0x{nextKnownStartAddr:X}");
        //    uint funcEnd = FindFunctionEnd(br, curAddr, nextKnownStartAddr);
        //    AddFunction(new Function($"fn_{curAddr:X}", true, curAddr, funcEnd, false));
        //}

        //Console.WriteLine($"Found {functionBoundaries.Count} functions");
        //DumpFuncs();
        //// need to resolve jump tables
    }

    // debug only: just to check that at the very minimum, we found the function boundaries that the map knows of
    public void VerifyAgainstMap(XexMap xexMap) {
        foreach(var entry in xexMap.entries) {
            if (AddrIsText(entry.vaddr)) {
                Function? func = GetFunctionFromStartAddr(entry.vaddr);
                if(func != null) {
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
    public int pDataSectionIndex;
    public int textSectionIndex;
    public List<uint> knownStartAddrs = new();
    public List<SectionHeader> peSections = new();
    // no two functions can have the same starting address
    // sorted by starting address implicitly, we don't have to do the sorting ourselves
    public SortedSet<Function> functionBoundaries = new SortedSet<Function>(new StartAddrCmp());
}