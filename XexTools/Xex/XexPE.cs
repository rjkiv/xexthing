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

    private void DumpFuncs(bool includePdata) {
        string funcsDump = "";
        foreach (var func in functionBoundaries) {
            if (func.knownFromPData) {
                if (!includePdata) continue;
                funcsDump += $"{func.name}: 0x{func.addressStart:X} - 0x{func.addressEnd:X} (pdata)\n";
            }
            else {
                funcsDump += $"{func.name}: 0x{func.addressStart:X} - 0x{func.addressEnd:X}\n";
            }
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
        DumpFuncs(false);
        VerifyAgainstPData();
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

    public void VerifyAgainstPData() {
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

            Function? function = GetFunctionFromStartAddr(beginAddr);
            Debug.Assert(function != null, $"Function starting at 0x{beginAddr:X} has been tampered with!");
            if (!Function.IsRegIntrinsic(beginAddr)) {
                Debug.Assert(function.addressEnd == beginAddr + (numInstsInFunc * 4),
                    $"Function starting at 0x{beginAddr:X} should end at 0x{beginAddr + (numInstsInFunc * 4):X}, but instead, it now ends at 0x{function.addressEnd:X}!");
            }

            // using a sorted set to not worry about duplicates (like the reg intrinsics or XAPI calls)
            if (functionBoundaries.Add(new Function(beginAddr, beginAddr + (numInstsInFunc * 4), exceptionFlag))) {
                //Console.WriteLine($"Func found: 0x{beginAddr:X} - 0x{beginAddr + (numInstsInFunc * 4):X}");
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