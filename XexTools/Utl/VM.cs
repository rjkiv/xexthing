using Gee.External.Capstone;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using static System.Reflection.Metadata.BlobBuilder;

class GPR {

}

class VM {

}

public class BasicBlock {
    public uint startAddr;
    public uint endAddr;
    public List<uint> successors = new();
}

public class Function {
    // the fn's name
    public string name { get; private set; }
    // the known start addr of this func
    public uint addressStart;
    // the end addr of this func (either found through .pdata or determined through FindBasicBlocks())
    public uint addressEnd;
    // the exception flag in .pdata. if this func is not in .pdata, this should be false
    public bool hasExceptionHandler;

    public bool knownFromPData;
    public bool possibleJumpTable;

    //List<BasicBlock> basicBlocks = new List<BasicBlock> ();
    SortedSet<BasicBlock> basicBlocks = new SortedSet<BasicBlock>(new BlockStartCmp());

    public static uint gprStart;
    public static uint gprEnd;
    public static uint fprStart;
    public static uint fprEnd;
    public static uint vmxStart;
    public static uint vmxEnd;
    public static bool IsRegIntrinsic(uint addr) {
        if (addr >= gprStart && addr < gprEnd) return true;
        if(addr >= fprStart && addr < fprEnd) return true;
        if(addr >= vmxStart && addr < vmxEnd) return true;
        return false;
    }

    // start addr, end addr (either known or speculated max addr)
    public Function(uint start, uint end, string name = "") {
        addressStart = start;
        addressEnd = end;
        hasExceptionHandler = false;
        possibleJumpTable = false;
        knownFromPData = false;
        if (name == "") this.name = $"fn_{addressStart:X}";
        else this.name = name;
    }

    // for if you find a function from .pdata
    public Function(uint start, uint end, bool hasHandler, string name = "") {
        addressStart = start;
        addressEnd = end;
        hasExceptionHandler = hasHandler;
        possibleJumpTable = false;
        knownFromPData = true;
        if (name == "") this.name = $"fn_{addressStart:X}";
        else this.name = name;
    }

    public void SetName(string name) { this.name = name; }
    public void FindBasicBlocks(BEBinaryReader br) {
        var visited = new HashSet<uint>();
        var basicBlockBounds = new SortedSet<uint>();
        var startPos = br.BaseStream.Position;
        var endPos = startPos + (addressEnd - addressStart);
        var queue = new Queue<uint>();
        queue.Enqueue(addressStart);
        basicBlockBounds.Add(addressStart);
        var branchPaths = new Dictionary<uint, List<uint>>();

        var disasm = CapstoneDisassembler.CreatePowerPcDisassembler(Gee.External.Capstone.PowerPc.PowerPcDisassembleMode.BigEndian);
        disasm.EnableInstructionDetails = true;

        // just go through every instruction one by one, marking block boundaries
        // once you've got them, assemble them and mark down successors

        uint possibleJumpTableMask = 0;

        if(addressStart == 0x821a5720) {

        }

        uint addr = addressStart;
        for(; addr < addressEnd; addr += 4) {
            uint instr = br.ReadUInt32();
            if (instr == 0) break; // ignore zero-padding

            // if cmplwi, this is possibly the first of a sequence of jump table bytes
            if ((instr & 0xFC000000) == 0x28000000) possibleJumpTableMask |= 1;
            // if l(whatever)zx
            if (PPCHelper.IsLoadIndexed(instr)  ) possibleJumpTableMask |= 4;
            // if mtspr
            if ((instr & 0xfc0007ff) == 0x7C0003a6 && possibleJumpTableMask == 7) possibleJumpTableMask |= 8;

            // if inst & 0xF0000000 == 0x40000000, possible branch
            if ((instr & 0xF0000000) == 0x40000000) {
                byte[] instBytes = BitConverter.GetBytes(instr);
                Array.Reverse(instBytes);
                var bInst = disasm.Disassemble(instBytes, addr)[0];
                char[] remove = ['+', '-']; // we don't care about speculative branch direction
                string mnemonic = bInst.Mnemonic.TrimEnd(remove);
                if(mnemonic == "bdnz" || mnemonic == "bdz" ||
                    mnemonic == "bdzf" || mnemonic == "bdnzf" ||
                    mnemonic == "bge" || mnemonic == "bgt" ||
                    mnemonic == "bne" || mnemonic == "beq" ||
                    mnemonic == "ble" || mnemonic == "blt") {
                    if (mnemonic == "bgt" && (possibleJumpTableMask & 1) == 1) possibleJumpTableMask |= 2;
                    // new bounds: the target, and the fallthrough
                    uint target = (uint)bInst.Details.Operands[bInst.Details.Operands.Length - 1].Immediate;
                    basicBlockBounds.Add(target);
                    basicBlockBounds.Add(addr + 4);
                    branchPaths[addr] = new List<uint> { target, addr + 4 };
                }
                else if(mnemonic == "bl" || mnemonic == "bctrl") {
                    // we only want the fallthrough
                    basicBlockBounds.Add(addr + 4);
                }
                else if(mnemonic == "blelr" || mnemonic == "beqlr" || mnemonic == "bltlr" || mnemonic == "bnelr" || mnemonic == "bgelr" || mnemonic == "bdzlr" || mnemonic == "bgtlr") {
                    basicBlockBounds.Add(addr + 4);
                }
                else if(mnemonic == "bctr") {
                    if(possibleJumpTableMask == 15) {
                        possibleJumpTableMask = 0;
                        possibleJumpTable = true;
                        basicBlockBounds.Add(addr + 4);
                    }
                    // if not a possible jump table, this is the end
                    // if there are no more established basic block bounds that are > this address, it IS a tail call
                    else {
                        uint? firstGreaterBound = basicBlockBounds.FirstOrDefault(x => x > addr);
                        if(firstGreaterBound == 0) {
                            addr += 4;
                            if (PPCHelper.IsBLR(br.PeekUInt32())) addr += 4; // evil hack to make it end after the blr if the next inst is a blr
                            break;
                        }
                    }
                }
                else if(mnemonic == "bnectr") {
                    // anything special to do here?
                }
                else if(mnemonic == "b") {
                    if(br.PeekUInt32() == 0) { // if the next inst is 0
                        continue; // because the next iteration of the loop will catch that 0 and mark the end of this function
                    }

                    uint target = (uint)bInst.Details.Operands[bInst.Details.Operands.Length - 1].Immediate;
                    // if the target is within the bounds of this function, add it to our bounds
                    if (target >= addressStart && target < addressEnd) {
                        basicBlockBounds.Add(target);
                        // although not a fallthrough, if the target went down, this does mark the start of a new block
                        if(target > addr) basicBlockBounds.Add(addr + 4);
                        branchPaths[addr] = new List<uint> { target };
                    }
                    // if the target is outside the bounds of this function and it's NOT a reg intrinsic, it's a tail call
                    if((target < addressStart || target > addressEnd) && !IsRegIntrinsic(target)){
                        addr += 4; break;
                    }
                    else {
                        // if there are no more established basic block bounds that are > this address, it IS a tail call
                        uint? firstGreaterBound = basicBlockBounds.FirstOrDefault(x => x > addr);
                        if (firstGreaterBound == 0) {
                            addr += 4; break;
                        }
                        else {
                            // any other logic to determine tail calls goes here
                            // currently, if this branch is reached, it's treated as NOT a tail call
                        }
                    }
                }
                else if(mnemonic == "blr" || mnemonic == "blrl") {
                    // if there are no more established basic block bounds that are > this address, it IS a tail call
                    uint? firstGreaterBound = basicBlockBounds.FirstOrDefault(x => x > addr);
                    if (firstGreaterBound == 0) {
                        addr += 4; break;
                    }
                    //addr += 4;
                    //break; // (should we do this? i *think* in some switch cases there may be multiple blrs)
                }
                else throw new Exception($"Unhandled branch instruction {mnemonic}!");
            }
        }

        if(!knownFromPData) addressEnd = addr;
        // construct the basic blocks
        for (int i = 0; i < basicBlockBounds.Count; i++) {
            BasicBlock block = new BasicBlock();
            block.startAddr = basicBlockBounds.ElementAt(i);
            if (i == basicBlockBounds.Count - 1) block.endAddr = addressEnd;
            else {
                block.endAddr = basicBlockBounds.ElementAt(i + 1);
                if (branchPaths.TryGetValue(block.endAddr - 4, out var branchResults)) {
                    block.successors = branchResults;
                }
                // if there are no successors at this point, it means the block doesn't end in a branch instruction
                // so, we'll add one successor that starts at the block's end address
                if (block.successors.Count == 0) {
                    block.successors.Add(block.endAddr);
                }
            }
            basicBlocks.Add(block);
        }

    }
    void Analyze() {

    }
}

class BlockStartCmp : IComparer<BasicBlock> {
    public int Compare(BasicBlock x, BasicBlock y) {
        return x.startAddr.CompareTo(y.startAddr);
    }
}

class StartAddrCmp : IComparer<Function> {
    public int Compare(Function x, Function y) {
        return x.addressStart.CompareTo(y.addressStart);
    }
}