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

    //List<BasicBlock> basicBlocks = new List<BasicBlock> ();
    SortedSet<BasicBlock> basicBlocks = new SortedSet<BasicBlock>(new BlockStartCmp());

    // start addr, end addr (either known or speculated max addr)
    public Function(uint start, uint end, string name = "") {
        addressStart = start;
        addressEnd = end;
        hasExceptionHandler = false;
        if (name == "") this.name = $"fn_{addressStart:X}";
        else this.name = name;
    }

    // for if you find a function from .pdata
    public Function(uint start, uint end, bool hasHandler, string name = "") {
        addressStart = start;
        addressEnd = end;
        hasExceptionHandler = hasHandler;
        if (name == "") this.name = $"fn_{addressStart:X}";
        else this.name = name;
    }

    public void SetName(string name) { this.name = name; }
    public void FindBasicBlocks(BEBinaryReader br) {
        var visited = new HashSet<uint>();
        //var basicBlockBounds = new SortedSet<uint>();
        var startPos = br.BaseStream.Position;
        var endPos = startPos + (addressEnd - addressStart);
        var queue = new Queue<uint>();
        queue.Enqueue(addressStart);
        //basicBlockBounds.Add(addressStart);

        var disasm = CapstoneDisassembler.CreatePowerPcDisassembler(Gee.External.Capstone.PowerPc.PowerPcDisassembleMode.BigEndian);
        disasm.EnableInstructionDetails = true;

        while (queue.Count > 0) {
            uint addr = queue.Dequeue();
            if(visited.Contains(addr)) continue;

            visited.Add(addr);
            var curBlock = new BasicBlock();
            curBlock.startAddr = addr;

            uint curAddr = addr;
            while(curAddr < addressEnd) {
                uint curOffset = curAddr - addressStart;
                if (curOffset + 4 > endPos) break;

                br.BaseStream.Seek(startPos + curOffset, SeekOrigin.Begin);
                uint instr = br.PeekUInt32();

                // blr(l) = block ends here, no successors
                if (PPCHelper.IsBLR(instr) || PPCHelper.IsBLRL(instr)) {
                    curBlock.endAddr = curAddr + 4;
                    basicBlocks.Add(curBlock);
                    break;
                }
                // bl = block ends here, successor = the next addr over
                else if (PPCHelper.IsBL(instr)) {
                    curBlock.endAddr = curAddr + 4;
                    curBlock.successors.Add(curBlock.endAddr);
                    basicBlocks.Add(curBlock);
                    queue.Enqueue(curAddr + 4);
                    break;
                }
                // for a conditional branch, depending on if the branchTarget goes up or down, do different things
                else if (PPCHelper.IsConditionalBranch(instr)) {
                    byte[] instBytes = BitConverter.GetBytes(instr);
                    Array.Reverse(instBytes);
                    var inst = disasm.Disassemble(instBytes, curAddr)[0];
                    uint branchTarget = (uint)inst.Details.Operands[inst.Details.Operands.Length - 1].Immediate;
                    // goes down
                    if (branchTarget > curAddr) {
                        curBlock.endAddr = curAddr + 4;
                        curBlock.successors.Add(branchTarget);
                        curBlock.successors.Add(curBlock.endAddr);
                        basicBlocks.Add(curBlock);
                        queue.Enqueue(branchTarget);
                        queue.Enqueue(curAddr + 4);
                        break;
                    }
                    // goes up
                    else {
                        BasicBlock? prevBlock = basicBlocks.FirstOrDefault(b => b.startAddr < branchTarget && branchTarget <= b.endAddr);
                        // if the target is part of a different, pre-established block
                        if (prevBlock != null) {
                            // if our branch target in the middle of said block
                            if (prevBlock.endAddr != branchTarget) {
                                // prevBlock's end address should now be this branch target
                                prevBlock.endAddr = branchTarget;
                                // the sole successor should now be the branch target
                                prevBlock.successors.Clear();
                                prevBlock.successors.Add(prevBlock.endAddr);
                            }
                            // otherwise, no need to do any splitting

                            // this block should end just after the branch inst
                            curBlock.endAddr = curAddr + 4;
                            // add two successors: the branch target, and the fallthrough
                            curBlock.successors.Add(branchTarget);
                            curBlock.successors.Add(curAddr + 4);
                            basicBlocks.Add(curBlock);
                            // enqueue our successors
                            queue.Enqueue(branchTarget);
                            queue.Enqueue(curAddr + 4);
                            break;
                        }
                        // if the target is part of this specific block...
                        // if we're looping back to ourselves
                        else if (branchTarget == curBlock.startAddr) {
                            curBlock.endAddr = curAddr + 4;
                            curBlock.successors.Add(curBlock.startAddr); // should we do this? i mean technically it's true
                            curBlock.successors.Add(curAddr + 4);
                            basicBlocks.Add(curBlock);
                            queue.Enqueue(curAddr + 4);
                            break;
                        }
                        else {
                            // cut this block off at the branch target, make it a successor, and then enqueue it
                            curBlock.endAddr = branchTarget;
                            curBlock.successors.Add(branchTarget);
                            basicBlocks.Add(curBlock);
                            queue.Enqueue(branchTarget);
                            break;
                        }
                    }
                }
                // TODO: else if is bc/bctr/bctrl starts with bc
                else if (PPCHelper.IsBranch(instr)) {
                    byte[] instBytes = BitConverter.GetBytes(instr);
                    Array.Reverse(instBytes);
                    var inst = disasm.Disassemble(instBytes, curAddr)[0];
                    uint branchTarget = (uint)inst.Details.Operands[inst.Details.Operands.Length - 1].Immediate;
                    // TODO: logic for handling tail calls
                    // if the branch target isn't even part of the function
                    // AND TODO: target is not a reg intrinsic!
                    if (branchTarget < addressStart || branchTarget >= addressEnd) {
                        // tail call, end it here
                        curBlock.endAddr = curAddr;
                        basicBlocks.Add(curBlock);
                        break;
                    }

                    // if the branch goes down into the function
                    if (branchTarget > curAddr) {
                        curBlock.endAddr = curAddr + 4;
                        curBlock.successors.Add(branchTarget);
                        basicBlocks.Add(curBlock);
                        queue.Enqueue(branchTarget);
                        break;

                    }
                    // if the branch goes up into the function
                    else {
                        BasicBlock? prevBlock = basicBlocks.FirstOrDefault(b => b.startAddr < branchTarget && branchTarget <= b.endAddr);
                        // if the target is part of a different, pre-established block
                        if (prevBlock != null) {
                            // if our branch target is in the middle of said block
                            if (prevBlock.endAddr != branchTarget) {
                                // prevBlock's end address should now be this branch target
                                prevBlock.endAddr = branchTarget;
                                // the sole successor should now be the branch target
                                prevBlock.successors.Clear();
                                prevBlock.successors.Add(prevBlock.endAddr);
                            }
                            // this block should end at the branch inst
                            curBlock.endAddr = curAddr + 4;
                            curBlock.successors.Add(branchTarget);
                            basicBlocks.Add(curBlock);
                            queue.Enqueue(branchTarget);
                            break;
                        }
                        // if the target is part of this specific block...
                        // if we're looping back to ourselves
                        else if (branchTarget == curBlock.startAddr) {
                            // would this even happen in the case of an unconditional branch?
                            curBlock.endAddr = curAddr + 4;
                            curBlock.successors.Add(curBlock.startAddr); // should we do this? i mean technically it's true
                            curBlock.successors.Add(curAddr + 4);
                            basicBlocks.Add(curBlock);
                            queue.Enqueue(curAddr + 4);
                            break;
                        }
                        else {
                            // cut this block off at the branch target, make it a successor, and then enqueue it
                            curBlock.endAddr = branchTarget;
                            curBlock.successors.Add(branchTarget);
                            basicBlocks.Add(curBlock);
                            queue.Enqueue(branchTarget);
                            break;
                        }
                    }
                }
                // if we've bumped into an existing BasicBlock
                else if (basicBlocks.FirstOrDefault(b => b.startAddr == curAddr) != null) {
                    curBlock.endAddr = curAddr;
                    curBlock.successors.Add(curAddr);
                    basicBlocks.Add(curBlock);
                    queue.Enqueue(curAddr);
                    break;
                }
                else curAddr += 4;
            }
        }
    }
    void Analyze() {

    }

    //    public bool IsGPRIntrinsic() {
    //        return name.Contains("__savegprlr") || name.Contains("__restgprlr");
    //    }

    //    public bool IsFPRIntrinsic() {
    //        return name.Contains("__savefpr") || name.Contains("__restfpr");
    //    }

    //    public bool IsVMXIntrinsic() {
    //        return name.Contains("__savevmx") || name.Contains("__restvmx");
    //    }

    //    public bool IsRegIntrinsic() {
    //        return IsGPRIntrinsic() || IsFPRIntrinsic() || IsVMXIntrinsic();
    //    }
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

/*

class VM {
    public uint GPR[32];
};

class VMState {
    VM vm;
    uint address;
};

class Instruction {
    Opcode opcode;
    // other stuff
};

class Function {
    // the fn's name
    public string name;
    // the known start addr of this func
    public uint addressStart;
    // the end addr of this func (either found through .pdata or determined through FindBasicBlocks())
    public uint addressEnd;
    // the exception flag in .pdata. if this func is not in .pdata, this should be false
    public bool hasExceptionHandler;

    List<BasicBlock> basicBlocks;

    // start addr, end addr (either known or speculated max addr)
    Function(start addr, end addr, name = "")

    // for if you find a function from .pdata
    Function(start addr, end addr, hasExceptionHandler, name = "")

    void SetName(string name);
    void FindBasicBlocks();
    void Analyze();
};
 

void Analyze(Function func){
    // the memory addresses to process
    var worklist = new Stack<uint>();
    // the memory addresses that we've visited, via CFA
    var visited = new HashSet<uint>();

    uint highestAddr = func.addressStart;
    uint textSectionBegin = (uint)textSection.VirtualAddress + imageBase;
    uint textSectionEnd = textSectionBegin + (uint)textSection.SizeOfRawData;
    BEBinaryReader br = stream for the raw exeBytes

    // our VM, initialized before function analysis begins
    // contains 32 GPRs
    VM curVM;

    // a vector of VMStates, to be populated in the event we encounter a branch
    Array<VMState> vmStates;

    worklist.Push(func.addressStart);

    while(worklist.Count > 0){
        // the current address we're analyzing
        uint addr = worklist.Pop();

        if(visited.Contains(addr) || addr >= func.addressEnd || addr < textSectionBegin) continue;
        visited.Add(addr);
        if(addr > highestAddr) highestAddr = addr;

        int offset = textSection.PointerToRawData + (int)(addr - textSectionBegin);
        if (offset + 4 > textSectionEnd) continue;

        br.BaseStream.Seek(offset, SeekOrigin.Begin);
        uint instr = br.PeekUInt32();

        // if the instruction is a non-branching arithmetic function, update the corresponding regs in curVM

        // if we somehow managed to have a 0 slip through the cracks, stop, this is the end
        if (instr == 0) { highestAddr -= 4; break; }

        // if blr
        if (PPCHelper.IsBLR(instr)) continue;
    }
    

       var worklist = new Queue<uint>();
        var visited = new HashSet<uint>();
        uint highestAddr = startAddr;
        SectionHeader textSection = peSections[textSectionIndex];
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
                        else if(GetFunctionFromBounds(target) != null && !GetFunctionFromBounds(target).IsRegIntrinsic()) {
                            break;
                        }
                        // if the target is NOT part of a known function
                        else if (GetFunctionFromBounds(target) == null) {
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
 
 
 
 
 
 */