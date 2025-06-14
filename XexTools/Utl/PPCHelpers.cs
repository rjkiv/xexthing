using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

public static class PPCHelper {
    public static bool IsBranch(uint instr) {
        if ((instr & 0xFC000000) != 0x48000000) return false;
        return (instr & 0x48000003) == 0x48000000;
    }

    public static bool IsBL(uint instr) {
        if ((instr & 0xFC000000) != 0x48000000) return false;
        return (instr & 0x48000003) == 0x48000001;
    }

    public static bool IsConditionalBranch(uint instr) {
        return (instr & 0xfc000000) == 0x40000000;
    }

    public static bool IsBLR(uint instr) {
        return instr == 0x4e800020;
    }
}