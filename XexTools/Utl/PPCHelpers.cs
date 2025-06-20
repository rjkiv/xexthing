using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// blr: 4e 80 00 20

//      -name: b
//  pattern: 0x48000000

//- name: bc
//  pattern: 0x40000000

//- name: bcctr
//  pattern: 0x4c000420

//- name: bclr
//  pattern: 0x4c000020
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

    public static bool IsBLRL(uint instr) {
        return instr == 0x4e800021;
    }

    public static bool IsLIS(uint instr) {
        if ((instr & 0xFC000000) != 0x3C000000) return false;
        return (instr & 0xFC1F0000) == 0x3C000000;
    }

    public static bool IsLFS(uint instr) {
        return (instr & 0xFC000000) == 0xC0000000;
    }

    public static bool IsAddi(uint instr) {
        return (instr & 0xFC000000) == 0x38000000;
    }

    public static bool IsBdnz(uint instr) {
        if ((instr & 0xFC000000) != 0x40000000) return false;
        return (instr & 0xFFFF0000) == 0x42000000;
    }

    public static bool IsLoadIndexed(uint instr) {
        uint mask = instr & 0xfc0007ff;
        if (mask == 0x7C0000AE) return true; // lbzx
        if (mask == 0x7C00022E) return true; // lhzx
        if (mask == 0x7C00002E) return true; // lwzx
        return false;
    }
}