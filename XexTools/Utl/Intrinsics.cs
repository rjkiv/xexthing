using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Threading.Tasks;

// for compiler intrinsics or API calls that have a hard-set series of asm we can look out for
public static class Intrinsics {
    private class Intrinsic {
        public string name { get; private set; }
        public string bytes { get; private set; }

        public Intrinsic(string name, string bytes) { this.name = name; this.bytes = bytes; }
    }
    // savegprlrs 14-17
    public static string strSaveGPR = "F9C1FF68F9E1FF70FA01FF78FA21FF80";
    // savefprs 14-17
    public static string strSaveFPR = "D9CCFF70D9ECFF78DA0CFF80DA2CFF88";
    // savevmxs 14-17
    public static string strSaveVMX = "3960FEE07DCB61CE3960FEF07DEB61CE3960FF007E0B61CE3960FF107E2B61CE";

    private static readonly Intrinsic[] regIntrinsics = [
        // savegprlrs 14-17
        new("__savegprlr", "F9C1FF68F9E1FF70FA01FF78FA21FF80"),
        // savefprs 14-17
        new("__savefpr", "D9CCFF70D9ECFF78DA0CFF80DA2CFF88"),
        // savevmxs 14-17
        new("__savevmx", "3960FEE07DCB61CE3960FEF07DEB61CE3960FF007E0B61CE3960FF107E2B61CE")
    ];

    public static void FindRegIntrinsics(byte[] exeBytes, SectionHeader sectionToSearch, uint imageBase, ref SortedSet<Function> funcs) {
        ReadOnlySpan<byte> searchableBytes = exeBytes.AsSpan().Slice(sectionToSearch.PointerToRawData, sectionToSearch.SizeOfRawData);

        int saveIdx = searchableBytes.IndexOf(Convert.FromHexString(regIntrinsics[0].bytes));
        if (saveIdx == -1) throw new Exception("Save gpr compiler intrinsics not found. Is that even possible for an xex?");
        else saveIdx += sectionToSearch.PointerToRawData;
        for(int i = 14; i <= 31; i++, saveIdx += 4) {
            uint saveAddr = (uint)saveIdx - (uint)sectionToSearch.PointerToRawData + imageBase + (uint)sectionToSearch.VirtualAddress;
            uint restoreAddr = saveAddr + 0x50;
            funcs.Add(new Function(saveAddr, saveAddr + 4 + (uint)(i == 31 ? 8 : 0), true, $"__savegprlr_{i}"));
            funcs.Add(new Function(restoreAddr, restoreAddr + 4 + (uint)(i == 31 ? 12 : 0), true, $"__restgprlr_{i}"));
            if (i == 14) Function.gprStart = saveAddr;
            if (i == 31) Function.gprEnd = restoreAddr + 16;
        }

        saveIdx = searchableBytes.IndexOf(Convert.FromHexString(regIntrinsics[1].bytes));
        if (saveIdx == -1) throw new Exception("Save fpr compiler intrinsics not found. Is that even possible for an xex?");
        else saveIdx += sectionToSearch.PointerToRawData;
        for (int i = 14; i <= 31; i++, saveIdx += 4) {
            uint saveAddr = (uint)saveIdx - (uint)sectionToSearch.PointerToRawData + imageBase + (uint)sectionToSearch.VirtualAddress;
            uint restoreAddr = saveAddr + 0x4C;
            funcs.Add(new Function(saveAddr, saveAddr + 4 + (uint)(i == 31 ? 4 : 0), true, $"__savefpr_{i}"));
            funcs.Add(new Function(restoreAddr, restoreAddr + 4 + (uint)(i == 31 ? 4 : 0), true, $"__restfpr_{i}"));
            if (i == 14) Function.fprStart = saveAddr;
            if (i == 31) Function.fprEnd = restoreAddr + 8;
        }

        saveIdx = searchableBytes.IndexOf(Convert.FromHexString(regIntrinsics[2].bytes));
        if (saveIdx == -1) throw new Exception("Save vmx compiler intrinsics not found. Is that even possible for an xex?");
        else saveIdx += sectionToSearch.PointerToRawData;

        // the order goes: save 14-31, then 64-127, with each func taking up 8 bytes
        for (int i = 14; i <= 31; i++, saveIdx += 8) {
            uint saveAddr = (uint)saveIdx - (uint)sectionToSearch.PointerToRawData + imageBase + (uint)sectionToSearch.VirtualAddress;
            funcs.Add(new Function(saveAddr, saveAddr + 8 + (uint)(i == 31 ? 4 : 0), true, $"__savevmx_{i}"));
            if(i == 14) Function.vmxStart = saveAddr;
        }
        saveIdx += 4;
        for(int i = 64; i <= 127; i++, saveIdx += 8) {
            uint saveAddr = (uint)saveIdx - (uint)sectionToSearch.PointerToRawData + imageBase + (uint)sectionToSearch.VirtualAddress;
            funcs.Add(new Function(saveAddr, saveAddr + 8 + (uint)(i == 127 ? 4 : 0), true, $"__savevmx_{i}"));
        }
        saveIdx += 4;
        for (int i = 14; i <= 31; i++, saveIdx += 8) {
            uint restoreAddr = (uint)saveIdx - (uint)sectionToSearch.PointerToRawData + imageBase + (uint)sectionToSearch.VirtualAddress;
            funcs.Add(new Function(restoreAddr, restoreAddr + 8 + (uint)(i == 31 ? 4 : 0), true, $"__restvmx_{i}"));
        }
        saveIdx += 4;
        for (int i = 64; i <= 127; i++, saveIdx += 8) {
            uint restoreAddr = (uint)saveIdx - (uint)sectionToSearch.PointerToRawData + imageBase + (uint)sectionToSearch.VirtualAddress;
            funcs.Add(new Function(restoreAddr, restoreAddr + 8 + (uint)(i == 127 ? 4 : 0), true, $"__restvmx_{i}"));
            if (i == 127) Function.vmxEnd = restoreAddr + 12;
        }
    }

    // funny enough, these are in .xidata in debug, but in release, these get tacked onto the end of .text
    private static readonly Intrinsic[] xIntrinsics = [
        new("XamInputGetCapabilities", "01000190020001907D6903A64E800420"),
        new("XamInputGetState", "01000191020001917D6903A64E800420"),
        new("XamInputSetState", "01000192020001927D6903A64E800420")
        // TODO: there are waaaaay more of these
    ];

    public static void FindXCalls(byte[] exeBytes, SectionHeader sectionToSearch, uint imageBase, ref SortedSet<Function> funcs) {
        ReadOnlySpan<byte> searchableBytes = exeBytes.AsSpan().Slice(sectionToSearch.PointerToRawData, sectionToSearch.SizeOfRawData);

        foreach(var intr in xIntrinsics) {
            int xOffset = searchableBytes.IndexOf(Convert.FromHexString(intr.bytes));
            if (xOffset != -1) {
                xOffset += sectionToSearch.PointerToRawData;
                // since xOffset != -1, that means it found our bytes
                // and since searchableBytes are only the bytes that make up sectionToSearch, we know what we found is in the section we want
                uint xAddr = (uint)xOffset - (uint)sectionToSearch.PointerToRawData + imageBase + (uint)sectionToSearch.VirtualAddress;
                funcs.Add(new Function(xAddr, xAddr + (((uint)intr.bytes.Length / 8) * 4), intr.name));
            }
        }
    }
}