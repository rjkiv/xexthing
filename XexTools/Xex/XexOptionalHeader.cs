using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

class XexOptionalHeader {
    public enum XexOptionalHeaderID {
        kResourceInfo = 0x2FF,
        kBaseFileFormat = 0x3FF,
        kBaseReference = 0x405,
        kDeltaPatchDescriptor = 0x5FF,
        kBoundingPath = 0x80FF,
        kDeviceID = 0x8105,
        kOriginalBaseAddress = 0x10001,
        kEntryPoint = 0x10100,
        kImageBaseAddress = 0x10201,
        kImportLibraries = 0x103FF,
        kChecksumTimestamp = 0x18002,
        kEnabledForCallcap = 0x18102,
        kEnabledForFastcap = 0x18200,
        kOriginalPEName = 0x183FF,
        kStaticLibraries = 0x200FF,
        kTLSInfo = 0x20104,
        kDefaultStackSize = 0x20200,
        kDefaultFilesystemCacheSize = 0x20301,
        kDefaultHeapSize = 0x20401,
        kPageHeapSizeAndFlags = 0x28002,
        kSystemFlags = 0x30000,
        // extra flag found! 0x30100
        kExecutionID = 0x40006,
        kServiceIDList = 0x401FF,
        kTitleWorkspaceSize = 0x40201,
        kGameRatings = 0x40310,
        kLANKey = 0x40404,
        kXbox360Logo = 0x405FF,
        kMultidiscMediaIDs = 0x406FF,
        kAlternateTitleIDs = 0x407FF,
        kAdditionalTitleMemory = 0x40801,
        kExportsByName = 0xE10402
    }

    public XexOptionalHeaderID headerID;
    public uint value;
    public byte[] data;

    public XexOptionalHeader Read(BEBinaryReader br) {
        headerID = (XexOptionalHeaderID)br.ReadUInt32();
        value = br.ReadUInt32();
        // set data according to the headerID mask
        var curPos = br.BaseStream.Position;
        uint mask = (uint)headerID & 0xFF;
        if(mask == 0xFF) {
            br.BaseStream.Seek(value, SeekOrigin.Begin);
            uint len = br.ReadUInt32();
            data = new byte[len];
            br.Read(data, 0, (int)len);
        }
        else if(mask < 2) {
            data = BitConverter.GetBytes(value);
            Array.Reverse(data); // because big endian
        }
        else {
            br.BaseStream.Seek(value, SeekOrigin.Begin);
            uint len = br.ReadUInt32() * 4;
            data = new byte[len];
            br.Read(data, 0, (int)len);
        }
        br.BaseStream.Seek(curPos, SeekOrigin.Begin);
        return this;
    }
}