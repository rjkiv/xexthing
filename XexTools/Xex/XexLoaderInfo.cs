using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

class XexLoaderInfo {
    public uint headerSize;
    public uint imageSize;
    public byte[] rsaSignature;
    public uint unk;
    public uint imageFlags;
    public uint loadAddress;
    public byte[] sectionDigest;
    public uint importTableCount;
    public byte[] importTableDigest;
    public byte[] mediaID;
    public byte[] fileKey;
    public uint exportTable;
    public byte[] headerDigest;
    public uint gameRegions;
    public uint mediaFlags;

    public XexLoaderInfo() {
        rsaSignature = new byte[256];
        sectionDigest = new byte[20];
        importTableDigest = new byte[20];
        mediaID = new byte[16];
        fileKey = new byte[16];
        headerDigest = new byte[20];
    }

    public void Read(BEBinaryReader br) {
        headerSize = br.ReadUInt32();
        imageSize = br.ReadUInt32();
        br.Read(rsaSignature, 0, 256);
        unk = br.ReadUInt32();
        imageFlags = br.ReadUInt32();
        loadAddress = br.ReadUInt32();
        br.Read(sectionDigest, 0, 20);
        importTableCount = br.ReadUInt32();
        br.Read(importTableDigest, 0, 20);
        br.Read(mediaID, 0, 16);
        br.Read(fileKey, 0, 16);
        exportTable = br.ReadUInt32();
        br.Read(headerDigest, 0, 20);
        gameRegions = br.ReadUInt32();
        mediaFlags = br.ReadUInt32();
    }
}