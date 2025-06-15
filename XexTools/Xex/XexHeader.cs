using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

class XexHeader {
    const uint XEX2_MAGIC = 0x58455832; // 'XEX2'
    public uint magic;
    public uint moduleFlags;
    public uint peDataOffset;
    public uint reserved;
    public uint securityInfoOffset;
    public uint optionalHeaderCount;
    public List<XexOptionalHeader> optionalHeaders;
    public BaseFileFormat baseFileFormat;
    public List<String> stringTable;
    public List<ImportLibrary> importLibs;
    public XexLoaderInfo loaderInfo = new();
    public byte[] sessionKey;
    public List<XexSection> sections = new();
    public byte[] peImage;

    public void DecryptFileKey() {
        byte[] key = new byte[16]; // TODO: this will be different for retail xex's (i.e. did not come from a dev kit): 20B185A59D28FDC340583FBB0896BF91
        sessionKey = AesHelper.DecryptAesCbcNoPadding(key, loaderInfo.fileKey);
    }

    private void ReadOptionalHeaders(BEBinaryReader br) {
        optionalHeaderCount = br.ReadUInt32();
        Console.WriteLine("Optional header count: " + optionalHeaderCount);
        optionalHeaders = new List<XexOptionalHeader>();
        for(int i = 0; i < optionalHeaderCount; i++) {
            optionalHeaders.Add(new XexOptionalHeader().Read(br));
        }
        // process extra fields based on the optional headers
        foreach(var header in optionalHeaders){
            switch (header.headerID) {
                //case XexOptionalHeader.XexOptionalHeaderID.kResourceInfo:
                //    break;
                case XexOptionalHeader.XexOptionalHeaderID.kBaseFileFormat:
                    baseFileFormat = new BaseFileFormat(header.data);
                    break;
                case XexOptionalHeader.XexOptionalHeaderID.kImportLibraries:
                    ReadImportLibraries(header.data);
                    break;
                default:
                    Console.WriteLine($"TODO: Handle option header case {header.headerID}");
                    break;
            }
        }
    }

    private void ReadStringTable(byte[] data, int start, int len) {
        if(stringTable == null)
            stringTable = new List<String>();
        int pos = start;
        String s = "";
        while(pos < start + len) {
            if (data[pos] != 0) {
                s += (char)data[pos];
            }
            else {
                while (data[pos + 1] == 0 && pos < start + len - 1) pos++;
                stringTable.Add(s);
                s = "";
            }
            pos++;
        }
    }

    private void ReadImportLibraries(byte[] data) {
        importLibs = new List<ImportLibrary>();
        BEBinaryReader br = new BEBinaryReader(new MemoryStream(data));
        uint stringSize = br.ReadUInt32();
        uint libCount = br.ReadUInt32();
        ReadStringTable(data, (int)br.BaseStream.Position, (int)stringSize);
        br.BaseStream.Seek(stringSize, SeekOrigin.Current);
        for(int i = 0; i < libCount; i++) {
            ImportLibrary lib = new ImportLibrary();
            br.BaseStream.Seek(0x24, SeekOrigin.Current);
            ushort nameIdx = br.ReadUInt16();
            ushort count = br.ReadUInt16();
            lib.name = stringTable[nameIdx];
            for(int j = 0; j < count; j++) {
                lib.records.Add((int)br.ReadUInt32());
            }
            importLibs.Add(lib);
        }
    }

    public void Read(BEBinaryReader br) {
        magic = br.ReadUInt32();
        Debug.Assert(magic == XEX2_MAGIC, "Did not find XEX2 header!");
        moduleFlags = br.ReadUInt32();
        peDataOffset = br.ReadUInt32();
        Console.WriteLine("PE Data Offset: 0x{0:X}", peDataOffset);
        reserved = br.ReadUInt32();
        securityInfoOffset = br.ReadUInt32();
        Console.WriteLine("Security Info Offset: 0x{0:X}", securityInfoOffset);
        // read the optional headers and process metadata that comes from them
        ReadOptionalHeaders(br);

        // load the loader info
        var curPos = br.BaseStream.Position;
        br.BaseStream.Seek(securityInfoOffset, SeekOrigin.Begin);
        loaderInfo.Read(br);
        DecryptFileKey();
        //br.BaseStream.Seek(curPos, SeekOrigin.Begin);

        // load the section info
        uint sectionCount = br.ReadUInt32();
        for(int i = 0; i < sectionCount; i++) {
            sections.Add(new XexSection().Read(br));
        }

        // if compression != 3, read the PE image
        if(baseFileFormat.compression != 3) {
            Console.WriteLine("Read the PE image");
            ReadPEImage(br);
            //File.WriteAllBytes("D:\\DC3 Debug\\Gamepad\\Debug\\jeff_release.exe", peImage);
        }
    }

    public void ReadPEImage(BEBinaryReader br) {
        int len = (int)br.BaseStream.Length - (int)peDataOffset;
        byte[] compressed = new byte[len];
        br.BaseStream.Seek(peDataOffset, SeekOrigin.Begin);
        for(int i = 0; i < len; i++) {
            compressed[i] = br.ReadByte();
        }
        Console.WriteLine("Encryption type: " + baseFileFormat.encryption);
        Console.WriteLine("Compression type: " + baseFileFormat.compression);
        switch (baseFileFormat.encryption) {
            case 0: break;
            case 1:
                compressed = AesHelper.DecryptAesCbcNoPadding(sessionKey, compressed);
                break;
            default:
                throw new Exception("Encryption type " + baseFileFormat.encryption + " not supported!");
        }
        peImage = new byte[loaderInfo.imageSize];
        uint posIn = 0, posOut = 0;
        switch(baseFileFormat.compression) {
            case 1:
                foreach(var bc in baseFileFormat.basics) {
                    for(int i = 0; i < bc.dataSize && posIn + i < compressed.Length; i++) {
                        peImage[posOut + i] = compressed[posIn + i];
                    }
                    posOut += bc.dataSize + bc.zeroSize;
                    posIn += bc.dataSize;
                }
                break;
            case 0:
            case 3:
                peImage = compressed;
                break;
            case 2:
                Console.WriteLine("TODO: implement compression case 2");
                break;
            default:
                throw new Exception("Compression type " + baseFileFormat.compression + " not supported!");
        }
    }
}