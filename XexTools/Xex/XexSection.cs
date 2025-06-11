using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

class XexSection {
    public byte type;
    public uint pageCount;
    public byte[] digest = new byte[20];
    public XexSection Read(BEBinaryReader br) {
        uint temp = br.ReadUInt32();
        type = (byte)(temp & 0xF);
        pageCount = temp >> 4;
        br.Read(digest, 0, 20);
        return this;
    }
}