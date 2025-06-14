using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

class BEBinaryReader : BinaryReader {
    public BEBinaryReader(System.IO.Stream stream) : base(stream) { }

    public override ushort ReadUInt16() {
        var data = base.ReadBytes(2);
        Array.Reverse(data);
        return BitConverter.ToUInt16(data, 0);
    }
    public override uint ReadUInt32() {
        var data = base.ReadBytes(4);
        Array.Reverse(data);
        return BitConverter.ToUInt32(data, 0);
    }

    public uint PeekUInt32() {
        var curPos = BaseStream.Position;
        uint ret = ReadUInt32();
        BaseStream.Seek(curPos, SeekOrigin.Begin);
        return ret;
    }
}