using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

class BaseFileFormat {
    public class BasicCompression {
        public uint dataSize;
        public uint zeroSize;
        public BasicCompression Read(BEBinaryReader br) {
            dataSize = br.ReadUInt32();
            zeroSize = br.ReadUInt32();
            return this;
        }
    }

    public class NormalCompression {
        public uint windowSize;
        public uint blockSize;
        public byte[] blockHash = new byte[20];

        public NormalCompression Read(BEBinaryReader br) {
            windowSize = br.ReadUInt32();
            blockSize = br.ReadUInt32();
            br.Read(blockHash, 0, 20);
            return this;
        }
    }

    public ushort encryption;
    public ushort compression;
    public List<BasicCompression> basics;
    public NormalCompression normal;

    public BaseFileFormat(byte[] data) {
        BEBinaryReader br = new BEBinaryReader(new MemoryStream(data));
        encryption = br.ReadUInt16();
        compression = br.ReadUInt16();
        switch (compression) {
            case 1:
                basics = new List<BasicCompression>();
                int count = (data.Length / 8) - 1;
                for(int i = 0; i < count; i++) {
                    basics.Add(new BasicCompression().Read(br));
                }
                break;
            case 2:
            case 3:
                normal = new NormalCompression();
                normal.Read(br);
                break;
            default: break;
        }
    }
}