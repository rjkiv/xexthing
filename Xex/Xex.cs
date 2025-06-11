using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Buffers.Binary;
using System.Threading.Tasks;

// documentation on the xex format here: https://free60.org/System-Software/Formats/XEX/
class Xex {

    public XexHeader xexHeader = new();

    public void Read(BEBinaryReader br) {
        xexHeader.Read(br);
    }

}