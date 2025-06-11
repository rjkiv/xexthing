using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

class ImportFunction {
    public uint address;
    public uint ordinal;
    public uint thunk;
}

class ImportLibrary {
    public String name;
    public List<int> records = new();
    public List<ImportFunction> functions = new();
}