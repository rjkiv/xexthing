using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

class XexMap {
    public class MapFileEntry {
        public string value;
        public uint vaddr;
        public string obj;

        public MapFileEntry(string value, uint vaddr, string obj) {
            this.value = value;
            this.vaddr = vaddr;
            this.obj = obj;
        }
    };

    public XexMap(string mapPath) {
        if (mapPath == "") {
            exists = false;
            return;
        }
        exists = true;
        entries = new List<MapFileEntry>();
        using StreamReader sr = new StreamReader(mapPath);
        string line;
        // we're skipping til we get to the line:
        // "  Address         Publics by Value              Rva+Base       Lib:Object"
        while (!(line = sr.ReadLine()).Contains("Publics by Value")) ;
        // skip forward one because it'll be blank
        line = sr.ReadLine();
        // a "" marks the end of the big map file entry list
        while((line = sr.ReadLine()) != "") {
            //Console.WriteLine(line);
            string[] parts = Regex.Split(line.Trim(), @"\s+");
            entries.Add(new MapFileEntry(parts[1], Convert.ToUInt32(parts[2], 16), parts[3]));
        }
    }

    public void Print() {
        foreach(var entry in entries) {
            Console.WriteLine($"0x{entry.vaddr:X}: {entry.value}");
        }
    }

    public bool exists;
    public List<MapFileEntry> entries;
}