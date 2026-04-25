<#
Rosemary - Cross-platform transparent tunneling platform
Copyright (C) 2026 Chokri Hammedi (blue0x1)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/
#>

Add-Type -TypeDefinition @"
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

#pragma warning disable 4014

delegate Task RmWriteFunc(byte[] data);
delegate Task<byte[]> RmReadFunc(int n);

public class RosemaryStreamBuf {
    readonly List<byte> _b = new List<byte>();
    bool _eof;
    readonly SemaphoreSlim _s = new SemaphoreSlim(0, int.MaxValue);
    public uint Id;
    public RosemaryStreamBuf(uint id) { Id = id; }
    public void Push(byte[] data, bool fin) {
        lock (_b) { if (data != null && data.Length > 0) _b.AddRange(data); if (fin) _eof = true; }
        _s.Release();
    }
    public async Task<byte[]> ReadN(int n, CancellationToken ct) {
        while (true) {
            lock (_b) {
                if (_b.Count >= n) { var r = _b.GetRange(0, n).ToArray(); _b.RemoveRange(0, n); return r; }
                if (_eof) throw new EndOfStreamException();
            }
            await _s.WaitAsync(ct);
        }
    }
}

public class RosemaryAgent {
    const byte FrData = 0, FrWin = 1, FrPing = 2, FrGoAway = 3;
    const ushort FSyn = 1, FAck = 2, FFin = 4, FRst = 8;
    const uint InitWin = 262144;

    static readonly int[] SweepPorts = {
        80,443,8080,8443,8000,8888,445,139,2049,548,
        22,3389,5900,5901,23,3306,5432,27017,6379,
        25,110,143,53,161,1883,5683,25565,27015,
        3000,5000,9000,135,137,8086,9090,
        49152,49153,49154,49155,49156,49157,49158,49159,49160,
        62078,62079,62080,62081,62082
    };

    public static bool Verbose = false;
    static void Log(string msg) { if (Verbose) Console.Error.WriteLine(msg); }

    readonly byte[] _key;
    CancellationTokenSource _cts;
    CancellationTokenSource _stopCts;
    ConcurrentDictionary<uint, RosemaryStreamBuf> _streams;
    BlockingCollection<RosemaryStreamBuf> _incoming;
    long _sid;
    string _agentId = "";
    readonly ConcurrentDictionary<string, TcpClient> _tcp = new ConcurrentDictionary<string, TcpClient>();
    readonly ConcurrentDictionary<string, UdpClient> _udp = new ConcurrentDictionary<string, UdpClient>();
    readonly ConcurrentDictionary<string, TcpListener> _lns = new ConcurrentDictionary<string, TcpListener>();
    readonly ConcurrentDictionary<string, UdpClient> _ulns = new ConcurrentDictionary<string, UdpClient>();
    readonly ConcurrentDictionary<string, CancellationTokenSource> _lcts = new ConcurrentDictionary<string, CancellationTokenSource>();
    readonly ConcurrentDictionary<string, TcpClient> _fwdConns = new ConcurrentDictionary<string, TcpClient>();
    readonly ConcurrentDictionary<string, TaskCompletionSource<bool>> _fwdAcks = new ConcurrentDictionary<string, TaskCompletionSource<bool>>();

    public RosemaryAgent(string keyB64) {
        string b = keyB64.Replace('-', '+').Replace('_', '/');
        b = b.PadRight((b.Length + 3) & ~3, '=');
        _key = Convert.FromBase64String(b);
        if (_key.Length != 32) throw new Exception("Key must be 32 bytes");
    }
    RosemaryAgent(byte[] key) { _key = (byte[])key.Clone(); }

    // ── AES-GCM (manual, .NET Framework compatible) ───────────────────────────

    static byte[] AesBlock(byte[] key, byte[] block) {
        using (var aes = Aes.Create()) {
            aes.Key = key;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            using (var enc = aes.CreateEncryptor()) {
                return enc.TransformFinalBlock(block, 0, 16);
            }
        }
    }

    static byte[] GfMul(byte[] X, byte[] Y) {
        var Z = new byte[16];
        var V = (byte[])Y.Clone();
        for (int i = 0; i < 128; i++) {
            if ((X[i >> 3] & (0x80 >> (i & 7))) != 0)
                for (int j = 0; j < 16; j++) Z[j] ^= V[j];
            bool lsb = (V[15] & 1) != 0;
            for (int j = 15; j > 0; j--)
                V[j] = (byte)((V[j] >> 1) | ((V[j - 1] & 1) << 7));
            V[0] >>= 1;
            if (lsb) V[0] ^= 0xE1;
        }
        return Z;
    }

    static byte[] GHash(byte[] H, byte[] data) {
        var Y = new byte[16];
        for (int i = 0; i < data.Length; i += 16) {
            int len = Math.Min(16, data.Length - i);
            for (int j = 0; j < len; j++) Y[j] ^= data[i + j];
            Y = GfMul(Y, H);
        }
        return Y;
    }

    static byte[] GcmComputeTag(byte[] key, byte[] nonce, byte[] ciphertext) {
        var H = AesBlock(key, new byte[16]);
        var J0 = new byte[16];
        Buffer.BlockCopy(nonce, 0, J0, 0, 12);
        J0[15] = 1;
        int cLen = ciphertext.Length;
        int padded = ((cLen + 15) / 16) * 16;
        var ghashIn = new byte[padded + 16];
        Buffer.BlockCopy(ciphertext, 0, ghashIn, 0, cLen);
        long bits = (long)cLen * 8;
        ghashIn[padded + 8]  = (byte)(bits >> 56);
        ghashIn[padded + 9]  = (byte)(bits >> 48);
        ghashIn[padded + 10] = (byte)(bits >> 40);
        ghashIn[padded + 11] = (byte)(bits >> 32);
        ghashIn[padded + 12] = (byte)(bits >> 24);
        ghashIn[padded + 13] = (byte)(bits >> 16);
        ghashIn[padded + 14] = (byte)(bits >> 8);
        ghashIn[padded + 15] = (byte)bits;
        var S = GHash(H, ghashIn);
        var EJ0 = AesBlock(key, J0);
        var tag = new byte[16];
        for (int i = 0; i < 16; i++) tag[i] = (byte)(S[i] ^ EJ0[i]);
        return tag;
    }

    static byte[] GcmCtr(byte[] key, byte[] nonce, byte[] data) {
        var ctr = new byte[16];
        Buffer.BlockCopy(nonce, 0, ctr, 0, 12);
        ctr[15] = 2;
        var result = new byte[data.Length];
        for (int i = 0; i < data.Length; i += 16) {
            var ks = AesBlock(key, ctr);
            int len = Math.Min(16, data.Length - i);
            for (int j = 0; j < len; j++) result[i + j] = (byte)(data[i + j] ^ ks[j]);
            for (int j = 15; j >= 12; j--) { if (++ctr[j] != 0) break; }
        }
        return result;
    }

    byte[] Enc(byte[] p) {
        var n = new byte[12];
        using (var rng = new RNGCryptoServiceProvider()) { rng.GetBytes(n); }
        var c = GcmCtr(_key, n, p);
        var t = GcmComputeTag(_key, n, c);
        var r = new byte[12 + p.Length + 16];
        Buffer.BlockCopy(n, 0, r, 0, 12);
        Buffer.BlockCopy(c, 0, r, 12, p.Length);
        Buffer.BlockCopy(t, 0, r, 12 + p.Length, 16);
        return r;
    }

    byte[] Dec(byte[] d) {
        var nonce = new byte[12];
        Buffer.BlockCopy(d, 0, nonce, 0, 12);
        int cLen = d.Length - 28;
        var ciphertext = new byte[cLen];
        Buffer.BlockCopy(d, 12, ciphertext, 0, cLen);
        var tag = new byte[16];
        Buffer.BlockCopy(d, 12 + cLen, tag, 0, 16);
        var expected = GcmComputeTag(_key, nonce, ciphertext);
        int diff = 0;
        for (int i = 0; i < 16; i++) diff |= tag[i] ^ expected[i];
        if (diff != 0) throw new Exception("AES-GCM auth failed");
        return GcmCtr(_key, nonce, ciphertext);
    }

    // ── Compression ───────────────────────────────────────────────────────────

    byte[] Deflate(byte[] d) {
        var ms = new MemoryStream();
        using (var s = new DeflateStream(ms, CompressionLevel.Fastest)) { s.Write(d, 0, d.Length); }
        return ms.ToArray();
    }

    byte[] Inflate(byte[] d) {
        using (var s = new DeflateStream(new MemoryStream(d), CompressionMode.Decompress)) {
            var ms = new MemoryStream(); s.CopyTo(ms); return ms.ToArray();
        }
    }

    // ── Framing ───────────────────────────────────────────────────────────────

    byte[] Hdr(byte type, ushort flags, uint id, uint len) {
        return new byte[] {
            0, type, (byte)(flags >> 8), (byte)flags,
            (byte)(id >> 24), (byte)(id >> 16), (byte)(id >> 8), (byte)id,
            (byte)(len >> 24), (byte)(len >> 16), (byte)(len >> 8), (byte)len
        };
    }

    // ── JSON helpers (no external library) ───────────────────────────────────

    static string JStr(string json, string key, string def) {
        var m = Regex.Match(json, "\"" + Regex.Escape(key) + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
        if (!m.Success) return def;
        return m.Groups[1].Value
            .Replace("\\\"", "\"").Replace("\\\\", "\\")
            .Replace("\\n", "\n").Replace("\\r", "\r").Replace("\\t", "\t");
    }
    static string JStr(string json, string key) { return JStr(json, key, ""); }

    static int JInt(string json, string key, int def) {
        var m = Regex.Match(json, "\"" + Regex.Escape(key) + "\"\\s*:\\s*(-?\\d+)");
        if (!m.Success) return def;
        int v; return int.TryParse(m.Groups[1].Value, out v) ? v : def;
    }
    static int JInt(string json, string key) { return JInt(json, key, 0); }

    static bool JBool(string json, string key) {
        var m = Regex.Match(json, "\"" + Regex.Escape(key) + "\"\\s*:\\s*(true|false)");
        return m.Success && m.Groups[1].Value == "true";
    }

    static byte[] JB64(string json, string key) {
        var s = JStr(json, key);
        if (s == "") return null;
        try { return Convert.FromBase64String(s); } catch { return null; }
    }

    static string JObj(string json, string key) {
        var m = Regex.Match(json, "\"" + Regex.Escape(key) + "\"\\s*:\\s*");
        if (!m.Success) return "{}";
        int start = m.Index + m.Length;
        if (start >= json.Length || json[start] != '{') return "{}";
        int depth = 0; bool inStr = false;
        for (int i = start; i < json.Length; i++) {
            char c = json[i];
            if (inStr) { if (c == '\\') i++; else if (c == '"') inStr = false; }
            else { if (c == '"') inStr = true; else if (c == '{') depth++; else if (c == '}') { depth--; if (depth == 0) return json.Substring(start, i - start + 1); } }
        }
        return "{}";
    }

    static string JRaw(string json, string key) {
        var m = Regex.Match(json, "\"" + Regex.Escape(key) + "\"\\s*:\\s*");
        if (!m.Success) return "null";
        int start = m.Index + m.Length;
        if (start >= json.Length) return "null";
        char first = json[start];
        if (first == '{' || first == '[') {
            char open = first; char close = first == '{' ? '}' : ']';
            int depth = 0; bool inStr = false;
            for (int i = start; i < json.Length; i++) {
                char c = json[i];
                if (inStr) { if (c == '\\') i++; else if (c == '"') inStr = false; }
                else { if (c == '"') inStr = true; else if (c == open) depth++; else if (c == close) { depth--; if (depth == 0) return json.Substring(start, i - start + 1); } }
            }
            return "null";
        }
        int end = start;
        if (first == '"') {
            end = start + 1;
            while (end < json.Length) { if (json[end] == '\\') { end += 2; continue; } if (json[end] == '"') { end++; break; } end++; }
        } else {
            while (end < json.Length && json[end] != ',' && json[end] != '}' && json[end] != ']' && json[end] != ' ' && json[end] != '\n' && json[end] != '\r') end++;
        }
        return json.Substring(start, end - start);
    }

    // ── Misc helpers ──────────────────────────────────────────────────────────

    string JE(string s) {
        if (s == null) return "";
        return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "\\r").Replace("\n", "\\n").Replace("\t", "\\t");
    }

    static byte[] Slice(byte[] src, int off, int len) { var r = new byte[len]; Buffer.BlockCopy(src, off, r, 0, len); return r; }

    string GetHostname() { try { return Dns.GetHostName(); } catch { return "unknown"; } }
    string GetUser() { try { return System.Security.Principal.WindowsIdentity.GetCurrent().Name; } catch { return ""; } }
    bool HasInternet() { try { using (var c = new TcpClient()) { c.Connect("8.8.8.8", 53); return true; } } catch { return false; } }

    List<string> GetSubnets() {
        var seen = new HashSet<string>();
        foreach (var iface in NetworkInterface.GetAllNetworkInterfaces()) {
            if (iface.OperationalStatus != OperationalStatus.Up) continue;
            foreach (var ua in iface.GetIPProperties().UnicastAddresses) {
                if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                var ip = ua.Address.GetAddressBytes();
                if (ua.IPv4Mask == null) continue;
                var mask = ua.IPv4Mask.GetAddressBytes();
                if (mask.Length != 4) continue;
                var net = new byte[4]; for (int i = 0; i < 4; i++) net[i] = (byte)(ip[i] & mask[i]);
                if (net[0] == 127 || net[0] >= 224) continue;
                int ones = 0; foreach (var bv in mask) for (int v = bv; v != 0; v >>= 1) ones += v & 1;
                if (ones == 32 || ones == 0) continue;
                seen.Add(net[0] + "." + net[1] + "." + net[2] + "." + net[3] + "/" + ones);
            }
        }
        try {
            var psi = new ProcessStartInfo("route.exe", "print -4") { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using (var proc = Process.Start(psi)) {
                string outp = proc.StandardOutput.ReadToEnd(); proc.WaitForExit();
                foreach (var line in outp.Split('\n')) {
                    var f = line.Trim().Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    if (f.Length < 2) continue;
                    IPAddress ipA, maskA;
                    if (!IPAddress.TryParse(f[0], out ipA) || !IPAddress.TryParse(f[1], out maskA)) continue;
                    var ipB = ipA.GetAddressBytes(); var maskB = maskA.GetAddressBytes();
                    if (ipB.Length != 4 || maskB.Length != 4) continue;
                    var netB = new byte[4]; for (int i = 0; i < 4; i++) netB[i] = (byte)(ipB[i] & maskB[i]);
                    if (netB[0] == 0 && netB[1] == 0 && netB[2] == 0 && netB[3] == 0) continue;
                    if (netB[0] == 127 || netB[0] >= 224) continue;
                    int ones = 0; foreach (var bv in maskB) for (int v = bv; v != 0; v >>= 1) ones += v & 1;
                    if (ones == 32 || ones == 0) continue;
                    seen.Add(netB[0] + "." + netB[1] + "." + netB[2] + "." + netB[3] + "/" + ones);
                }
            }
        } catch { }
        return seen.ToList();
    }

    // ── DNS helpers ───────────────────────────────────────────────────────────

    byte[] BuildDnsQuery(string domain, ushort qtype) {
        var ms = new MemoryStream();
        var id = new byte[2]; using (var rng = new RNGCryptoServiceProvider()) { rng.GetBytes(id); }
        ms.Write(id, 0, 2); ms.Write(new byte[] { 0x01, 0x00 }, 0, 2);
        ms.Write(new byte[] { 0x00, 0x01 }, 0, 2); ms.Write(new byte[6], 0, 6);
        foreach (var label in domain.TrimEnd('.').Split('.')) { ms.WriteByte((byte)label.Length); ms.Write(Encoding.ASCII.GetBytes(label), 0, label.Length); }
        ms.WriteByte(0); ms.Write(new byte[] { (byte)(qtype >> 8), (byte)qtype }, 0, 2); ms.Write(new byte[] { 0x00, 0x01 }, 0, 2);
        return ms.ToArray();
    }

    int SkipDnsName(byte[] r, int p) { while (p < r.Length) { if (r[p] == 0) return p + 1; if ((r[p] & 0xC0) == 0xC0) return p + 2; p += r[p] + 1; } return p; }

    List<string> ParseDnsAnswers(byte[] resp, ushort qtype) {
        var results = new List<string>();
        if (resp.Length < 12) return results;
        int ancount = (resp[6] << 8) | resp[7];
        int pos = SkipDnsName(resp, 12) + 4;
        for (int i = 0; i < ancount && pos + 10 < resp.Length; i++) {
            pos = SkipDnsName(resp, pos);
            if (pos + 10 > resp.Length) break;
            ushort rtype = (ushort)((resp[pos] << 8) | resp[pos + 1]); pos += 4; pos += 4;
            int rdlen = (resp[pos] << 8) | resp[pos + 1]; pos += 2;
            if (pos + rdlen > resp.Length) break;
            if (rtype == 1 && rdlen == 4 && qtype == 1) results.Add(resp[pos] + "." + resp[pos + 1] + "." + resp[pos + 2] + "." + resp[pos + 3]);
            else if (rtype == 28 && rdlen == 16 && qtype == 28) results.Add(new IPAddress(Slice(resp, pos, 16)).ToString());
            pos += rdlen;
        }
        return results;
    }

    async Task<List<string>> QueryPublicDns(string domain, int qtype) {
        foreach (var server in new string[] { "8.8.8.8", "1.1.1.1", "8.8.4.4" }) {
            try {
                var query = BuildDnsQuery(domain, (ushort)qtype);
                using (var udp = new UdpClient()) {
                    udp.Client.ReceiveTimeout = 3000; udp.Connect(server, 53);
                    await udp.SendAsync(query, query.Length);
                    var ep = new IPEndPoint(IPAddress.Any, 0);
                    byte[] resp; try { resp = udp.Receive(ref ep); } catch { continue; }
                    var ans = ParseDnsAnswers(resp, (ushort)qtype);
                    if (ans.Count > 0) return ans;
                }
            } catch { }
        }
        return new List<string>();
    }

    // ── Protocol ──────────────────────────────────────────────────────────────

    async Task SendMsg(RmWriteFunc write, string type, string payload, string origId) {
        string orig = origId.Length > 0 ? ",\"original_agent_id\":\"" + origId + "\"" : "";
        string json = "{\"type\":\"" + type + "\",\"payload\":" + payload + orig + "}";
        var enc = Enc(Encoding.UTF8.GetBytes(json));
        var msg = new byte[4 + enc.Length];
        msg[0] = (byte)(enc.Length >> 24); msg[1] = (byte)(enc.Length >> 16);
        msg[2] = (byte)(enc.Length >> 8); msg[3] = (byte)enc.Length;
        Buffer.BlockCopy(enc, 0, msg, 4, enc.Length);
        uint sid = (uint)(Interlocked.Add(ref _sid, 2) - 2);
        await write(Hdr(FrWin, FSyn, sid, InitWin));
        var fr = new byte[12 + msg.Length];
        Buffer.BlockCopy(Hdr(FrData, FFin, sid, (uint)msg.Length), 0, fr, 0, 12);
        Buffer.BlockCopy(msg, 0, fr, 12, msg.Length);
        await write(fr);
    }

    async Task YamuxLoop(RmReadFunc readN, RmWriteFunc write) {
        try {
            while (!_cts.IsCancellationRequested) {
                var hdr = await readN(12);
                byte ft = hdr[1];
                ushort fl = (ushort)((hdr[2] << 8) | hdr[3]);
                uint sid = ((uint)hdr[4] << 24) | ((uint)hdr[5] << 16) | ((uint)hdr[6] << 8) | hdr[7];
                uint flen = ((uint)hdr[8] << 24) | ((uint)hdr[9] << 16) | ((uint)hdr[10] << 8) | hdr[11];
                if (ft == FrData) {
                    var data = flen > 0 ? await readN((int)flen) : new byte[0];
                    bool fin = (fl & FFin) != 0 || (fl & FRst) != 0;
                    RosemaryStreamBuf sb;
                    if (_streams.TryGetValue(sid, out sb)) { sb.Push(data, fin); if (fin) { RosemaryStreamBuf ig; _streams.TryRemove(sid, out ig); } }
                } else if (ft == FrWin) {
                    if ((fl & FSyn) != 0 && (fl & FAck) == 0) {
                        var sb = new RosemaryStreamBuf(sid);
                        _streams[sid] = sb; _incoming.TryAdd(sb);
                        await write(Hdr(FrWin, FAck, sid, InitWin));
                    }
                } else if (ft == FrPing && (fl & FAck) == 0) {
                    await write(Hdr(FrPing, FAck, 0, flen));
                } else if (ft == FrGoAway) { Log("[rm] server sent go-away, session closing"); break; }
            }
        } catch (Exception ex) {
            if (!_cts.IsCancellationRequested) Log("[rm] yamux read error: " + ex.GetType().Name + ": " + ex.Message);
        }
        _incoming.CompleteAdding();
    }

    async Task HandleConnect(RmWriteFunc write, string p) {
        string cid = JStr(p, "conn_id"), host = JStr(p, "target_host"), proto = JStr(p, "protocol", "tcp");
        int port = JInt(p, "target_port");
        Exception connEx = null;
        try {
            if (proto == "udp") {
                var u = new UdpClient(); u.Connect(host, port); _udp[cid] = u;
                await SendMsg(write, "connect_response", "{\"conn_id\":\"" + cid + "\",\"success\":true}", _agentId);
                Task.Run(async () => {
                    try { while (!_cts.IsCancellationRequested) { var r = await u.ReceiveAsync(); await SendMsg(write, "data", "{\"conn_id\":\"" + cid + "\",\"data\":\"" + Convert.ToBase64String(r.Buffer) + "\"}", _agentId); } } catch { }
                    UdpClient ig; _udp.TryRemove(cid, out ig);
                    try { await SendMsg(write, "data", "{\"conn_id\":\"" + cid + "\",\"close\":true}", _agentId); } catch { }
                });
            } else {
                var tc = new TcpClient(); await tc.ConnectAsync(host, port); _tcp[cid] = tc;
                await SendMsg(write, "connect_response", "{\"conn_id\":\"" + cid + "\",\"success\":true}", _agentId);
                Task.Run(async () => {
                    try {
                        var ns = tc.GetStream(); var buf = new byte[65536]; int n;
                        while ((n = await ns.ReadAsync(buf, 0, buf.Length)) > 0) {
                            var chunk = new byte[n]; Buffer.BlockCopy(buf, 0, chunk, 0, n);
                            bool z = n > 256; var pl = z ? Deflate(chunk) : chunk;
                            if (z && pl.Length >= chunk.Length) { pl = chunk; z = false; }
                            string zf = z ? ",\"z\":true" : "";
                            await SendMsg(write, "data", "{\"conn_id\":\"" + cid + "\",\"data\":\"" + Convert.ToBase64String(pl) + "\"" + zf + "}", _agentId);
                        }
                    } catch { }
                    TcpClient ig; _tcp.TryRemove(cid, out ig);
                    try { await SendMsg(write, "data", "{\"conn_id\":\"" + cid + "\",\"close\":true}", _agentId); } catch { }
                });
            }
        } catch (Exception ex) { connEx = ex; }
        if (connEx != null)
            await SendMsg(write, "connect_response", "{\"conn_id\":\"" + cid + "\",\"success\":false,\"error\":\"" + JE(connEx.Message) + "\"}", _agentId);
    }

    void HandleData(string p) {
        string cid = JStr(p, "conn_id"); bool close = JBool(p, "close");
        byte[] data = JB64(p, "data"); if (data != null && JBool(p, "z")) data = Inflate(data);
        TcpClient tc; UdpClient uc;
        if (_tcp.TryGetValue(cid, out tc)) {
            if (close) { try { tc.Close(); } catch { } TcpClient ig; _tcp.TryRemove(cid, out ig); }
            else if (data != null) try { tc.GetStream().Write(data, 0, data.Length); } catch { }
        } else if (_udp.TryGetValue(cid, out uc)) {
            if (close) { try { uc.Close(); } catch { } UdpClient ig; _udp.TryRemove(cid, out ig); }
            else if (data != null) try { uc.Send(data, data.Length); } catch { }
        }
    }

    void HandleFwdAck(string p) {
        string cid = JStr(p, "conn_id"); TaskCompletionSource<bool> tcs;
        if (_fwdAcks.TryGetValue(cid, out tcs)) tcs.TrySetResult(JBool(p, "success"));
    }

    void HandleFwdData(string p) {
        string cid = JStr(p, "conn_id"); bool close = JBool(p, "close");
        byte[] data = JB64(p, "data"); if (data != null && JBool(p, "z")) data = Inflate(data);
        TcpClient tc;
        if (_fwdConns.TryGetValue(cid, out tc)) {
            if (close) { try { tc.Close(); } catch { } TcpClient ig; _fwdConns.TryRemove(cid, out ig); }
            else if (data != null) try { tc.GetStream().Write(data, 0, data.Length); } catch { }
        }
    }

    async Task HandlePortScan(RmWriteFunc write, string p) {
        string target = JStr(p, "target"), ports = JStr(p, "ports"), proto = JStr(p, "proto", "tcp");
        bool udp = proto == "udp";
        var allPorts = new List<int>();
        foreach (var tok in ports.Split(',')) {
            var t = tok.Trim();
            if (t.Contains('-')) { var pts = t.Split('-'); int s, e; if (int.TryParse(pts[0].Trim(), out s) && int.TryParse(pts[1].Trim(), out e)) for (int i = s; i <= e; i++) allPorts.Add(i); }
            else { int pp; if (int.TryParse(t, out pp)) allPorts.Add(pp); }
        }
        int w = allPorts.Count > 1000 ? 300 : allPorts.Count > 100 ? 150 : 50;
        w = Math.Min(w, allPorts.Count); if (w < 1) w = 1;
        var sem = new SemaphoreSlim(w, w);
        var results = new ConcurrentBag<int>();
        var tasks = allPorts.Select(async port => {
            await sem.WaitAsync();
            try {
                if (udp) {
                    try { using (var u = new UdpClient()) { u.Connect(target, port); u.Client.ReceiveTimeout = 800; u.Send(new byte[] { 0 }, 1); var ep = new IPEndPoint(IPAddress.Any, 0); try { u.Receive(ref ep); results.Add(port); } catch { } } } catch { }
                } else {
                    try { using (var tc = new TcpClient()) { var t2 = tc.ConnectAsync(target, port); if (await Task.WhenAny(t2, Task.Delay(800)) == t2 && tc.Connected) results.Add(port); } } catch { }
                }
            } finally { sem.Release(); }
        });
        await Task.WhenAll(tasks);
        var sorted = results.OrderBy(x => x).ToList();
        var rj = "[" + string.Join(",", sorted.Select(x => "{\"port\":" + x + ",\"open\":true}")) + "]";
        await SendMsg(write, "port-scan-response", "{\"target\":\"" + JE(target) + "\",\"proto\":\"" + proto + "\",\"results\":" + rj + ",\"done\":true}", _agentId);
    }

    async Task HandlePingSweep(RmWriteFunc write, string p) {
        string subnet = JStr(p, "subnet"); int tms = JInt(p, "timeout_ms", 300); int workers = JInt(p, "workers", 50);
        var parts = subnet.Split('/'); if (parts.Length != 2) return;
        var baseBytes = IPAddress.Parse(parts[0]).GetAddressBytes();
        int prefix = int.Parse(parts[1]);
        uint baseIp = ((uint)baseBytes[0] << 24) | ((uint)baseBytes[1] << 16) | ((uint)baseBytes[2] << 8) | baseBytes[3];
        uint maskBits = prefix == 0 ? 0 : ~((1u << (32 - prefix)) - 1);
        uint netAddr = baseIp & maskBits, bcast = netAddr | ~maskBits;
        var ips = new List<string>();
        for (uint i = netAddr + 1; i < bcast; i++) ips.Add(((i >> 24) & 0xFF) + "." + ((i >> 16) & 0xFF) + "." + ((i >> 8) & 0xFF) + "." + (i & 0xFF));
        int ww = Math.Min(workers < 1 ? 50 : workers, ips.Count); if (ww < 1) ww = 1;
        var sem = new SemaphoreSlim(ww, ww);
        var alive = new ConcurrentBag<string>();
        var rtts = new ConcurrentDictionary<string, long>();
        var tasks = ips.Select(async ip => {
            await sem.WaitAsync();
            try {
                var sw = Stopwatch.StartNew(); bool ok = false;
                foreach (int port in SweepPorts) {
                    try { using (var tc = new TcpClient()) { var t2 = tc.ConnectAsync(ip, port); if (await Task.WhenAny(t2, Task.Delay(tms)) == t2 && tc.Connected) { ok = true; break; } } } catch { }
                }
                sw.Stop(); if (ok) { alive.Add(ip); rtts[ip] = sw.ElapsedMilliseconds; }
            } finally { sem.Release(); }
        });
        await Task.WhenAll(tasks);
        var sorted = alive.OrderBy(x => { var o = x.Split('.').Select(int.Parse).ToArray(); return ((long)o[0] << 24) | ((long)o[1] << 16) | ((long)o[2] << 8) | (long)(uint)o[3]; }).ToList();
        var rj = "[" + string.Join(",", sorted.Select(x => "{\"ip\":\"" + x + "\",\"rtt\":" + rtts[x] + "}")) + "]";
        await SendMsg(write, "ping-sweep-response", "{\"subnet\":\"" + JE(subnet) + "\",\"results\":" + rj + "}", _agentId);
    }

    static bool IsValidPingTarget(string t) {
        return !string.IsNullOrEmpty(t) && t.Length <= 253 && Regex.IsMatch(t, @"^[a-zA-Z0-9.\-:]+$");
    }

    async Task HandleICMP(RmWriteFunc write, string p) {
        string target = JStr(p, "target"); int count = JInt(p, "count", 1); int tms = JInt(p, "timeout_ms", 1000);
        if (count < 1) count = 1;
        if (!IsValidPingTarget(target)) {
            for (int i = 1; i <= count; i++)
                await SendMsg(write, "icmp-response", "{\"target\":\"" + JE(target) + "\",\"seq\":" + i + ",\"success\":false,\"rtt_ms\":0,\"error\":\"invalid target\"}", _agentId);
            return;
        }
        for (int i = 1; i <= count; i++) {
            bool ok = false; double rttMs = 0; string errStr = "";
            try {
                using (var ping = new Ping()) {
                    var reply = await ping.SendPingAsync(target, tms);
                    ok = reply.Status == IPStatus.Success; rttMs = ok ? reply.RoundtripTime : 0;
                    if (!ok) errStr = reply.Status.ToString();
                }
            } catch {
                try {
                    var psi2 = new ProcessStartInfo("ping.exe", "-n 1 -w " + tms + " " + target) { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                    using (var proc2 = Process.Start(psi2)) {
                        string o2 = proc2.StandardOutput.ReadToEnd(); proc2.WaitForExit();
                        ok = o2.Contains("Reply from") || o2.Contains("TTL=");
                        if (ok) { var m2 = Regex.Match(o2, @"time[=<](\d+)ms"); rttMs = m2.Success ? double.Parse(m2.Groups[1].Value) : 0; }
                        else errStr = "host unreachable";
                    }
                } catch { errStr = "host unreachable"; }
            }
            string err = ok ? "" : (",\"error\":\"" + JE(errStr) + "\"");
            await SendMsg(write, "icmp-response", "{\"target\":\"" + JE(target) + "\",\"seq\":" + i + ",\"success\":" + (ok ? "true" : "false") + ",\"rtt_ms\":" + rttMs + err + "}", _agentId);
        }
    }

    async Task HandleICMPProxy(RmWriteFunc write, string p) {
        string cid = JStr(p, "conn_id"), target = JStr(p, "target"); int tms = JInt(p, "timeout_ms", 1000);
        bool ok = false; double rttMs = 0; string errStr = "";
        if (!IsValidPingTarget(target)) {
            await SendMsg(write, "icmp_proxy_response", "{\"conn_id\":\"" + cid + "\",\"success\":false,\"rtt_ms\":0,\"error\":\"invalid target\"}", _agentId);
            return;
        }
        try {
            using (var ping = new Ping()) {
                var reply = await ping.SendPingAsync(target, tms);
                ok = reply.Status == IPStatus.Success; rttMs = ok ? reply.RoundtripTime : 0;
                if (!ok) errStr = reply.Status.ToString();
            }
        } catch {
            try {
                var psi2 = new ProcessStartInfo("ping.exe", "-n 1 -w " + tms + " " + target) { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using (var proc2 = Process.Start(psi2)) {
                    string o2 = proc2.StandardOutput.ReadToEnd(); proc2.WaitForExit();
                    ok = o2.Contains("Reply from") || o2.Contains("TTL=");
                    if (ok) { var m2 = Regex.Match(o2, @"time[=<](\d+)ms"); rttMs = m2.Success ? double.Parse(m2.Groups[1].Value) : 0; }
                    else errStr = "host unreachable";
                }
            } catch { errStr = "host unreachable"; }
        }
        string err = ok ? "" : (",\"error\":\"" + JE(errStr) + "\"");
        await SendMsg(write, "icmp_proxy_response", "{\"conn_id\":\"" + cid + "\",\"success\":" + (ok ? "true" : "false") + ",\"rtt_ms\":" + rttMs + err + "}", _agentId);
    }

    async Task HandleDNS(RmWriteFunc write, string p) {
        uint reqId = (uint)JInt(p, "request_id"); string domain = JStr(p, "domain").TrimEnd('.'); int qtype = JInt(p, "qtype", 1);
        var answers = new List<string>();
        try {
            foreach (var ip in Dns.GetHostAddresses(domain)) {
                if (qtype == 1 && ip.AddressFamily == AddressFamily.InterNetwork) answers.Add("{\"name\":\"" + JE(domain) + "\",\"type\":1,\"ttl\":300,\"data\":\"" + ip + "\"}");
                else if (qtype == 28 && ip.AddressFamily == AddressFamily.InterNetworkV6) answers.Add("{\"name\":\"" + JE(domain) + "\",\"type\":28,\"ttl\":300,\"data\":\"" + ip + "\"}");
            }
        } catch { }
        if (answers.Count == 0) { foreach (var ip in await QueryPublicDns(domain, qtype)) answers.Add("{\"name\":\"" + JE(domain) + "\",\"type\":" + (qtype == 28 ? 28 : 1) + ",\"ttl\":300,\"data\":\"" + ip + "\"}"); }
        int rcode = answers.Count == 0 ? 3 : 0;
        await SendMsg(write, "dns_response", "{\"request_id\":" + reqId + ",\"answers\":[" + string.Join(",", answers) + "],\"rcode\":" + rcode + "}", _agentId);
    }

    Task HandleStartListener(string p) {
        string lid = JStr(p, "listener_id"); int lport = JInt(p, "agent_listen_port");
        string dhost = JStr(p, "destination_host"); int dport = JInt(p, "destination_port"); string proto = JStr(p, "protocol", "tcp");
        var lcts = new CancellationTokenSource(); _lcts[lid] = lcts;
        if (proto == "udp") {
            var pc = new UdpClient(lport); _ulns[lid] = pc;
            Task.Run(async () => {
                var sessions = new ConcurrentDictionary<string, UdpClient>();
                try {
                    while (!lcts.Token.IsCancellationRequested) {
                        var r = await pc.ReceiveAsync(); string k = r.RemoteEndPoint.ToString();
                        UdpClient out2;
                        if (!sessions.TryGetValue(k, out out2)) {
                            out2 = new UdpClient(); out2.Connect(dhost, dport); sessions[k] = out2;
                            var ep = r.RemoteEndPoint;
                            Task.Run(async () => { try { while (true) { var rr = await out2.ReceiveAsync(); pc.Send(rr.Buffer, rr.Buffer.Length, ep); } } catch { } });
                        }
                        out2.Send(r.Buffer, r.Buffer.Length);
                    }
                } catch { }
                pc.Close(); UdpClient ig; _ulns.TryRemove(lid, out ig);
            }, lcts.Token);
        } else {
            var ln = new TcpListener(IPAddress.Any, lport); ln.Start(); _lns[lid] = ln;
            Task.Run(async () => {
                try {
                    while (!lcts.Token.IsCancellationRequested) {
                        var client = await ln.AcceptTcpClientAsync();
                        Task.Run(async () => {
                            try { using (var dest = new TcpClient()) { await dest.ConnectAsync(dhost, dport); var t1 = client.GetStream().CopyToAsync(dest.GetStream()); var t2 = dest.GetStream().CopyToAsync(client.GetStream()); await Task.WhenAny(t1, t2); } } catch { }
                            finally { if (client != null) client.Close(); }
                        });
                    }
                } catch { }
                ln.Stop(); TcpListener ig; _lns.TryRemove(lid, out ig);
            }, lcts.Token);
        }
        return Task.CompletedTask;
    }

    void HandleStopListener(string p) {
        string lid = JStr(p, "listener_id");
        CancellationTokenSource lcts; if (_lcts.TryRemove(lid, out lcts)) lcts.Cancel();
        TcpListener ln; if (_lns.TryRemove(lid, out ln)) try { ln.Stop(); } catch { }
        UdpClient uc; if (_ulns.TryRemove(lid, out uc)) try { uc.Close(); } catch { }
    }

    async Task RunSession(RmReadFunc readN, RmWriteFunc write) {
        _streams = new ConcurrentDictionary<uint, RosemaryStreamBuf>();
        _incoming = new BlockingCollection<RosemaryStreamBuf>(256);
        Interlocked.Exchange(ref _sid, 1);
        _agentId = "";
        Task.Run(() => YamuxLoop(readN, write));
        var subnets = GetSubnets();
        string regPay = "{\"subnets\":[" + string.Join(",", subnets.Select(s => "\"" + JE(s) + "\"")) + "],\"os\":\"windows\",\"hostname\":\"" + JE(GetHostname()) + "\",\"username\":\"" + JE(GetUser()) + "\",\"has_internet\":" + (HasInternet() ? "true" : "false") + "}";
        await SendMsg(write, "register", regPay, "");
        Task.Run(async () => {
            while (!_cts.IsCancellationRequested) {
                try { await Task.Delay(10000, _cts.Token); } catch { break; }
                if (_agentId.Length > 0) try { await SendMsg(write, "heartbeat", "{}", _agentId); } catch { break; }
            }
        });
        while (!_cts.IsCancellationRequested) {
            RosemaryStreamBuf sb;
            try { sb = _incoming.Take(_cts.Token); } catch (InvalidOperationException) { break; } catch (OperationCanceledException) { break; }
            Task.Run(async () => {
                try {
                    var lb = await sb.ReadN(4, _cts.Token);
                    int ml = (lb[0] << 24) | (lb[1] << 16) | (lb[2] << 8) | lb[3];
                    var enc = await sb.ReadN(ml, _cts.Token);
                    var plain = Encoding.UTF8.GetString(Dec(enc));
                    string type = JStr(plain, "type");
                    string payload = JObj(plain, "payload");
                    switch (type) {
                        case "register_ok": _agentId = JStr(payload, "id"); break;
                        case "reconnect": _cts.Cancel(); break;
                        case "disconnect": await Task.Delay(400); Environment.Exit(0); break;
                        case "connect": await HandleConnect(write, payload); break;
                        case "data": HandleData(payload); break;
                        case "port-scan-request": await HandlePortScan(write, payload); break;
                        case "ping-sweep-request": await HandlePingSweep(write, payload); break;
                        case "icmp-request": await HandleICMP(write, payload); break;
                        case "icmp_proxy": await HandleICMPProxy(write, payload); break;
                        case "dns_request": await HandleDNS(write, payload); break;
                        case "start-agent-listener": await HandleStartListener(payload); break;
                        case "stop-agent-listener": HandleStopListener(payload); break;
                        case "agent_fwd_ack": HandleFwdAck(payload); break;
                        case "agent_fwd_data": HandleFwdData(payload); break;
                    }
                } catch { }
            });
        }
    }

    async Task<byte[]> WsReadMsg(ClientWebSocket ws) {
        var ms = new MemoryStream(); var buf = new byte[65536]; WebSocketReceiveResult r;
        do { r = await ws.ReceiveAsync(new ArraySegment<byte>(buf), _cts.Token); if (r.MessageType == WebSocketMessageType.Close) return null; ms.Write(buf, 0, r.Count); } while (!r.EndOfMessage);
        return ms.ToArray();
    }

    public async Task RunWS(string addr, string wsPath) {
        int backoff = 5000;
        while (!_stopCts.IsCancellationRequested) {
            _cts = new CancellationTokenSource();
            try {
                var ws = new ClientWebSocket();
                Log("[rm] connecting ws://" + addr + wsPath);
                await ws.ConnectAsync(new Uri("ws://" + addr + wsPath), _cts.Token);
                Log("[rm] connected, waiting for challenge...");
                var chalRaw = await WsReadMsg(ws); if (chalRaw == null) throw new Exception("no challenge");
                Log("[rm] got challenge " + chalRaw.Length + "b, authenticating...");
                var chalPlain = Encoding.UTF8.GetString(Dec(chalRaw));
                string payRaw = JRaw(chalPlain, "payload");
                var respEnc = Enc(Encoding.UTF8.GetBytes("{\"type\":\"auth_response\",\"payload\":" + payRaw + "}"));
                await ws.SendAsync(new ArraySegment<byte>(respEnc), WebSocketMessageType.Binary, true, _cts.Token);
                Log("[rm] auth sent, running session...");
                backoff = 5000;
                var wsMu = new SemaphoreSlim(1, 1);
                var wsBuf = new List<byte>();
                RmReadFunc WsReadN = async (n) => {
                    while (wsBuf.Count < n) { var msg = await WsReadMsg(ws); if (msg == null) throw new EndOfStreamException(); wsBuf.AddRange(msg); }
                    var result = wsBuf.GetRange(0, n).ToArray(); wsBuf.RemoveRange(0, n); return result;
                };
                RmWriteFunc WsWrite = async (data) => {
                    await wsMu.WaitAsync(_cts.Token);
                    try { await ws.SendAsync(new ArraySegment<byte>(data), WebSocketMessageType.Binary, true, _cts.Token); } finally { wsMu.Release(); }
                };
                await RunSession(WsReadN, WsWrite);
            } catch (Exception ex) { Log("[rm] " + ex.GetType().Name + ": " + ex.Message); }
            _cts.Cancel();
            if (_stopCts.IsCancellationRequested) break;
            try { await Task.Delay(backoff, _stopCts.Token); } catch { break; }
            backoff = Math.Min(backoff * 2, 60000);
        }
    }

    public void RunWSBlocking(string addr, string wsPath) {
        _stopCts = new CancellationTokenSource();
        Console.CancelKeyPress += (s, e) => { e.Cancel = true; _stopCts.Cancel(); if (_cts != null) _cts.Cancel(); };
        var done = new System.Threading.ManualResetEventSlim(false);
        var thread = new System.Threading.Thread(() => {
            try { RunWS(addr, wsPath).GetAwaiter().GetResult(); } catch { }
            done.Set();
        });
        thread.IsBackground = true;
        thread.Start();
        done.Wait();
    }

    public static void StartBind(string bindAddr, string keyB64) {
        var parts = bindAddr.Split(':');
        int port = int.Parse(parts[parts.Length - 1]);
        string host = parts.Length > 1 ? string.Join(":", parts, 0, parts.Length - 1) : "0.0.0.0";
        var ip = (host == "" || host == "0.0.0.0") ? IPAddress.Any : IPAddress.Parse(host);
        var ln = new TcpListener(ip, port); ln.Start();
        Log("[rm] bind mode listening on " + bindAddr);
        Log("[rm] waiting for server connection...");
        var stopCts = new CancellationTokenSource();
        Console.CancelKeyPress += (s, e) => { e.Cancel = true; stopCts.Cancel(); ln.Stop(); Log("[rm] stopped"); };
        Task.Run(async () => {
            try {
                while (!stopCts.IsCancellationRequested) {
                    var client = await ln.AcceptTcpClientAsync();
                    Log("[rm] server connected from " + client.Client.RemoteEndPoint);
                    try {
                        client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                        var kav = new byte[12];
                        BitConverter.GetBytes(1).CopyTo(kav, 0);
                        BitConverter.GetBytes(15000).CopyTo(kav, 4);
                        BitConverter.GetBytes(5000).CopyTo(kav, 8);
                        client.Client.IOControl(IOControlCode.KeepAliveValues, kav, null);
                    } catch { }
                    var agent = new RosemaryAgent(keyB64);
                    Task.Run(async () => {
                        await agent.RunBindSession(client);
                        Log("[rm] session ended, waiting for next connection...");
                    });
                }
            } catch { }
        }).GetAwaiter().GetResult();
    }

    async Task RunBindSession(TcpClient client) {
        _cts = new CancellationTokenSource();
        try {
            var ns = client.GetStream();
            var tcpMu = new SemaphoreSlim(1, 1);
            RmReadFunc TcpReadN = async (n) => {
                var buf = new byte[n]; int read = 0;
                while (read < n) { int r = await ns.ReadAsync(buf, read, n - read, _cts.Token); if (r == 0) throw new EndOfStreamException(); read += r; }
                return buf;
            };
            RmWriteFunc TcpWrite = async (data) => {
                await tcpMu.WaitAsync(_cts.Token);
                try { await ns.WriteAsync(data, 0, data.Length, _cts.Token); } finally { tcpMu.Release(); }
            };
            Log("[rm] running session...");
            await RunSession(TcpReadN, TcpWrite);
        } catch (Exception ex) { Log("[rm] " + ex.GetType().Name + ": " + ex.Message); }
        client.Close();
    }
}
"@ -Language CSharp

function Invoke-Rosemary {
    [CmdletBinding()]
<#
.SYNOPSIS
    Rosemary agent - connects to or listens for a Rosemary server.

.DESCRIPTION
    Runs the Rosemary agent in one of two modes:
      agent      - connects outbound to the server via WebSocket (default)
      agent-bind - listens for an inbound TCP connection from the server

.PARAMETER Key
    Base64-encoded 32-byte encryption key (required). Must match the server key.

.PARAMETER Server
    Server address in host:port format. Required in agent mode.
    Example: 192.168.1.10:1024

.PARAMETER Path
    WebSocket path on the server. Defaults to /ws.

.PARAMETER Mode
    agent       - outbound WebSocket agent (default)
    agent-bind  - inbound TCP bind agent

.PARAMETER Listen
    Bind address for agent-bind mode. Defaults to 0.0.0.0:9001.

.EXAMPLE
    # Outbound agent mode
    Invoke-Rosemary -Key abcdefghijklmnopqrstuvwxyz012345= -Server 192.168.1.10:1024

.EXAMPLE
    # Bind mode - server connects to us
    Invoke-Rosemary -Key abcdefghijklmnopqrstuvwxyz012345= -Mode agent-bind -Listen 0.0.0.0:9001
#>
    param(
        [string]$Key = "",
        [string]$Server = "",
        [string]$Path = "/ws",
        [string]$Mode = "agent",
        [string]$Listen = "0.0.0.0:9001",
        [switch]$Background,
        [switch]$Help
    )
    if ($Help -or $PSBoundParameters.Count -eq 0) {
        Write-Host ''
        Write-Host '  Usage: Invoke-Rosemary -Key KEY [options]'
        Write-Host ''
        Write-Host '  Parameters:'
        Write-Host '    -Key        BASE64     Encryption key (required, must match server)'
        Write-Host '    -Mode       MODE       agent (default) | agent-bind'
        Write-Host '    -Server     HOST:PORT  Server address  required in agent mode'
        Write-Host '    -Listen     HOST:PORT  Bind address for agent-bind mode (default: 0.0.0.0:9001)'
        Write-Host '    -Background            Run silently in a hidden background window'
        Write-Host '    -Verbose               Show connection and session diagnostic output'
        Write-Host '    -Help                  Show this help'
        Write-Host ''
        Write-Host '  Examples:'
        Write-Host '    Invoke-Rosemary -Mode agent -Server 192.168.1.10:1024 -Key YOUR_KEY'
        Write-Host '    Invoke-Rosemary -Mode agent-bind -Listen 0.0.0.0:9001 -Key YOUR_KEY'
        Write-Host '    Invoke-Rosemary -Mode agent -Server 192.168.1.10:1024 -Key YOUR_KEY -Background'
        Write-Host ''
        return
    }
    if (-not $Key) { Write-Error "Key is required. Run Invoke-Rosemary -Help for usage."; return }
    [RosemaryAgent]::Verbose = $PSBoundParameters.ContainsKey('Verbose')
    if ($Background) {
        $call = "Invoke-Rosemary -Key '" + ($Key -replace "'","''") + "' -Mode '$Mode' -Listen '$Listen'"
        if ($Server) { $call += " -Server '" + ($Server -replace "'","''") + "'" }
        if ($Path -ne '/ws') { $call += " -Path '" + ($Path -replace "'","''") + "'" }
        $scriptPath = $MyInvocation.MyCommand.ScriptBlock.File
        $script = ". '" + ($scriptPath -replace "'","''") + "'; " + $call
        Start-Process powershell -WindowStyle Hidden -ArgumentList @("-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-Command",$script)
        Write-Host "[*] Agent started in background"
        return
    }
    if ($Mode -eq "agent-bind") {
        Write-Host "Running in agent-bind mode"
        [RosemaryAgent]::StartBind($Listen, $Key)
    } else {
        if (-not $Server) { Write-Error "Server is required in agent mode (-Server host:port)"; return }
        Write-Host "Running in agent mode"
        $agent = [RosemaryAgent]::new($Key)
        $agent.RunWSBlocking($Server, $Path)
    }
}
