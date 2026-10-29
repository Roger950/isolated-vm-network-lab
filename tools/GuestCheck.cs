using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

class GuestCheck {
    static string Flag(bool value) { return value ? "YES" : "NO"; }
    static bool ClaudeRunning() {
        return Process.GetProcesses().Any(p => { try { return p.ProcessName.IndexOf("claude", StringComparison.OrdinalIgnoreCase) >= 0; } catch { return false; } });
    }
    static bool BrowserRunning() {
        string[] names = { "msedge", "chrome", "firefox", "brave", "opera" };
        return Process.GetProcesses().Any(p => { try { return names.Contains(p.ProcessName.ToLowerInvariant()); } catch { return false; } });
    }
    static bool Ethernet(NetworkInterface n) {
        return n.NetworkInterfaceType == NetworkInterfaceType.Ethernet || n.NetworkInterfaceType == NetworkInterfaceType.GigabitEthernet;
    }
    static void Offline() {
        Console.WriteLine("\n=== OFFLINE CHECK / 离线检查（不联网、不改设置） ===");
        Console.WriteLine("CLAUDE_RUNNING=" + Flag(ClaudeRunning()));
        Console.WriteLine("BROWSER_RUNNING=" + Flag(BrowserRunning()));
        NetworkInterface[] cards = NetworkInterface.GetAllNetworkInterfaces().Where(Ethernet).ToArray();
        Console.WriteLine("ETHERNET_ADAPTERS=" + cards.Length);
        var up = cards.Where(n => n.OperationalStatus == OperationalStatus.Up).ToArray();
        Console.WriteLine("ETHERNET_LINK_UP=" + Flag(up.Length > 0));
        bool lan = up.Any(n => n.GetIPProperties().UnicastAddresses.Any(a => a.Address.AddressFamily == AddressFamily.InterNetwork && a.Address.ToString().StartsWith("10.42.0.")));
        bool gateway = up.Any(n => n.GetIPProperties().GatewayAddresses.Any(a => a.Address.ToString() == "10.42.0.1"));
        bool dns = up.Any(n => n.GetIPProperties().DnsAddresses.Any(a => a.ToString() == "10.42.0.1"));
        bool ipv6 = up.Any(n => n.GetIPProperties().UnicastAddresses.Any(a => a.Address.AddressFamily == AddressFamily.InterNetworkV6 && !a.Address.IsIPv6LinkLocal && !IPAddress.IsLoopback(a.Address)));
        Console.WriteLine("LAN_ADDRESS=" + Flag(lan));
        Console.WriteLine("OPENWRT_GATEWAY=" + Flag(gateway));
        Console.WriteLine("OPENWRT_DNS=" + Flag(dns));
        Console.WriteLine("NONLOCAL_IPV6=" + Flag(ipv6));
        Console.WriteLine("请保持窗口打开，让 Agent 读取这些状态。\n");
    }
    static string HiddenLine() {
        StringBuilder b = new StringBuilder();
        while (true) {
            ConsoleKeyInfo k = Console.ReadKey(true);
            if (k.Key == ConsoleKey.Enter) { Console.WriteLine(); return b.ToString(); }
            if (k.Key == ConsoleKey.Backspace) { if (b.Length > 0) b.Length--; continue; }
            if (!Char.IsControl(k.KeyChar)) b.Append(k.KeyChar);
        }
    }
    static void NetworkCheck() {
        Console.WriteLine("\n=== NETWORK CHECK / 客机网络检查 ===");
        if (ClaudeRunning() || BrowserRunning()) {
            Console.WriteLine("请先本人退出 Claude 和浏览器，再运行网络检查。不会自动关闭任何应用。"); return;
        }
        Console.WriteLine("只访问 api.ipify.org HTTPS 一次、example.com/stun.cloudflare.com DNS，以及 Cloudflare IPv6 TCP、STUN UDP 检测地址。");
        Console.WriteLine("不访问 Claude/Anthropic。服务可见出口 IP；工具不保存或显示实际公网地址。不会改设置。");
        Console.Write("输入 T 开始，其他键返回：");
        if (!String.Equals(Console.ReadLine(), "T", StringComparison.OrdinalIgnoreCase)) return;
        Console.Write("预期 ISP 出口 IPv4（不回显，可留空；不是代理入口地址）：");
        string expected = HiddenLine().Trim();
        IPAddress parsed;
        if (expected.Length > 0 && (!IPAddress.TryParse(expected, out parsed) || parsed.AddressFamily != AddressFamily.InterNetwork)) {
            Console.WriteLine("预期出口格式无效；未发起检查。\n"); return;
        }
        string actual = null;
        try {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://api.ipify.org");
            request.Proxy = null;
            request.Timeout = 15000; request.ReadWriteTimeout = 15000;
            request.AllowAutoRedirect = false;
            using (WebResponse response = request.GetResponse())
            using (StreamReader reader = new StreamReader(response.GetResponseStream())) actual = reader.ReadToEnd().Trim();
            bool ipv4 = IPAddress.TryParse(actual, out parsed) && parsed.AddressFamily == AddressFamily.InterNetwork;
            Console.WriteLine("NATIVE_HTTPS_IPV4=" + Flag(ipv4));
            Console.WriteLine("EXPECTED_EXIT_MATCH=" + (expected.Length == 0 ? "NOT_PROVIDED" : Flag(ipv4 && actual == expected)));
        } catch (WebException ex) { Console.WriteLine("NATIVE_HTTPS_IPV4=NO (" + ex.Status.ToString() + ")"); }
        catch { Console.WriteLine("NATIVE_HTTPS_IPV4=UNKNOWN"); }
        try {
            IAsyncResult query = Dns.BeginGetHostAddresses("example.com", null, null);
            if (!query.AsyncWaitHandle.WaitOne(8000)) throw new TimeoutException();
            IPAddress[] answers = Dns.EndGetHostAddresses(query);
            Console.WriteLine("SYSTEM_DNS_IPV4=" + Flag(answers.Any(a => a.AddressFamily == AddressFamily.InterNetwork)));
            Console.WriteLine("SYSTEM_DNS_AAAA=" + Flag(answers.Any(a => a.AddressFamily == AddressFamily.InterNetworkV6)));
        } catch { Console.WriteLine("SYSTEM_DNS_IPV4=NO"); }
        try {
            using (Socket probe = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp)) {
                IAsyncResult connection = probe.BeginConnect(IPAddress.Parse("2606:4700:4700::1111"), 443, null, null);
                if (!connection.AsyncWaitHandle.WaitOne(5000)) throw new TimeoutException();
                probe.EndConnect(connection);
                Console.WriteLine("IPV6_TCP_REACHABLE=YES");
            }
        } catch { Console.WriteLine("IPV6_TCP_REACHABLE=NO"); }
        try {
            using (UdpClient udp = new UdpClient(AddressFamily.InterNetwork)) {
                udp.Client.ReceiveTimeout = 3000;
                byte[] binding = new byte[20]; binding[1] = 1;
                binding[4] = 0x21; binding[5] = 0x12; binding[6] = 0xa4; binding[7] = 0x42;
                byte[] transaction = new byte[12]; using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) rng.GetBytes(transaction);
                Buffer.BlockCopy(transaction, 0, binding, 8, 12);
                IPAddress stunAddress = Dns.GetHostAddresses("stun.cloudflare.com").First(a => a.AddressFamily == AddressFamily.InterNetwork);
                udp.Connect(stunAddress, 3478); udp.Send(binding, binding.Length);
                IPEndPoint remote = null; byte[] reply = udp.Receive(ref remote);
                bool valid = reply.Length >= 20 && reply[0] == 1 && reply[1] == 1 && reply.Skip(8).Take(12).SequenceEqual(transaction);
                Console.WriteLine("UDP_STUN_RESPONSE=" + Flag(valid));
            }
        } catch { Console.WriteLine("UDP_STUN_RESPONSE=NONE (需结合网关规则判读)"); }
        Console.WriteLine("BROWSER_WEBRTC=NOT_TESTED\n请保持窗口打开，让 Agent 读取结果。\n");
    }
    static void DirectIpCheck() {
        Console.WriteLine("\n=== DIRECT IP HTTPS / 不依赖 DNS 的连接检查 ===");
        if (ClaudeRunning() || BrowserRunning()) {
            Console.WriteLine("请先本人退出 Claude 和浏览器，再运行检查。"); return;
        }
        Console.WriteLine("只向 https://1.1.1.1/cdn-cgi/trace 发起一次 HTTPS 请求，不查询 DNS、不跟随跳转。");
        Console.WriteLine("Cloudflare 可见出口 IP；不会显示或保存返回的公网地址，不改设置。保留正常证书校验。");
        Console.Write("输入 T 开始，其他键返回：");
        if (!String.Equals(Console.ReadLine(), "T", StringComparison.OrdinalIgnoreCase)) return;
        try {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://1.1.1.1/cdn-cgi/trace");
            request.Proxy = null;
            request.Timeout = 15000; request.ReadWriteTimeout = 15000;
            request.AllowAutoRedirect = false;
            request.KeepAlive = false;
            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            using (StreamReader reader = new StreamReader(response.GetResponseStream())) {
                char[] buffer = new char[4096];
                int count = reader.ReadBlock(buffer, 0, buffer.Length);
                string body = new string(buffer, 0, count);
                bool valid = response.StatusCode == HttpStatusCode.OK && body.Split('\n').Any(line => {
                    IPAddress address;
                    return line.StartsWith("ip=", StringComparison.Ordinal) && IPAddress.TryParse(line.Substring(3).Trim(), out address);
                });
                Console.WriteLine("DIRECT_IP_HTTPS=" + (valid ? "YES" : "UNKNOWN (响应不符合检测格式)"));
            }
        } catch (WebException ex) { Console.WriteLine("DIRECT_IP_HTTPS=NO (" + ex.Status.ToString() + ")"); }
        catch { Console.WriteLine("DIRECT_IP_HTTPS=UNKNOWN"); }
        Console.WriteLine("DNS_LOOKUP=NOT_USED\n请保持窗口打开，让 Agent 读取结果。\n");
    }
    static void Main() {
        Console.OutputEncoding = new UTF8Encoding(false);
        Console.Title = "Guardian Guest Check";
        Console.WriteLine("Guardian 客机只读检测：不安装、不改设置、不读取账号或密码。");
        while (true) {
            Console.Write("\n1=离线检查  2=网络检查  3=直接IP检查  Q=退出：");
            string selection = Console.ReadLine();
            if (selection == null || String.Equals(selection, "Q", StringComparison.OrdinalIgnoreCase)) return;
            try { if (selection == "1") Offline(); else if (selection == "2") NetworkCheck(); else if (selection == "3") DirectIpCheck(); }
            catch { Console.WriteLine("CHECK=UNKNOWN；请保留窗口，由 Agent 排查。"); }
        }
    }
}
