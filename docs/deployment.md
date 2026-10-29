# 部署与验证说明

## 前提

需要独立实验虚拟机、双网卡 OpenWrt、Mihomo、nftables/jsonfilter、密钥 SSH 管理、独立虚拟机控制台与可用备份。客机只连接隔离 LAN；网关管理侧经 VMware NAT。操作者必须对目标环境拥有管理权限。

这里提供组件与案例说明，不提供自动创建虚拟机或无人确认接管整机网络的安装器。先核对示例地址、接口名、SSH 来源和恢复通道，再逐项部署。不要直接修改运行中的 VMX 文件。

## 文件布局与运行路径

| 仓库文件 | 实验网关路径 |
|---|---|
| `gateway/guardian-gateway.nft.in` | `/usr/share/guardian-gateway/guardian-gateway.nft.in` |
| `gateway/guardian-render-firewall.sh` | `/usr/share/guardian-gateway/guardian-render-firewall.sh` |
| `gateway/guardian-gateway.init` | `/etc/init.d/guardian-gateway` |
| `gateway/guardian-ipv6.hotplug` | `/etc/hotplug.d/iface/99-guardian-ipv6` |
| 私有 Mihomo 配置 | `/etc/mihomo/config.yaml`，JSON 格式、权限 600 |

核心服务须命名为 `/etc/init.d/guardian-mihomo`。防护服务先于代理启动；停止代理时保留防护。额外配置 dnsmasq 转发到 `127.0.0.1:1053`、LAN DHCP、系统 IPv6 禁用与管理防火墙。公开的 `mihomo-closed.yaml` 是拒绝全部流量的初始配置，不包含代理资源。

凭据输入样式见 `examples/credentials.example.json`；这是无效占位示例，不应提交实际填写后的文件。配置字段和备份可能包含秘密，应仅放入受限目录。

## 分段诊断

```sh
python -B tools/diagnose_socks_chain.py < private-input.json
```

输入字段包括 `local_port`、`server`、`port`、`username`、`password`，可选 `test_host`（仅 example.com / api.ipify.org）和 `hold_seconds`（最多 10 秒）。实际使用宜通过安全的标准输入传入，避免凭据落在命令行或 Shell 历史中。工具只访问指定代理及两个允许的 HTTPS 目标，保留 TLS 校验，不输出密码或返回的公网地址。

## 可回滚出口切换

```sh
python -B tools/switch_gateway_isp.py --host root@gateway.example.invalid --key PATH_TO_KEY --known-hosts PATH_TO_KNOWN_HOSTS < private-endpoint.json
```

仅在现有网关已具备上述布局、JSON 配置首个代理名为 `Static-ISP` 且类型为 socks5 时使用。工具读取当前私有配置至内存，只修改首个出口的连接字段，并在网关私有目录保留备份。

流程为：读取与哈希冲突检查 → 校验候选 → 布置 300 秒自动回滚 → 变更配置及规则模板 → 重启核心 → 经 SSH 转发测试 HTTPS 与出口 → 检查 DNS 和唯一入口集合 → 验收成功后解除回滚。

该工具修改生产网关，会短暂中断客机连接，应只在维护窗口操作。超时保险丝依赖网关仍运行及 SSH/控制台可恢复；工具不是断电事务，不能代替快照。备份恢复脚本只在 `pending` 存在时生效；成功解除后，人工恢复需先检查当前版本和备份内容，不能直接假定再次调用即可回滚。

## 构建 Windows 客机检测工具

在 Windows 的 `tools` 目录运行 .NET Framework C# 编译器：

```powershell
& "$env:WINDIR/Microsoft.NET/Framework64/v4.0.30319/csc.exe" /nologo /target:exe /out:CHECK.EXE GuestCheck.cs
python -B build_guest_check_iso.py --executable CHECK.EXE --output guest-check.iso
```

ISO 构建器仅使用 Python 标准库，生成含检测程序、完整源码与说明的非启动数据光盘。挂载后由操作者手动运行；选项 1 不联网，选项 2/3 每次要求输入 T。程序不改设置、不读取账号密码、不保存结果文件。

网络检查会向 ipify、example.com 和 Cloudflare 指定服务发请求，服务可见出口地址。程序可能读取本机进程名称以提醒先退出目标应用 / 浏览器，但不发送进程列表；预期出口输入只在内存中比较。代码中的 `10.42.0.0/24` 是实验默认值。

## 完整验收顺序

1. 核对实际客机网卡、租约、网关、DNS 和唯一入口。
2. 核对宿主 TUN 的实际连接链，避免出口地址被排除而绕过中转。
3. 测试客机 HTTPS、DNS A/AAAA、IPv6 与 UDP。
4. 从浏览器独立检查 DNS/WebRTC，不能以功能开启代替无泄露证据。
5. 由使用者验证目标应用功能。
6. 有独立恢复通道后再演练代理故障与冷启动，并记录配置版本。
