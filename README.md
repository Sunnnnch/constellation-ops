# Constellation Ops · 星图运维

星图是本地 Codex 插件，使用现有 OpenSSH 连接云服务器、GPU 实例、物理机和支持 SSH 的 NAS。设备面板支持分组、搜索、增删改、定时巡检和到期提醒标记。也可通过 Codex 检查系统资源、读取 systemd 日志、传文件和开本机 SSH 隧道。

## 打开设备面板

安装插件后，在 Codex 桌面版左侧选择 **星图**，或从会话的内容标签打开 **星图**。也可以在本地会话中说「打开星图设备面板」。内置面板由本地 MCP 进程启动，可与浏览器面板共用主机清单。

Windows 上双击本目录的 `start-dashboard.cmd`，也可以在本目录运行下列命令。面板可以独立运行。密钥和 SSH 别名使用系统 OpenSSH，表单内密码登录需要下面的 Python 依赖。

```powershell
python '.\plugins\vps-ops\skills\vps-ops\scripts\dashboard.py' --open
```

浏览器打开 `http://127.0.0.1:8765/`。面板默认每 60 秒采集一次，可手动刷新。点击顶栏的「查看示例」可以预览四台模拟设备。端口冲突时加 `--port 0`，使用终端打印的地址。按 Ctrl+C 结束本机面板。

面板通过非交互 SSH 巡检。请先在终端确认主机指纹，并为常用设备配置 SSH 密钥或 SSH agent。可在设备的更多选项里指定已验证的 `known_hosts` 文件。Windows 版继续从 `%LOCALAPPDATA%\VPS Ops\hosts.sqlite3` 读取已保存的设备。需要隔离清单时用 `--data-dir PATH`。

点击主页上的设备卡片查看详情，包括 CPU 型号、内存和根磁盘容量、最近的 SSH 巡检，以及巡检延迟和 VPS 出网 Ping 趋势。硬件信息会在成功巡检后更新。流量是服务器网卡累计计数，速率从连续两次采集计算。到期日和流量参考额度由你填写。

## 面板内 SSH 终端

打开设备详情，点击「打开 SSH 终端」。面板顶部会出现该设备的终端标签。可以开多个会话，在设备概览和终端之间切换，或点击标签上的 × 断开。也可以在编辑设备时用刚输入的密码打开终端。Windows 支持已保存的密码、OpenSSH 别名和本机私钥。首次使用密码连接时需要确认主机指纹；OpenSSH 别名和私钥沿用本机 OpenSSH 的已知主机配置，带口令的密钥可通过 `ssh-agent` 解锁。需要使用系统终端时，可以在设备编辑页选择「系统终端」。

## SSH 隧道

在顶部「隧道」按 VPS 查看已保存的配置，也可以从设备详情打开并选中该 VPS。新建时填写本机端口、从 VPS 可访问的目标地址和目标端口。比如 VPS 上的 Jupyter 监听 `127.0.0.1:8888`，可设置本机端口 `18888`，启动后在这台电脑打开 `http://127.0.0.1:18888/`。

每条隧道可单独启动、停止，并显示本机端口是否可用。转发只监听本机 IPv4 回环地址 `127.0.0.1`，沿用所选设备的 SSH 认证和主机指纹校验。Codex 和独立浏览器面板共用本机配置，也可以从任一面板停止正在运行的隧道。隧道运行期间需要保持启动它的星图进程运行。

在新建隧道或已有隧道的「自动化」设置中，可分别开启「自动启动」和「断线重连」。前者在星图后台进程重新启动时恢复隧道，后者在 SSH 连接意外断开后逐步延长重试间隔。手动停止会取消当前重试。下次启动星图时，启用了「自动启动」的隧道仍会恢复。独立面板的浏览器标签关闭时，后台进程可以继续运行。

自动连接需要可无交互使用的 SSH 私钥、SSH 别名或设备已记住的密码。只输入一次的密码用于该次连接。主机指纹或认证需要处理时，面板会显示具体提示。

## 设备旗标与文件管理

设备卡片按 SSH 主机的公网 IP 显示国家或地区旗标。域名或 SSH 别名会先在本机解析，然后使用随插件附带的 IP 数据查询。公网 IP 的地理归属来自数据库记录，可能与机房的实际位置有差异。 [DB-IP IP to Country Lite](https://db-ip.com/db/download/ip-to-country-lite)

在顶部「文件管理」从左侧选择 VPS，右侧显示该设备的远程目录。可随时从左侧切换设备，也可以从设备详情打开文件管理。进入目标目录后点击「上传文件」选择本机文件，或点击远端文件旁的「下载」选择本机保存位置。传输使用 SFTP，沿用设备的 SSH 认证和主机指纹校验。遇到同名文件时请选择新名称或其他目录。文件管理需要已安装下文的 Paramiko 依赖，也需要服务器启用 SFTP。

## 网络检测

在设备详情点击「网络检测」，通过「本机探针」和「VPS 出网测速」切换检测方向。

### 本机探针

可为设备添加多个检测目标。ICMP 检测主机是否回应 Ping，TCP 检测指定端口是否可连接，HTTP / HTTPS 检测指定 URL 的状态码和响应时间。每个探针可设置 30 至 3600 秒的检测间隔，也可关闭自动检测并手动运行。最近 96 条结果保存在本机，可通过「记录」查看。

网络探针从运行星图的电脑发起。独立浏览器面板在后台进程运行时检测，Codex 内置面板在打开时检测。可以用它查看本机到 VPS 的连通性。若要从多台 VPS 分别发起探测，可使用 [Komari 的 Agent](https://github.com/komari-monitor/komari-agent)。

### VPS 出网测速

在「VPS 出网测速」可同时选择最多 8 个内置或自定义地区。点击「保存为常用地区」记住这台 VPS 的选择，或临时勾选后直接开始检测。一次检测复用一条 SSH 连接，默认每个目标发 5 个 ICMP 包，也可以选 20 包复测。面板按地区并排显示平均往返延迟、发包数、回包数和丢包率，并按设备和地区保存最近一次结果。

从「主页」打开「批量设置测速地区」，勾选多台 VPS 和一组地区并保存。保存会把所选 VPS 的常用地区设为这一组。随后可在各设备详情里发起检测。

在「定时测速」中点击「使用推荐参数」，可填入每 60 秒检测一次、每个目标发 3 包。勾选「启用定时测速」并保存后生效。频率可设为 30 至 86,400 秒，每个目标每轮可发送 1 至 20 个 ICMP 包。定时任务使用该设备保存的常用地区，需要可自动使用的 SSH 凭据。首次启用后会安排首轮检测，上一轮还在运行时不会启动重叠任务。地区结果会自动刷新，点击「测速历史」查看实际收发包、累计丢包率和延迟。每台设备的每个地区最多保留 240 轮，历史面板按最近 120 轮统计。1 包模式下，单轮只有收到或无应答两种有效结果，累计丢包率按实际发包数计算。

设备卡片的「VPS 出网 Ping」在同一张图上显示已选线路最近一小时的往返延迟，不同网络用不同颜色标记。点击「测速设置」可打开这台设备的出网测速配置。

定时任务由本机星图后台进程执行。使用独立面板服务时可以关闭浏览器标签。电脑睡眠、关机或面板进程退出时，定时任务会暂停。面板恢复运行后继续执行已启用的任务。

国内预设包括中国、安徽（合肥）和上海。安徽电信、联通、移动目标分别是 `61.132.163.68`、`218.104.78.2`、`211.138.180.2`。上海三网分别是 `202.96.209.133`、`210.22.97.1`、`211.136.112.200`。[安徽联通路由登记](https://stat.ripe.net/data/prefix-overview/data.json?resource=218.104.78.2) · [上海三网公开路由样本](https://dc99.bwg.net/routes)

海外预设包括英国伦敦、美国纽约、日本东京和新加坡。伦敦使用三家服务商公布的测试地址。 [EDIS 伦敦](https://uk.edisglobal.com/) · [Psychz 伦敦](https://lg.lon.psychz.net/) · [SpeedyPage 伦敦](https://lon.lg.speedypage.com/)

「自定义地区」可以填写一个地区名，以及 1–6 个带名称的 IPv4 或 IPv6 地址。IPv6 目标需要 VPS 具备 IPv6 连通性。没有收到 ICMP 回包时面板显示「无应答」。

## 查看巡检历史和迁移设备

设备卡片显示最近 1 小时的 SSH 巡检延迟。打开设备详情，在「最近 24 小时」查看更长的 SSH 延迟以及 CPU、内存历史。SSH 巡检延迟为命令总耗时扣除远程巡检脚本运行时间，包含握手、认证和结果传输等耗时。历史存在本机，每分钟保留该分钟最新的一次巡检。浏览器面板在进程运行期间采集，Codex 内置面板在打开时采集。失败或缺少采样的时段在图上留空。需要在电脑关机后继续监控或发送告警时，可使用 [Komari](https://github.com/komari-monitor/komari) 或 [Beszel](https://github.com/henrygd/beszel) 的独立监控服务。

在设备列表的「指标显示」菜单切换仪表盘或文字。面板默认使用仪表盘，并在本机记住选择。

使用「导入 / 导出」生成星图的 JSON 设备清单。可复制 JSON 保存到文件。导入时选择 JSON 文件或粘贴清单，先预览再确认。导入只添加新连接，跳过重复项。清单包含地址、用户名、端口、认证方式、分组和配额等配置。私钥、密钥路径、密码、指纹文件路径、备注和巡检历史留在原电脑。导入后给本机私钥设备重新选择密钥，并按需配置 SSH 别名和核对主机指纹。

在顶部「同步」页的「WebDAV 加密同步」填入已有的 HTTPS 文件夹地址和同步密码。勾选「使用专用子文件夹」后，首次上传会在该文件夹下创建 `VPS-Ops/`。设备资料、常用测速地区和参数、仪表盘显示偏好以及选中的私钥，在本机加密后写入 `vps-ops-sync.v1.enc`。另一台电脑输入相同文件夹和密码，先预览差异，再选择保留本机或云端冲突版本并应用。更新远端备份需要服务提供可用于条件写入的 ETag。

在 Windows 上可启用「自动上传」或「双向同步」，选择每 5、15、30 或 60 分钟检查一次。WebDAV 登录和同步密码保存在本机 Windows 凭据管理器。面板进程运行期间才会执行定时任务。双向同步可应用单侧的普通配置变更。遇到两端同时修改、远端删除或待恢复的私钥时会暂停，等手动预览处理。SSH 登录密码、主机信任、监控历史和监控服务凭据留在本机。新导入设备的定时测速需在这台电脑上启用。

在「主页 → 监控集成」选择 Komari 或 Beszel，测试并保存对应面板的连接，从设备详情绑定节点。设备卡片显示来源、在线状态、CPU、内存和磁盘，详情可查看负载历史。Komari 节点还可显示 Ping 历史。Beszel 可用仅共享所需系统的普通或只读账号登录。监控服务的凭据由 Windows 凭据管理器保管。

## 安装

准备 Python 3.10+ 和 OpenSSH 9+ 客户端。Windows 上可用 `python --version`、`ssh -V` 和 `Get-Command scp` 检查。

克隆仓库，然后在项目目录注册本地插件源。

```powershell
git clone https://github.com/Sunnnnch/constellation-ops.git
cd constellation-ops
codex plugin marketplace add .
```

在 Codex 桌面版的插件目录选择 **星图运维本地目录**，安装 **Constellation Ops · 星图运维**。也可运行 `codex plugin add vps-ops@vps-ops-local`。若插件源或入口未显示，完全退出并重新打开 Codex 桌面版。插件使用本机 SSH，请在本地聊天中调用。[Codex 侧栏入口文档](https://developers.openai.com/plugins/build/extensions#sidebar-apps)

## 连接服务器

在左侧打开 **星图 → 添加设备**。填设备名称、主机地址、SSH 端口和登录用户名，再选认证方式。已有设备可直接编辑。

- **OpenSSH 配置**。填已有的 SSH 别名，例如 `gpu-vps`。用户名和端口可留空，沿用该别名的配置。
- **本机私钥**。选取 OpenSSH 支持的私钥文件，或填写它的本机路径。对应公钥应已安装在服务器账号下。带口令的私钥可通过本机 `ssh-add` 加入已运行的 `ssh-agent`，供后台巡检使用。
- **密码**。选择「密码」后，在表单输入服务器的 SSH 密码。「打开 SSH 终端」会使用表单密码登录。Windows 下勾选「在本机记住密码」并保存后，可以从设备详情直接登录，面板也能自动巡检。密码保存在当前用户的 Windows 凭据管理器。取消勾选并保存可移除凭据。

保存前可点「测试连接」。测试会报告端口拒绝或超时、主机指纹待确认或已变更，以及认证失败。如果首次连接提示核对指纹，请对照服务商控制台显示的指纹。确认后回到面板继续连接。也可在「更多选项」填写已验证的 `known_hosts` 文件路径。保存的密码只用于当前主机、端口、用户和已确认的主机指纹。

SSH 密码登录、SFTP 文件管理和 WebDAV 加密同步需要额外的 Python 依赖。在 Windows PowerShell 运行以下命令，然后重新打开面板。

```powershell
python -m pip install --target "$env:LOCALAPPDATA\VPS Ops\python-deps" "paramiko==5.1.0"
```

macOS 和 Linux 可把同一依赖安装到运行面板的 Python 环境。Codex 插件通过 `python` 命令启动，请确保该命令指向 Python 3.10 或更新版本。

也可在本机 `~/.ssh/config`（Windows 为 `%USERPROFILE%\.ssh\config`）配置别名。

```ssh-config
Host gpu-vps
    HostName gpu.example.com
    User ubuntu
    Port 2222
    IdentityFile ~/.ssh/id_ed25519_gpu
    IdentitiesOnly yes
```

在本机终端运行 `ssh gpu-vps` 验证别名。运行 `ssh -o BatchMode=yes -o StrictHostKeyChecking=yes gpu-vps exit` 可验证能否无交互连接。参见 [OpenSSH 配置手册](https://man.openbsd.org/ssh_config)和 [Windows OpenSSH 密钥管理](https://learn.microsoft.com/windows-server/administration/openssh/openssh_keymanagement)。

安装后可以直接对 Codex 说：

- 「用星图查 `gpu-vps` 的显存、内存配额和剩余磁盘。」
- 「看 `gpu-vps` 上 `nginx.service` 最近 50 行日志。」
- 「把本地 `results.csv` 上传到 `gpu-vps` 的 `/home/ubuntu/results.csv`。」
- 「把 `gpu-vps` 上的 Jupyter 8888 端口转到本机 18888。」

也可以直接运行随包附带的 Python 工具。全局选项放在子命令前。

```powershell
$ops = '.\plugins\vps-ops\skills\vps-ops\scripts\vps_ops.py'
python $ops resolve gpu-vps
python $ops status gpu-vps
python $ops logs gpu-vps nginx.service --lines 50
python $ops --interactive --port 2222 status ubuntu@gpu.example.com
python $ops upload gpu-vps '.\results.csv' '/home/ubuntu/results.csv'
python $ops download gpu-vps '/home/ubuntu/results.csv' '.\downloaded.csv'
python $ops tunnel gpu-vps 18888 127.0.0.1 8888
```

远端文件请使用完整的绝对路径。下载要求本地目标文件尚不存在。上传使用 OpenSSH 的 SFTP 模式，可能覆盖远端已有文件；如目标是目录，则以本地文件名写入该目录。保留现有文件时，请选一个新的远端文件名。

隧道保持前台运行，只监听本机 `127.0.0.1`。上述例子的 Jupyter 地址是 `http://127.0.0.1:18888`。按 Ctrl+C 结束隧道。

如果要让 Codex 直接在远端项目里写代码，可使用桌面版的原生 SSH 连接。星图用于从本机巡检、传文件和转发端口。[Codex 远程连接说明](https://learn.chatgpt.com/docs/remote-connections#connect-to-an-ssh-host)

插件安装格式见 [OpenAI 本地插件打包文档](https://developers.openai.com/plugins/build/plugins)。
