'use strict';
'require view';
'require form';
'require uci';
'require fs';
'require ui';
'require poll';

/*
 * xdp-fw LuCI 视图（重构版）
 *   - 不再有 启用/停止 按钮（避免与"XDP 加速"页面在同一接口上抢 XDP slot）
 *   - 顶部统一显示 "XDP 接口占用快照"：每个接口当前 attach 的程序
 *   - 高亮冲突：xdp-fw 配置的 wan_if/lan_if 上挂着非 nat-redirect 程序时给红字提示
 *   - 服务的启停由 procd autostart / CLI / 后端自动判断（与该页面解耦）
 */

function runCtl(args) {
    return fs.exec('/usr/sbin/xdp-fw-ctl', args).catch(function(e){
        return { code:-1, stdout:'', stderr:String(e) };
    });
}
function runLoader(args) {
    return fs.exec('/usr/sbin/xdp-loader', args).catch(function(e){
        return { code:-1, stdout:'', stderr:String(e) };
    });
}
function runXdpCtl(args) {
    return fs.exec('/usr/sbin/xdp-ctl', args).catch(function(e){
        return { code:-1, stdout:'', stderr:String(e) };
    });
}

function parseStats(text) {
    var o = {};
    (text||'').split('\n').forEach(function(line){
        var p = line.split(' ');
        if (p.length >= 2) o[p[0]] = p[1];
    });
    return o;
}

/* 解析 xdp-loader status 输出 → [{iface, prog, mode, id, tag}] */
function parseLoader(text) {
    var rows = [];
    var inTable = false;
    (text||'').split('\n').forEach(function(line){
        if (/^Interface\s+/.test(line)) { inTable = true; return; }
        if (!inTable) return;
        if (/^---/.test(line) || !line.trim()) return;
        var p = line.trim().split(/\s+/);
        if (p.length < 2) return;
        var iface = p[0];
        if (/^</.test(p[1])) {
            rows.push({ iface: iface, prog: '', mode: '', id: '', tag: '' });
        } else {
            // [iface, (Prio?), prog, mode, id, tag, ...]
            // Prio 列常为空 → awk 会合并；按出现的关键词识别
            var prog = '', mode = '', id = '', tag = '';
            for (var i = 1; i < p.length; i++) {
                if (p[i] === 'native' || p[i] === 'skb' || p[i] === 'generic') {
                    mode = p[i];
                    prog = p[i-1];
                    id = p[i+1] || '';
                    tag = p[i+2] || '';
                    break;
                }
            }
            rows.push({ iface: iface, prog: prog, mode: mode, id: id, tag: tag });
        }
    });
    return rows;
}

/* 判定 prog 名属于哪个项目 */
function classifyProg(prog) {
    if (!prog) return { kind:'none', label:'(空闲)', color:'#9ca3af' };
    if (/xdp_fw_kern/i.test(prog) || /xdp_fw$/.test(prog))
        return { kind:'nat', label:'xdp-fw redirect', color:'#16a34a' };
    if (/xdp_main/i.test(prog))
        return { kind:'filter', label:'XDP 加速过滤', color:'#2563eb' };
    return { kind:'other', label: prog, color:'#f59e0b' };
}

return view.extend({
    load: function() {
        var p = function(promise, fb){ return promise.catch(function(){return fb;}); };
        return Promise.all([
            p(fs.read('/run/xdp-fw.stats'), ''),
            runCtl(['conns']),
            uci.load('xdp-fw'),
            runLoader(['status']),
            // BusyBox 的 pgrep 不支持 -c；直接打印 PID 列表，再在 JS 里数行
            p(fs.exec('/usr/bin/pgrep', ['xdp_fw']), {stdout:''}),
            p(fs.exec('/etc/init.d/xdp-fw', ['enabled']), {code:1}),
            // 拉 logread 用于判断内核 AF_XDP 支持（xsks_map 创建失败 = CONFIG_XDP_SOCKETS=n）
            p(fs.exec('/sbin/logread', []), {stdout:''})
        ]);
    },

    render: function(data) {
        var self        = this;
        var stats       = parseStats(data[0] || '');
        var conns_text  = (data[1] && data[1].stdout) || '';
        var loader_text = (data[3] && data[3].stdout) || '';
        var pgrep_out   = ((data[4] && data[4].stdout) || '').trim();
        var pgrep_count = pgrep_out ? pgrep_out.split(/\s+/).length : 0;
        var running     = pgrep_count > 0;
        var enabled     = !!(data[5] && data[5].code === 0);

        /* ---- 内核能力探测：XDP_SOCKETS 是否编进内核 ----
         * 判据：历史 logread 里是否出现过 xsks_map 创建失败的记录；
         *       或者 libbpf map xsks_map failed to create；任一命中 → 内核不支持 AF_XDP。 */
        var logread_all = ((data[6] && data[6].stdout) || '');
        var kernelNoXsk = /xsks_map[^\n]*failed to create/i.test(logread_all) ||
                          /libbpf: *map *'xsks_map'/i.test(logread_all);
        /* 保存到 this 让 onAutoEnable 能检查 */
        self._kernelNoXsk = kernelNoXsk;

        var wan_if = uci.get('xdp-fw', 'main', 'wan_if') || 'eth1';
        var lan_if = uci.get('xdp-fw', 'main', 'lan_if') || 'eth0';

        var ifaces = parseLoader(loader_text);
        var byIf = {}; ifaces.forEach(function(r){ byIf[r.iface] = r; });

        /* 读 XDP 加速 UCI 里每接口的意图 */
        var intent = {};
        try {
            uci.sections('xdp', null, function(sect){
                if (sect['.name'] !== 'main') return;
                Object.keys(sect).forEach(function(k){
                    if (/^if_/.test(k)) {
                        var key  = k.substr(3);   // if_xxx -> xxx
                        var real = sect['name_'+key] || key;
                        intent[real] = sect[k];
                    }
                });
            });
        } catch(e) {}

        /* 冲突检测：wan_if/lan_if 上是不是非 nat 程序 */
        var conflicts = [];
        [wan_if, lan_if].forEach(function(ifn){
            var r = byIf[ifn];
            if (r && r.prog) {
                var c = classifyProg(r.prog);
                if (c.kind !== 'nat')
                    conflicts.push({ iface: ifn, prog: r.prog, kind: c.kind });
            }
        });

        var root = E('div', {'class':'cbi-map'}, [
            E('h2', {}, _('XDP 防火墙 (NAT + ACL + 防 DDoS)')),
            E('div', {'class':'cbi-map-descr'}, [
                _('基于 AF_XDP 的一体化路由数据面：'),
                E('br'),
                '  • ', E('strong',{},_('NAT')), _('：IPv4 NAPT、DNAT、IPv6 NPTv6、NAT64、NAT46'),
                E('br'),
                '  • ', E('strong',{},_('防火墙')), _('：源/目的 IP 黑白名单（CIDR）、端口 ACL、状态跟踪 （P1 开发中）'),
                E('br'),
                '  • ', E('strong',{},_('防 DDoS')), _('：per-IP 限速、SYN flood 检测、自适应封禁 （P2 开发中）'),
                E('br'),
                E('br'),
                _('快慢双路径：已建立连接在内核 XDP BPF 里处理（零拷贝），新连接和复杂规则才进用户态。每个网卡同时只能挂一个 XDP 程序，若要切换到 '),
                E('a', {'href':'?'+encodeURIComponent('admin/network/xdp')}, _('XDP 加速（过滤）')),
                _(' 请先到那个页面操作。')
            ])
        ]);

        /* === 最高优先级：内核不支持 AF_XDP（CONFIG_XDP_SOCKETS=n）===
         * 如果检测到，在所有其它卡片之前贴一个大红横幅；其余卡片继续显示但按钮不会生效。 */
        if (kernelNoXsk) {
            root.appendChild(E('div', {
                'class':'alert-message danger',
                'style':'padding:16px 20px;border-left:6px solid #dc2626'
            }, [
                E('div', {'style':'font-size:18px;font-weight:700;margin-bottom:8px'},
                    '🚫  ' + _('当前内核不支持 AF_XDP，xdp-fw 无法启动')),
                E('p', {'style':'margin:6px 0;font-size:13px;line-height:1.7'}, [
                    _('XDP NAT 依赖内核 BPF 里的 AF_XDP 协议族（'),
                    E('code',{},'BPF_MAP_TYPE_XSKMAP'),
                    _('），而当前 OpenWrt 25.12.2 x86_64 的默认内核未编译 '),
                    E('code',{},'CONFIG_XDP_SOCKETS'),
                    _('。验证：'),
                    E('code',{},'bpftool map create ... type xskmap'),
                    _(' → '),
                    E('code',{'style':'color:#dc2626'},'Invalid argument'),
                    '。'
                ]),
                E('p', {'style':'margin:10px 0 6px;font-size:13px;font-weight:600'},
                    _('修复方法（二选一）：')),
                E('ol', {'style':'margin:0 0 6px 24px;font-size:13px;line-height:1.8'}, [
                    E('li', {}, [
                        E('strong', {}, _('A. 重编内核（推荐）')),
                        E('br'),
                        _('用完整 OpenWrt 源码树（不是 package SDK）执行 '),
                        E('code',{},'make menuconfig'),
                        _('，在 '),
                        E('code',{},'Kernel modules → Network Support'),
                        _(' 下勾选 '),
                        E('code',{},'kmod-xdpsockets'),
                        _('；或直接在 '),
                        E('code',{},'target/linux/x86/config-6.12'),
                        _(' 加入：'),
                        E('pre', {'style':'background:#1f2937;color:#d1d5db;padding:8px;margin:4px 0;border-radius:4px;font-size:12px'},
                            'CONFIG_XDP_SOCKETS=y\nCONFIG_XDP_SOCKETS_DIAG=y'),
                        _('然后重编固件刷机。')
                    ]),
                    E('li', {}, [
                        E('strong', {}, _('B. 改方案')),
                        _('：不用 AF_XDP，改用 TC eBPF + 内核常规 socket 做 NAT（性能没 zero-copy 高但无需改内核）。这等于重写 xdp-fw。')
                    ])
                ]),
                E('p', {'style':'margin:8px 0 0;font-size:12px;color:#6b7280'},
                    _('在内核修复之前，下方"🚀 自动启用"按钮会直接告知错误，不会尝试启动（避免 procd crash loop）。'))
            ]));
        }

        /* === 卡片 1：XDP 接口占用快照（含管理按钮） === */
        function modeBtn(iface, mode, label, isCurrent) {
            var bg = isCurrent ? '#2563eb' : '#e5e7eb';
            var fg = isCurrent ? '#fff'    : '#374151';
            return E('button', {
                'class':'btn',
                'style':'min-width:64px;margin:0 2px;padding:4px 10px;font-size:12px;'+
                        'background:'+bg+';color:'+fg+';border:1px solid #d1d5db;'+
                        (isCurrent ? 'cursor:default;' : 'cursor:pointer;'),
                'click': isCurrent ? null : ui.createHandlerFn(self, 'onSetMode', iface, mode)
            }, label);
        }

        var rows = ifaces.map(function(r){
            var c = classifyProg(r.prog);
            var roleLabel = (r.iface === wan_if) ? '【WAN】' :
                            (r.iface === lan_if) ? '【LAN】' : '';
            var ifIntent  = intent[r.iface] || 'off';

            return E('tr', {'class':'tr'}, [
                E('td', {'class':'td','style':'font-family:monospace;width:18%;'}, [
                    r.iface,
                    roleLabel ? E('span',{'style':'color:#2563eb;font-weight:600;margin-left:6px'},roleLabel) : ''
                ]),
                E('td', {'class':'td','style':'width:18%'},
                    E('span', {'style':'color:'+c.color+';font-weight:600'}, c.label)),
                E('td', {'class':'td','style':'width:8%'}, r.mode || '—'),
                E('td', {'class':'td','style':'width:14%;color:#6b7280;font-size:12px'},
                    'UCI: ' + ifIntent),
                E('td', {'class':'td'}, [
                    modeBtn(r.iface, 'off',     _('禁用'),   ifIntent === 'off'),
                    modeBtn(r.iface, 'native',  _('Native'), ifIntent === 'native'),
                    modeBtn(r.iface, 'generic', _('Generic'),ifIntent === 'generic' || ifIntent === 'skb')
                ])
            ]);
        });

        var snapshot = E('div', {'class':'cbi-section'}, [
            E('h3', {}, _('当前 XDP 接口占用与管理')),
            E('table', {'class':'table cbi-section-table'}, [
                E('tr', {'class':'tr table-titles'}, [
                    E('th', {'class':'th'}, _('接口')),
                    E('th', {'class':'th'}, _('实际程序')),
                    E('th', {'class':'th'}, _('模式')),
                    E('th', {'class':'th'}, _('UCI 意图')),
                    E('th', {'class':'th'}, _('管理'))
                ])
            ].concat(rows)),
            E('p', {'class':'cbi-value-description'}, [
                _('点击 '), E('strong',{},'禁用'),
                _(' / '), E('strong',{},'Native'),
                _(' / '), E('strong',{},'Generic'),
                _(' 即生效（持久化到 '), E('code',{},'/etc/config/xdp'),
                _('，开机自动）。WAN/LAN 接口若被 '),
                E('code',{},'xdp_main'),
                _(' 占用，xdp-fw 无法接管，请先点"禁用"释放该接口。')
            ])
        ]);
        root.appendChild(snapshot);

        /* === 卡片 2：状态面板（一眼看清"到底启用了没有"） === */
        var wanC = classifyProg(byIf[wan_if] ? byIf[wan_if].prog : '');
        var lanC = classifyProg(byIf[lan_if] ? byIf[lan_if].prog : '');
        var natOnWan = (wanC.kind === 'nat');
        var natOnLan = (lanC.kind === 'nat');

        /* 总体判断 */
        var sVerdict, sClass, sHint;
        if (running && natOnWan && natOnLan) {
            sVerdict = '✅  XDP NAT 已启用并正常运行';
            sClass   = 'alert-message success';
            sHint    = _('守护进程运行中，NAT 程序已挂到 WAN/LAN 接口。');
        } else if (running && (natOnWan || natOnLan)) {
            sVerdict = '⚠️  XDP NAT 部分生效';
            sClass   = 'alert-message warning';
            sHint    = _('守护进程在跑，但只有一侧接口挂上了 NAT，请点击下方"🚀 自动启用 XDP NAT"重试。');
        } else if (running) {
            sVerdict = '⚠️  XDP NAT 进程运行中，但 WAN/LAN 都未挂载 NAT';
            sClass   = 'alert-message warning';
            sHint    = _('可能被其它 XDP 程序占用，或 BPF 加载失败。请点击下方"🚀 自动启用 XDP NAT"。');
        } else if (conflicts.length > 0) {
            sVerdict = '❌  XDP NAT 未运行（接口被其它程序占用）';
            sClass   = 'alert-message danger';
            sHint    = _('请点击下方"🚀 自动启用 XDP NAT"按钮，会自动释放冲突接口并启动服务。');
        } else {
            sVerdict = '⏹  XDP NAT 未启用';
            sClass   = 'alert-message info';
            sHint    = _('在下方选好 WAN/LAN 接口与 IP/CIDR，保存并应用，然后点击"🚀 自动启用 XDP NAT"。');
        }

        var statusRow = function(k, v, vColor) {
            return E('tr', {}, [
                E('td', {'style':'padding:4px 14px 4px 0;color:#6b7280;white-space:nowrap'}, k),
                E('td', {'style':'padding:4px 0;font-family:monospace;'+(vColor?('color:'+vColor+';font-weight:600'):'')}, v)
            ]);
        };

        root.appendChild(E('div', {'class': sClass, 'style':'padding:14px 18px'}, [
            E('div', {'style':'font-size:17px;font-weight:700;margin-bottom:6px'}, sVerdict),
            E('div', {'style':'font-size:13px;margin-bottom:10px'}, sHint),
            E('table', {'style':'border-collapse:collapse;font-size:13px'}, [
                statusRow(_('守护进程 xdp_fw'),
                          running ? ('✓ 运行中（' + pgrep_count + ' 个进程）') : '✗ 未运行',
                          running ? '#16a34a' : '#dc2626'),
                statusRow(_('procd 开机自启'),
                          enabled ? '✓ 已启用' : '✗ 未启用',
                          enabled ? '#16a34a' : '#dc2626'),
                statusRow('WAN  (' + wan_if + ')', wanC.label, wanC.color),
                statusRow('LAN  (' + lan_if + ')', lanC.label, lanC.color)
            ])
        ]));

        /* 冲突详情：如果有非 nat 程序占着 WAN/LAN，把它们单独列出来 */
        if (conflicts.length > 0) {
            var msgs = conflicts.map(function(c){
                return E('li', {}, [
                    E('strong', {}, c.iface),
                    _(' 当前已被 '),
                    E('code', {}, c.prog),
                    _(' 占用。点击"🚀 自动启用 XDP NAT"可自动释放；也可到"XDP 加速"页面手动设为 off。')
                ]);
            });
            root.appendChild(E('div', {'class':'alert-message warning'}, [
                E('strong', {}, _('冲突接口列表')),
                E('ul', {'style':'margin:6px 0 0 20px'}, msgs)
            ]));
        }

        /* === 配置 form.Map（保留所有规则配置；去掉 enabled 开关） === */
        var m, s, o;
        m = new form.Map('xdp-fw', null, null);

        s = m.section(form.NamedSection, 'main', 'xdp-fw', _('主配置（选择入/出网口）'));
        s.anonymous = false;

        // WAN/LAN 改成下拉菜单，选项来自当前接口列表
        o = s.option(form.ListValue, 'wan_if', _('出网口（WAN，连上游/外网）'));
        o.default = 'eth1';
        ifaces.forEach(function(r){
            if (r.iface === 'lo' || /^sit/.test(r.iface)) return;
            var label = r.iface;
            if (r.prog) label += '  ⚠ 当前已被 ' + r.prog + ' 占用';
            o.value(r.iface, label);
        });

        o = s.option(form.Value, 'wan_ip',   _('WAN IPv4 地址'));
        o.datatype = 'ip4addr'; o.rmempty = false; o.placeholder = '203.0.113.10';

        o = s.option(form.ListValue, 'lan_if', _('入网口（LAN，连内网客户端）'));
        o.default = 'eth0';
        ifaces.forEach(function(r){
            if (r.iface === 'lo' || /^sit/.test(r.iface)) return;
            var label = r.iface;
            if (r.prog) label += '  ⚠ 当前已被 ' + r.prog + ' 占用';
            o.value(r.iface, label);
        });

        o = s.option(form.Value, 'lan_cidr', _('LAN 子网 CIDR'));
        o.datatype = 'cidr4'; o.placeholder='10.0.0.0/24'; o.rmempty = false;
        o = s.option(form.Value, 'queues',   _('并发队列数')); o.datatype='uinteger'; o.default='1';
        o = s.option(form.Flag,  'pin_cpus', _('worker 绑 CPU'));
        o = s.option(form.Value, 'wan_ip6',  _('WAN IPv6（启用 NAT66）')); o.datatype='ip6addr'; o.rmempty=true;
        o = s.option(form.Value, 'nat64_prefix', _('NAT64 前缀（如 64:ff9b::/96）'));
        o.placeholder='64:ff9b::/96'; o.rmempty=true;
        o = s.option(form.Value, 'nat46_v6_src', _('NAT46 共享 v6 源'));
        o.datatype='ip6addr'; o.placeholder='2001:db8::1'; o.rmempty=true;
        o = s.option(form.Flag,  'verbose',  _('详细日志'));

        s = m.section(form.TypedSection, 'forward', _('IPv4 端口转发 (DNAT)'));
        s.anonymous = true; s.addremove = true; s.addbtntitle = _('➕ 添加');
        o = s.option(form.Flag,   'enabled', _('启用')); o.default = '1';
        o = s.option(form.ListValue, 'proto', _('协议')); o.value('tcp','TCP'); o.value('udp','UDP');
        o = s.option(form.Value,  'wan_port', _('WAN 端口')); o.datatype='port';
        o = s.option(form.Value,  'lan_ip',   _('LAN IP'));   o.datatype='ip4addr';
        o = s.option(form.Value,  'lan_port', _('LAN 端口')); o.datatype='port';

        s = m.section(form.TypedSection, 'npt6', _('IPv6 NPTv6 前缀转换'));
        s.anonymous = true; s.addremove = true; s.addbtntitle = _('➕ 添加');
        o = s.option(form.Flag,  'enabled', _('启用')); o.default = '1';
        o = s.option(form.Value, 'inside',  _('内网前缀')); o.datatype='ip6addr';
        o = s.option(form.Value, 'outside', _('外网前缀')); o.datatype='ip6addr';
        o = s.option(form.Value, 'plen',    _('前缀长度')); o.datatype='range(1,128)'; o.default='64';

        s = m.section(form.TypedSection, 'nat46', _('NAT46 静态映射'));
        s.anonymous = true; s.addremove = true; s.addbtntitle = _('➕ 添加');
        o = s.option(form.Flag,  'enabled',   _('启用')); o.default = '1';
        o = s.option(form.Value, 'v4_target', _('v4 目标')); o.datatype='ip4addr';
        o = s.option(form.Value, 'v6_real',   _('v6 后端'));  o.datatype='ip6addr';

        /* === 卡片 3：快速操作（选好接口 → 一键启用 XDP NAT） === */
        var bottom = [];

        bottom.push(E('div', {'class':'cbi-section'}, [
            E('h3', {}, _('快速操作（一键启用 / 停止 XDP NAT）')),
            E('p', {'class':'cbi-value-description'},
                _('先在上方选好 WAN / LAN 接口与 IP、CIDR，点击"保存并应用"后，再点击下方按钮即可自动释放接口上的 XDP 占用并启动 xdp-fw 服务。')),
            E('div', {'style':'display:flex;gap:8px;flex-wrap:wrap;margin-top:10px'}, [
                E('button', {
                    'class': 'btn cbi-button-apply',
                    'style': 'background:#16a34a;color:#fff;padding:8px 18px;font-size:14px;font-weight:600;border:0;border-radius:4px;cursor:pointer;',
                    'click': ui.createHandlerFn(self, 'onAutoEnable')
                }, _('🚀 自动启用 XDP NAT')),
                E('button', {
                    'class': 'btn cbi-button-reset',
                    'style': 'background:#dc2626;color:#fff;padding:8px 18px;font-size:14px;font-weight:600;border:0;border-radius:4px;cursor:pointer;',
                    'click': ui.createHandlerFn(self, 'onStopNat')
                }, _('⏹ 停止 XDP NAT'))
            ]),
            E('p', {'class':'cbi-value-description', 'style':'margin-top:10px;color:#6b7280;font-size:12px;line-height:1.6'}, [
                _('"自动启用"执行：'),
                E('code',{},'xdp-ctl persist <wan> off'), ' → ',
                E('code',{},'xdp-ctl persist <lan> off'), ' → ',
                E('code',{},'/etc/init.d/xdp-fw enable'), ' → ',
                E('code',{},'restart'), '。',
                E('br'),
                _('若 WAN/LAN 当前被 xdp_main（XDP 加速）占用，这一步会先把它切到 off，由 xdp-fw 接管。')
            ])
        ]));

        /* === 卡片 4：运行统计 + 连接表（仅 running 时） === */
        if (running) {
            bottom.push(E('div', {'class':'cbi-section'}, [
                E('h3', {}, _('运行统计')),
                E('div', {'class':'table'}, [
                    E('div',{'class':'tr'},[E('div',{'class':'td'},_('NAT 活跃:')),  E('div',{'class':'td'},stats.nat_active||'0')]),
                    E('div',{'class':'tr'},[E('div',{'class':'td'},_('DNAT 命中:')),E('div',{'class':'td'},stats.dnat_hits||'0')]),
                    E('div',{'class':'tr'},[E('div',{'class':'td'},'WAN rx/tx/drop:'),
                        E('div',{'class':'td'},(stats.wan_rx_pkts||0)+' / '+(stats.wan_tx_pkts||0)+' / '+(stats.wan_drop||0))]),
                    E('div',{'class':'tr'},[E('div',{'class':'td'},'LAN rx/tx/drop:'),
                        E('div',{'class':'td'},(stats.lan_rx_pkts||0)+' / '+(stats.lan_tx_pkts||0)+' / '+(stats.lan_drop||0))])
                ])
            ]));
            bottom.push(E('div', {'class':'cbi-section'}, [
                E('h3', {}, _('连接表（最近一次 dump）')),
                E('pre', {
                    'style':'background:#0b1624;color:#d8e3ef;padding:12px;border-radius:6px;'+
                            'font-size:12px;max-height:250px;overflow:auto;white-space:pre-wrap;'
                }, conns_text || _('(空)')),
                E('button', {
                    'class':'btn',
                    'click': ui.createHandlerFn(self, 'onRefreshConns')
                }, _('🔄 触发 dump'))
            ]));
        }

        return m.render().then(function(mapnode) {
            return E('div', {}, [root].concat([mapnode]).concat(bottom));
        });
    },

    onRefreshConns: function() {
        return runCtl(['conns']).then(function(){ window.location.reload(); });
    },

    onSetMode: function(iface, mode) {
        return runXdpCtl(['persist', iface, mode]).then(function(r){
            var ok = (r.code === 0);
            ui.addNotification(null, E('p', [
                ok ? '✓ ' : '✗ ',
                iface, ' → ', mode,
                E('br'),
                E('small', {'style':'color:#6b7280'}, (r.stdout||'').trim() || (r.stderr||'').trim())
            ]), ok ? 'info' : 'danger');
            setTimeout(function(){ window.location.reload(); }, 800);
        });
    },

    onAutoEnable: function() {
        /* 如果内核不支持 AF_XDP，直接拒绝，不要尝试 restart（否则 procd 进入 crash loop） */
        if (this._kernelNoXsk) {
            ui.addNotification(null, E('div', [
                E('p', {}, E('strong', {'style':'color:#dc2626'},
                    '🚫 ' + _('当前内核不支持 AF_XDP，无法启动 xdp-fw'))),
                E('p', {'style':'font-size:13px;margin:6px 0'},
                    _('原因：CONFIG_XDP_SOCKETS 未编入内核，xsks_map 创建会被 kernel 拒绝。')),
                E('p', {'style':'font-size:13px'},
                    _('修复：重编 OpenWrt 内核并启用 CONFIG_XDP_SOCKETS=y，详见页面顶部的红色提示。'))
            ]), 'danger');
            return Promise.resolve();
        }

        var wan_if   = uci.get('xdp-fw', 'main', 'wan_if');
        var lan_if   = uci.get('xdp-fw', 'main', 'lan_if');
        var wan_ip   = uci.get('xdp-fw', 'main', 'wan_ip');
        var lan_cidr = uci.get('xdp-fw', 'main', 'lan_cidr');

        if (!wan_if || !lan_if) {
            ui.addNotification(null, E('p',
                _('请先在上方选择 WAN 和 LAN 接口，点击"保存并应用"后再执行此操作。')), 'warning');
            return Promise.resolve();
        }
        if (wan_if === lan_if) {
            ui.addNotification(null, E('p', _('WAN 和 LAN 接口不能相同。')), 'warning');
            return Promise.resolve();
        }
        if (!wan_ip) {
            ui.addNotification(null, E('p', _('请先填写 WAN IPv4 地址并保存。')), 'warning');
            return Promise.resolve();
        }
        if (!lan_cidr) {
            ui.addNotification(null, E('p', _('请先填写 LAN 子网 CIDR 并保存。')), 'warning');
            return Promise.resolve();
        }

        ui.addNotification(null, E('p', [
            E('strong', {}, _('正在启用 XDP NAT...')), E('br'),
            E('small', {'style':'color:#6b7280'},
                'WAN=' + wan_if + ' / LAN=' + lan_if +
                ' / WAN_IP=' + wan_ip + ' / LAN_CIDR=' + lan_cidr),
            E('br'),
            E('small', {'style':'color:#6b7280'},
                _('预计 4-5 秒（含 2 秒 crash-loop 检查）'))
        ]), 'info');

        var sleep = function(ms){ return new Promise(function(r){ setTimeout(r, ms); }); };

        /* 步骤 0：先 stop，防止 procd 处于 crash loop 状态下 restart 不干净 */
        return fs.exec('/etc/init.d/xdp-fw', ['stop']).catch(function(){return null;}).then(function(){
            /* 步骤 1：把 WAN / LAN 上其它 XDP 程序卸掉（释放槽位） */
            return runXdpCtl(['persist', wan_if, 'off']);
        }).then(function(){
            return runXdpCtl(['persist', lan_if, 'off']);
        }).then(function(){
            /* 步骤 2：procd enable + start */
            return fs.exec('/etc/init.d/xdp-fw', ['enable']);
        }).then(function(){
            return fs.exec('/etc/init.d/xdp-fw', ['start']);
        }).then(function(){
            /* 步骤 3：给守护进程 2 秒时间稳定（或 crash） */
            return sleep(2000);
        }).then(function(){
            /* 步骤 4：验证是不是真活着 */
            return fs.exec('/usr/bin/pgrep', ['xdp_fw']).catch(function(){return {stdout:''};});
        }).then(function(r){
            var pids = ((r && r.stdout) || '').trim();
            var alive = !!pids;
            if (alive) {
                ui.addNotification(null, E('p', [
                    E('strong', {'style':'color:#16a34a'}, '✅ ' + _('XDP NAT 启用成功')),
                    E('br'),
                    E('small', {'style':'color:#6b7280'},
                        _('守护进程 PID：') + pids.replace(/\s+/g,' ') +
                        _('；1.5 秒后刷新页面。'))
                ]), 'info');
                setTimeout(function(){ window.location.reload(); }, 1500);
                return;
            }
            /* 没活着——拉 logread 最后 20 行里跟 xdp 有关的给用户看 */
            return fs.exec('/sbin/logread', []).catch(function(){return {stdout:''};}).then(function(lr){
                var log = ((lr && lr.stdout) || '').split('\n')
                    .filter(function(l){ return /xdp/i.test(l); })
                    .slice(-15).join('\n');
                ui.addNotification(null, E('div', [
                    E('p', {}, E('strong', {'style':'color:#dc2626'},
                        '❌ ' + _('XDP NAT 启动后 2 秒内 crash（未检测到 xdp_fw 进程）'))),
                    E('p', {'style':'font-size:13px;margin:6px 0'},
                        _('通常原因：BPF 程序加载失败、BTF 不兼容、或 XDP 无法 attach 到接口。')),
                    E('pre', {
                        'style': 'background:#0b1624;color:#d8e3ef;padding:10px;border-radius:4px;' +
                                 'font-size:11px;max-height:220px;overflow:auto;white-space:pre-wrap;' +
                                 'margin-top:8px;'
                    }, log || _('(logread 为空或无匹配 xdp 的日志)')),
                    E('p', {'style':'font-size:12px;color:#6b7280;margin-top:8px'},
                        _('SSH 进一步排查：'),
                        E('code', {}, 'logread | grep -i xdp | tail -30'))
                ]), 'danger');
                /* 不 reload ——让用户看清错误信息再手动刷新 */
            });
        }).catch(function(e){
            ui.addNotification(null, E('p', '✗ ' + String(e)), 'danger');
        });
    },

    onStopNat: function() {
        return fs.exec('/etc/init.d/xdp-fw', ['stop']).then(function(r){
            var ok  = (r && r.code === 0);
            var msg = ((r && r.stdout) || '').trim() ||
                      ((r && r.stderr) || '').trim() ||
                      (ok ? 'stop ok' : '(no output)');
            ui.addNotification(null, E('p', [
                ok ? '✓ ' : '✗ ',
                _('XDP NAT 已停止'),
                E('br'),
                E('small', {'style':'color:#6b7280'}, msg)
            ]), ok ? 'info' : 'danger');
            setTimeout(function(){ window.location.reload(); }, 1000);
        }).catch(function(e){
            ui.addNotification(null, E('p', '✗ ' + String(e)), 'danger');
        });
    }
});
