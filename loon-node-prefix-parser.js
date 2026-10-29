/*
 * Loon 订阅解析插件 v3 · 全格式解析 + 节点名前缀
 * ---------------------------------------------------------------
 * 输入支持：
 *   Loon 标准行 / 节点 URI（ss ssr vmess vless trojan hysteria2 anytls socks http）
 *   Base64 整份 / Clash YAML（全字段）/ sing-box JSON / V2Ray JSON
 * 输出：Loon 标准节点行
 *
 * 额外：节点名前缀、幂等、Clash/sing-box 转换后按 server:port 去重
 *
 * Loon 不支持的协议（tuic / snell / hysteria v1）会被跳过，因为导入也没用。
 *
 * 用法：订阅 = URL,parser-enabled = true,parser-plugin=<本文件URL>,argument="prefix=【1】"
 * 更新：2026-10-29
 */

(function () {
  'use strict';

  /* ==================== 1. 参数 ==================== */
  var PREFIX = (function () {
    var a = (typeof $argument !== 'undefined') ? $argument : '';
    if (a && typeof a === 'object') return String(a.prefix || a.name || a.p || '').trim();
    var raw = String(a == null ? '' : a).trim();
    if (!raw) return '';
    var m = raw.match(/(?:^|&)prefix=([^&]*)/i);
    if (m) { try { return decodeURIComponent(m[1]).trim(); } catch (e) { return m[1].trim(); } }
    if (raw.indexOf('=') >= 0) return '';
    return raw;
  })();

  var INPUT = '';
  if (typeof $resource === 'string') INPUT = $resource;
  else if ($resource && typeof $resource === 'object' && typeof $resource.body === 'string') INPUT = $resource.body;

  /* ==================== 2. 通用工具 ==================== */
  function unq(v) {
    if (v == null) return '';
    v = String(v).trim();
    if (v.length > 1 && ((v.charAt(0) === '"' && v.charAt(v.length - 1) === '"') ||
        (v.charAt(0) === "'" && v.charAt(v.length - 1) === "'"))) {
      v = v.slice(1, -1);
    }
    return v.replace(/\s+/g, ' ').trim();
  }

  function b64(s) {
    var t = String(s).replace(/\s+/g, '');
    if (!/^[A-Za-z0-9+/=_-]+$/.test(t) || t.length < 8) return null;
    try {
      var x = t.replace(/-/g, '+').replace(/_/g, '/');
      while (x.length % 4) x += '=';
      var out;
      if (typeof atob === 'function') out = atob(x);
      else if (typeof Buffer !== 'undefined') out = Buffer.from(x, 'base64').toString('binary');
      else return null;
      try { return decodeURIComponent(escape(out)); } catch (e) { return out; }
    } catch (e) { return null; }
  }

  function truthy(v) { return v === true || v === 'true' || v === 1 || v === '1'; }

  function splitHostPort(v) {
    var i = v.lastIndexOf(':');
    if (i < 0) return [v, '443'];
    return [v.slice(0, i).replace(/^\[|\]$/g, ''), v.slice(i + 1)];
  }

  var LOON_PROTOCOLS = /^(shadowsocks|shadowsocksr|ss|ssr|vmess|vless|trojan|http|https|socks5|wireguard|hysteria2|hysteria|anytls|tuic|snell)\b/i;

  function dedupe(lines) {
    var seen = {}, out = [];
    for (var i = 0; i < lines.length; i++) {
      var l = lines[i];
      var eq = l.indexOf('=');
      var key = null;
      if (eq > 0) {
        var parts = l.slice(eq + 1).split(',');
        if (parts.length > 2) key = unq(parts[1]) + ':' + unq(parts[2]);
      }
      if (key) { if (seen[key]) continue; seen[key] = 1; }
      out.push(l);
    }
    return out;
  }

  /* 把 Clash/sing-box 的 tls/transport 参数统一成 Loon 参数串 */
  function tlsParams(sni, skipCert, alpn, fp) {
    var out = [];
    if (sni) out.push('sni=' + sni);
    if (skipCert) out.push('skip-cert-verify=true');
    if (alpn) out.push('alpn=' + alpn);
    if (fp) out.push('tls-profile=' + mapFp(fp));
    return out;
  }
  function mapFp(fp) {
    fp = String(fp || '').toLowerCase();
    if (fp === 'chrome') return 'chrome';
    if (fp === 'safari') return 'safari-ios18';
    if (fp === 'firefox' || fp === 'random' || fp === 'randomized') return 'default';
    return fp || 'default';
  }

  /* ==================== 3. Clash YAML -> Loon ==================== */
  function parseYaml(text) {
    var lines = text.split('\n');
    var start = -1;
    for (var i = 0; i < lines.length; i++) {
      if (/^proxies\s*:/.test(lines[i])) { start = i; break; }
    }
    if (start < 0) return null;
    var inline = lines[start].slice(lines[start].indexOf(':') + 1).trim();
    if (inline.replace(/\s/g, '') === '[]') return [];

    var end = lines.length;
    for (var j = start + 1; j < lines.length; j++) {
      if (!lines[j].trim()) continue;
      if (!/^\s/.test(lines[j])) { end = j; break; }
    }

    var items = [], cur = null, paths = [];
    for (var k = start + 1; k < end; k++) {
      var raw = lines[k];
      if (!raw.trim() || /^\s*#/.test(raw)) continue;
      var indent = raw.match(/^\s*/)[0].length;
      var body = raw.trim();

      var mItem = body.match(/^-\s*(.*)$/);
      if (mItem) {
        if (cur) items.push(cur);
        cur = {}; paths = [];
        var rest = mItem[1];
        if (rest) {
          if (rest.charAt(0) === '{') parseFlow(rest, cur);
          else assignToPath(cur, paths, rest, indent + 2);
        }
        continue;
      }
      if (cur) assignToPath(cur, paths, body, indent);
    }
    if (cur) items.push(cur);

    var out = [];
    for (var n = 0; n < items.length; n++) {
      var ln = yamlItemToLoon(items[n]);
      if (ln) out.push(ln);
    }
    return out;
  }

  /* 按缩进维护路径栈，正确处理 plugin-opts / ws-opts / grpc-opts 这类嵌套块 */
  function assignToPath(obj, paths, body, indent) {
    var m = body.match(/^([A-Za-z0-9_.-]+)\s*:\s*(.*)$/);
    if (!m) return;
    var key = m[1], val = m[2];
    while (paths.length && paths[paths.length - 1].indent >= indent) paths.pop();

    var target = obj;
    for (var i = 0; i < paths.length; i++) {
      var pk = paths[i].key;
      if (!target[pk] || typeof target[pk] !== 'object') target[pk] = {};
      target = target[pk];
    }

    if (val === '') {
      paths.push({ indent: indent, key: key });
      if (!target[key] || typeof target[key] !== 'object') target[key] = {};
      return;
    }
    setDeep(target, key, unq(val));
  }

  function parseFlow(s, obj) {
    var body = s.replace(/^\{/, '').replace(/\}\s*$/, '');
    body.split(',').forEach(function (part) {
      var i = part.indexOf(':');
      if (i > 0) obj[part.slice(0, i).trim()] = unq(part.slice(i + 1));
    });
  }

  function setDeep(obj, key, val) {
    if (key.indexOf('.') > 0) {
      var parts = key.split('.');
      var o = obj;
      for (var i = 0; i < parts.length - 1; i++) {
        if (!o[parts[i]] || typeof o[parts[i]] !== 'object') o[parts[i]] = {};
        o = o[parts[i]];
      }
      o[parts[parts.length - 1]] = val;
      return;
    }
    obj[key] = val;
  }

  function getNested(o, path) {
    var parts = path.split('.');
    var cur = o;
    for (var i = 0; i < parts.length; i++) {
      if (!cur || typeof cur !== 'object') return undefined;
      cur = cur[parts[i]];
    }
    return cur;
  }

  function yamlItemToLoon(p) {
    var t = String(p.type || '').toLowerCase();
    var name = unq(p.name) || (p.server + ':' + p.port);
    var server = unq(p.server), port = unq(p.port);
    if (!server || !port) return null;

    var common = [];
    if (truthy(p.udp)) common.push('udp=true');
    if (truthy(p['skip-cert-verify'])) common.push('skip-cert-verify=true');

    var sni = unq(p.sni || p.servername || getNested(p, 'ws-opts.headers.Host') || '');
    var net = unq(p.network || 'tcp');
    var wsPath = unq(getNested(p, 'ws-opts.path') || '');
    var wsHost = unq(getNested(p, 'ws-opts.headers.Host') || '');
    var grpcSvc = unq(getNested(p, 'grpc-opts.grpc-service-name') || '');
    var alpn = unq(p.alpn || '');
    var fp = unq(p['client-fingerprint'] || '');

    if (t === 'ss' || t === 'shadowsocks') {
      var a = ['Shadowsocks', server, port, unq(p.cipher), '"' + unq(p.password) + '"'];
      var plug = unq(p.plugin || '');
      var po = p['plugin-opts'] || {};
      if (plug === 'obfs') {
        if (po.mode) a.push('obfs-name=' + unq(po.mode));
        if (po.host) a.push('obfs-host=' + unq(po.host));
      }
      return name + '=' + a.concat(common).join(',');
    }

    if (t === 'ssr') {
      var b = ['ShadowsocksR', server, port, unq(p.cipher), '"' + unq(p.password) + '"'];
      if (p.protocol) b.push('protocol=' + unq(p.protocol));
      if (p['protocol-param']) b.push('protocol-param=' + unq(p['protocol-param']));
      if (p.obfs) b.push('obfs=' + unq(p.obfs));
      if (p['obfs-param']) b.push('obfs-param=' + unq(p['obfs-param']));
      return name + '=' + b.concat(common).join(',');
    }

    if (t === 'vmess') {
      var c = ['VMess', server, port, unq(p.cipher || 'auto'), '"' + unq(p.uuid) + '"',
               'transport=' + transName(net), 'alterId=' + (p['alter-id'] || p.alterId || 0)];
      c = c.concat(transParams(net, wsPath, wsHost, grpcSvc));
      if (truthy(p.tls)) c.push('over-tls=true');
      if (sni) c.push('sni=' + sni);
      if (alpn) c.push('alpn=' + alpn);
      if (fp) c.push('tls-profile=' + mapFp(fp));
      return name + '=' + c.concat(common).join(',');
    }

    if (t === 'vless') {
      var d = ['VLESS', server, port, '"' + unq(p.uuid) + '"', 'transport=' + transName(net)];
      d = d.concat(transParams(net, wsPath, wsHost, grpcSvc));
      if (p.flow) d.push('flow=' + unq(p.flow));
      var ro = p['reality-opts'] || {};
      if (ro['public-key']) d.push('public-key="' + unq(ro['public-key']) + '"');
      if (ro['short-id']) d.push('short-id=' + unq(ro['short-id']));
      if (truthy(p.tls) || ro['public-key']) d.push('over-tls=true');
      if (sni) d.push('sni=' + sni);
      if (fp) d.push('tls-profile=' + mapFp(fp));
      return name + '=' + d.concat(common).join(',');
    }

    if (t === 'trojan') {
      var e = ['Trojan', server, port, '"' + unq(p.password) + '"', 'transport=' + transName(net)];
      e = e.concat(transParams(net, wsPath, wsHost, grpcSvc));
      if (sni) e.push('sni=' + sni);
      if (alpn) e.push('alpn=' + alpn);
      return name + '=' + e.concat(common).join(',');
    }

    if (t === 'hysteria2' || t === 'hy2') {
      var f = ['Hysteria2', server, port, '"' + unq(p.password || p.auth) + '"'];
      if (sni) f.push('sni=' + sni);
      if (p.obfs) f.push('obfs=' + unq(p.obfs));
      if (p['obfs-password']) f.push('obfs-password=' + unq(p['obfs-password']));
      return name + '=' + f.concat(common).join(',');
    }

    if (t === 'anytls') {
      var g = ['anytls', server, port, '"' + unq(p.password) + '"'];
      if (sni) g.push('sni=' + sni);
      return name + '=' + g.concat(common).join(',');
    }

    if (t === 'http' || t === 'https' || t === 'socks5') {
      var h = [t === 'socks5' ? 'socks5' : t, server, port];
      if (p.username) h.push(unq(p.username));
      if (p.password) h.push('"' + unq(p.password) + '"');
      if (t === 'https' || truthy(p.tls)) h.push('over-tls=true');
      if (sni) h.push('sni=' + sni);
      return name + '=' + h.concat(common).join(',');
    }

    if (t === 'wireguard') {
      var w = ['WireGuard', 'interface-ip=' + unq(p.ip || '172.16.0.2')];
      if (p.ipv6) w.push('interface-ipv6=' + unq(p.ipv6));
      if (p['private-key']) w.push('private-key="' + unq(p['private-key']) + '"');
      if (p.mtu) w.push('mtu=' + unq(p.mtu));
      var peer = 'public-key="' + unq(p['public-key']) + '",endpoint=' + server + ':' + port;
      if (p['preshared-key']) peer += ',preshared-key="' + unq(p['preshared-key']) + '"';
      peer += ',allowed-ips="0.0.0.0/0,::/0"';
      w.push('peers=[{' + peer + '}]');
      return name + '=' + w.concat(common).join(',');
    }

    // tuic / snell / hysteria v1：Loon 不支持，跳过
    return null;
  }

  function transName(net) {
    net = String(net || 'tcp').toLowerCase();
    if (net === 'ws' || net === 'websocket') return 'ws';
    if (net === 'grpc') return 'grpc';
    if (net === 'h2' || net === 'http') return 'h2';
    return 'tcp';
  }

  function transParams(net, path, host, svc) {
    var out = [];
    if (net === 'ws' || net === 'websocket') {
      if (path) out.push('path=' + path);
      if (host) out.push('host=' + host);
    } else if (net === 'grpc') {
      if (svc) out.push('grpc-service-name=' + svc);
    } else if (net === 'h2' || net === 'http') {
      if (path) out.push('path=' + path);
      if (host) out.push('host=' + host);
    }
    return out;
  }

  /* ==================== 4. sing-box JSON -> Loon ==================== */
  function isSingBox(o) {
    if (!o || !o.outbounds || !o.outbounds.length) return false;
    var first = o.outbounds[0];
    return !!(first && first.type && first.server !== undefined || (first && first.type && first.type !== 'direct' && first.type !== 'block'));
  }

  function parseSingBox(o) {
    var out = [];
    var list = o.outbounds || [];
    for (var i = 0; i < list.length; i++) {
      var b = list[i];
      if (!b || !b.type) continue;
      var t = String(b.type).toLowerCase();
      if (t === 'direct' || t === 'block' || t === 'dns' || t === 'selector' || t === 'urltest') continue;
      var ln = singBoxToLoon(b);
      if (ln) out.push(ln);
    }
    return out;
  }

  function singBoxToLoon(b) {
    var t = String(b.type).toLowerCase();
    var name = unq(b.tag) || (b.server + ':' + b.server_port);
    var server = unq(b.server), port = unq(b.server_port || b.port);
    if (!server || !port) return null;

    var tls = b.tls || {};
    var sni = unq(tls.server_name || b.server_name || '');
    var insecure = truthy(tls.insecure);
    var tr = b.transport || {};
    var net = unq(tr.type || 'tcp');
    var wsPath = unq(tr.path || '');
    var wsHost = unq(getNested(tr, 'headers.Host') || getNested(tr, 'headers.host') || '');
    var grpcSvc = unq(tr.service_name || '');
    var common = [];
    if (truthy(b.udp) || t === 'hysteria2') common.push('udp=true');
    if (insecure) common.push('skip-cert-verify=true');
    var reality = tls.reality || {};

    if (t === 'shadowsocks') {
      var a = ['Shadowsocks', server, port, unq(b.method), '"' + unq(b.password) + '"'];
      return name + '=' + a.concat(common).join(',');
    }
    if (t === 'shadowsocksr') {
      var s2 = ['ShadowsocksR', server, port, unq(b.method), '"' + unq(b.password) + '"'];
      if (b.protocol) s2.push('protocol=' + unq(b.protocol));
      if (b.protocol_param) s2.push('protocol-param=' + unq(b.protocol_param));
      if (b.obfs) s2.push('obfs=' + unq(b.obfs));
      if (b.obfs_param) s2.push('obfs-param=' + unq(b.obfs_param));
      return name + '=' + s2.concat(common).join(',');
    }
    if (t === 'vmess') {
      var c = ['VMess', server, port, unq(b.security || 'auto'), '"' + unq(b.uuid) + '"',
               'transport=' + transName(net), 'alterId=' + (b.alter_id || 0)];
      c = c.concat(transParams(net, wsPath, wsHost, grpcSvc));
      if (tls.enabled) c.push('over-tls=true');
      if (sni) c.push('sni=' + sni);
      return name + '=' + c.concat(common).join(',');
    }
    if (t === 'vless') {
      var d = ['VLESS', server, port, '"' + unq(b.uuid) + '"', 'transport=' + transName(net)];
      d = d.concat(transParams(net, wsPath, wsHost, grpcSvc));
      if (b.flow) d.push('flow=' + unq(b.flow));
      if (reality.public_key) d.push('public-key="' + unq(reality.public_key) + '"');
      if (reality.short_id) d.push('short-id=' + unq(reality.short_id));
      if (tls.enabled || reality.public_key) d.push('over-tls=true');
      if (sni) d.push('sni=' + sni);
      return name + '=' + d.concat(common).join(',');
    }
    if (t === 'trojan') {
      var e = ['Trojan', server, port, '"' + unq(b.password) + '"', 'transport=' + transName(net)];
      e = e.concat(transParams(net, wsPath, wsHost, grpcSvc));
      if (sni) e.push('sni=' + sni);
      return name + '=' + e.concat(common).join(',');
    }
    if (t === 'hysteria2') {
      var f = ['Hysteria2', server, port, '"' + unq(b.password) + '"'];
      if (sni) f.push('sni=' + sni);
      return name + '=' + f.concat(common).join(',');
    }
    if (t === 'anytls') {
      var g = ['anytls', server, port, '"' + unq(b.password) + '"'];
      if (sni) g.push('sni=' + sni);
      return name + '=' + g.concat(common).join(',');
    }
    if (t === 'socks' || t === 'http') {
      var h = [t === 'socks' ? 'socks5' : 'http', server, port];
      if (b.username) h.push(unq(b.username));
      if (b.password) h.push('"' + unq(b.password) + '"');
      if (truthy(tls.enabled)) h.push('over-tls=true');
      return name + '=' + h.concat(common).join(',');
    }
    return null; // tuic / snell / wireguard(sing-box 结构特殊) 交给 Loon 原生
  }

  /* ==================== 5. V2Ray JSON -> Loon ==================== */
  function isV2ray(o) {
    if (!o || !o.outbounds || !o.outbounds.length) return false;
    return !!o.outbounds[0].protocol;
  }

  function parseV2ray(o) {
    var out = [];
    var list = o.outbounds || [];
    for (var i = 0; i < list.length; i++) {
      var b = list[i];
      if (!b || !b.protocol) continue;
      var ln = v2rayToLoon(b);
      if (ln) out.push(ln);
    }
    return out;
  }

  function v2rayToLoon(b) {
    var proto = String(b.protocol).toLowerCase();
    if (proto === 'freedom' || proto === 'blackhole' || proto === 'dns') return null;
    var st = b.streamSettings || {};
    var net = unq(st.network || 'tcp');
    var sec = unq(st.security || 'none');
    var tlsSet = st.tlsSettings || {};
    var sni = unq(tlsSet.serverName || '');
    var insecure = truthy(tlsSet.allowInsecure);
    var wsSet = st.wsSettings || {};
    var wsPath = unq(wsSet.path || '');
    var wsHost = unq(getNested(wsSet, 'headers.Host') || '');
    var grpcSvc = unq(getNested(st, 'grpcSettings.serviceName') || '');
    var reality = st.realitySettings || {};
    var common = [];
    if (insecure) common.push('skip-cert-verify=true');

    var settings = b.settings || {};

    if (proto === 'vmess' || proto === 'vless') {
      var vn = (settings.vnext || [])[0] || {};
      var user = (vn.users || [])[0] || {};
      var server = unq(vn.address), port = unq(vn.port);
      if (!server || !port) return null;
      var name = unq(b.tag) || (server + ':' + port);
      var head = proto === 'vmess'
        ? ['VMess', server, port, unq(user.security || 'auto'), '"' + unq(user.id) + '"', 'transport=' + transName(net), 'alterId=' + (user.alterId || 0)]
        : ['VLESS', server, port, '"' + unq(user.id) + '"', 'transport=' + transName(net)];
      head = head.concat(transParams(net, wsPath, wsHost, grpcSvc));
      if (proto === 'vless' && user.flow) head.push('flow=' + unq(user.flow));
      if (reality.publicKey) head.push('public-key="' + unq(reality.publicKey) + '"');
      if (reality.shortId) head.push('short-id=' + unq(reality.shortId));
      if (sec === 'tls' || sec === 'reality') head.push('over-tls=true');
      if (sni) head.push('sni=' + sni);
      return name + '=' + head.concat(common).join(',');
    }

    if (proto === 'shadowsocks') {
      var sv = (settings.servers || [])[0] || {};
      var s3 = unq(sv.address), p3 = unq(sv.port);
      if (!s3) return null;
      var n3 = unq(b.tag) || (s3 + ':' + p3);
      return n3 + '=' + ['Shadowsocks', s3, p3, unq(sv.method), '"' + unq(sv.password) + '"'].concat(common).join(',');
    }

    if (proto === 'trojan') {
      var sv2 = (settings.servers || [])[0] || {};
      var s4 = unq(sv2.address), p4 = unq(sv2.port);
      if (!s4) return null;
      var n4 = unq(b.tag) || (s4 + ':' + p4);
      var t4 = ['Trojan', s4, p4, '"' + unq(sv2.password) + '"', 'transport=' + transName(net)];
      t4 = t4.concat(transParams(net, wsPath, wsHost, grpcSvc));
      if (sni) t4.push('sni=' + sni);
      return n4 + '=' + t4.concat(common).join(',');
    }

    return null;
  }

  /* ==================== 6. SSR URI ==================== */
  function parseSSR(line) {
    var s = line.trim();
    var hash = s.indexOf('#');
    var b64part = s.slice(6, hash >= 0 ? hash : s.length);
    var dec = b64(b64part);
    if (!dec) return null;
    var q = dec.indexOf('?');
    var main = q >= 0 ? dec.slice(0, q) : dec;
    var query = q >= 0 ? dec.slice(q + 1) : '';
    var parts = main.split(':');
    if (parts.length < 6) return null;
    var server = parts[0], port = parts[1], protocol = parts[2], method = parts[3], obfs = parts[4];
    var pwdB64 = parts.slice(5).join(':');
    var pwd = b64(pwdB64) || pwdB64;
    var opts = {};
    query.split('&').forEach(function (kv) {
      var i2 = kv.indexOf('=');
      if (i2 > 0) opts[kv.slice(0, i2)] = kv.slice(i2 + 1);
    });
    var remarks = opts.remarks ? (b64(opts.remarks) || '') : '';
    var name = remarks || (server + ':' + port);
    var out = ['ShadowsocksR', server, port, method, '"' + pwd + '"',
               'protocol=' + protocol, 'obfs=' + obfs];
    if (opts.protoparam) out.push('protocol-param=' + (b64(opts.protoparam) || opts.protoparam));
    if (opts.obfsparam) out.push('obfs-param=' + (b64(opts.obfsparam) || opts.obfsparam));
    return name + '=' + out.join(',');
  }

  /* ==================== 6.5 Quantumult X 格式 -> Loon ==================== */
  var QX_LINE = /^(shadowsocks|vmess|vless|trojan|http|https|socks5|ssr)\s*=\s*[^,\s]+/im;

  function isQX(text) { return QX_LINE.test(text); }

  function parseKV(s) {
    var o = {};
    if (!s) return o;
    s.split(/,\s*(?=[a-z0-9_.-]+\s*=)/i).forEach(function (p) {
      var i = p.indexOf('=');
      if (i > 0) o[p.slice(0, i).trim().toLowerCase()] = p.slice(i + 1).trim();
    });
    return o;
  }

  function parseQX(text) {
    var out = [];
    var lines = text.split('\n');
    for (var i = 0; i < lines.length; i++) {
      var t = lines[i].trim();
      if (!t || t.charAt(0) === '#' || t.charAt(0) === ';' || t.charAt(0) === '/') continue;
      var m = t.match(/^([a-z0-9]+)\s*=\s*([^,]+)\s*(?:,\s*([\s\S]*))?$/i);
      if (!m) continue;
      var ln = null;
      try { ln = qxToLoon(m[1].toLowerCase(), m[2].trim(), parseKV(m[3] || '')); } catch (e) { ln = null; }
      if (ln) out.push(ln);
    }
    return out;
  }

  function qxToLoon(type, hostport, kv) {
    var hp = splitHostPort(hostport);
    var server = hp[0], port = hp[1];
    if (!server || !port) return null;
    var name = unq(kv.tag) || (server + ':' + port);

    var common = [];
    if (truthy(kv['udp-relay'])) common.push('udp=true');
    if (String(kv['tls-verification']) === 'false') common.push('skip-cert-verify=true');
    var overTls = truthy(kv['over-tls']);
    var obfs = unq(kv.obfs || '');
    var wsPath = unq(kv['obfs-uri'] || '');
    var wsHost = unq(kv['obfs-host'] || '');
    var sni = unq(kv['tls-host'] || kv.sni || '');

    if (type === 'shadowsocks') {
      var a = ['Shadowsocks', server, port, unq(kv.method), '"' + unq(kv.password) + '"'];
      if (obfs === 'http' || obfs === 'tls') {
        a.push('obfs-name=' + obfs);
        if (wsHost) a.push('obfs-host=' + wsHost);
        if (wsPath) a.push('obfs-uri=' + wsPath);
      }
      // obfs=ws：Loon 的 Shadowsocks 不支持 ws 混淆，按普通 ss 输出（可能连不上）
      return name + '=' + a.concat(common).join(',');
    }

    if (type === 'ssr') {
      var r = ['ShadowsocksR', server, port, unq(kv.method), '"' + unq(kv.password) + '"'];
      if (kv.protocol) r.push('protocol=' + unq(kv.protocol));
      if (kv['protocol-param']) r.push('protocol-param=' + unq(kv['protocol-param']));
      if (kv.obfs) r.push('obfs=' + unq(kv.obfs));
      if (kv['obfs-param']) r.push('obfs-param=' + unq(kv['obfs-param']));
      return name + '=' + r.concat(common).join(',');
    }

    if (type === 'vmess') {
      var c = ['VMess', server, port, unq(kv.method || 'none'), '"' + unq(kv.password) + '"', 'alterId=' + (kv.aid || kv.alterid || 0)];
      if (obfs === 'ws') {
        c.push('transport=ws');
        if (wsPath) c.push('path=' + wsPath);
        if (wsHost) c.push('host=' + wsHost);
      } else if (obfs === 'http') {
        c.push('transport=h2');
        if (wsPath) c.push('path=' + wsPath);
        if (wsHost) c.push('host=' + wsHost);
      } else {
        c.push('transport=tcp');
      }
      if (overTls) c.push('over-tls=true');
      if (sni) c.push('sni=' + sni);
      return name + '=' + c.concat(common).join(',');
    }

    if (type === 'vless') {
      var d = ['VLESS', server, port, '"' + unq(kv.password || kv.uuid) + '"'];
      if (obfs === 'ws') {
        d.push('transport=ws');
        if (wsPath) d.push('path=' + wsPath);
        if (wsHost) d.push('host=' + wsHost);
      } else if (obfs === 'grpc') {
        d.push('transport=grpc');
        if (wsPath) d.push('grpc-service-name=' + wsPath);
      } else {
        d.push('transport=tcp');
      }
      if (kv.flow) d.push('flow=' + unq(kv.flow));
      if (kv['public-key']) d.push('public-key="' + unq(kv['public-key']) + '"');
      if (kv['short-id']) d.push('short-id=' + unq(kv['short-id']));
      if (overTls) d.push('over-tls=true');
      if (sni) d.push('sni=' + sni);
      return name + '=' + d.concat(common).join(',');
    }

    if (type === 'trojan') {
      var e;
      if (obfs === 'ws') {
        e = ['Trojan', server, port, '"' + unq(kv.password) + '"', 'transport=ws'];
        if (wsPath) e.push('path=' + wsPath);
        if (wsHost) e.push('host=' + wsHost);
      } else {
        e = ['Trojan', server, port, '"' + unq(kv.password) + '"', 'transport=tcp'];
      }
      if (sni) e.push('sni=' + sni);
      return name + '=' + e.concat(common).join(',');
    }

    if (type === 'http' || type === 'https' || type === 'socks5') {
      var h = [type === 'socks5' ? 'socks5' : 'http', server, port];
      if (kv.username) h.push(unq(kv.username));
      if (kv.password) h.push('"' + unq(kv.password) + '"');
      if (type === 'https' || overTls) h.push('over-tls=true');
      if (sni) h.push('sni=' + sni);
      return name + '=' + h.concat(common).join(',');
    }

    return null;
  }

  /* ==================== 6.6 Surge 格式 -> Loon ==================== */
  /* Surge: 节点名 = ss, 1.2.3.4, 443, encrypt-method=aes-256-gcm, password=pw, obfs=http, ... */
  var SURGE_LINE = /^[^=#\n]{1,64}?=\s*(ss|vmess|trojan|vless|http|https|socks5|hysteria2)\s*,\s*[^,\n]+,\s*\d+\s*,\s*[a-zA-Z][a-zA-Z0-9_-]*\s*=/im;

  function isSurge(text) {
    if (!SURGE_LINE.test(text)) return false;
    // 仅当出现 Loon 完整协议名（大小写敏感）时才判为 Loon，避免 Surge 的 = http, 被误伤
    var loonFull = /= *\s*(Shadowsocks|ShadowsocksR|VMess|VLESS|Trojan|Hysteria2|anytls|WireGuard),/;
    return !loonFull.test(text);
  }

  function parseSurge(text) {
    var out = [];
    var lines = text.split('\n');
    for (var i = 0; i < lines.length; i++) {
      var t = lines[i].trim();
      if (!t || t.charAt(0) === '#' || t.charAt(0) === ';') continue;
      var m = t.match(/^(.+?)\s*=\s*(ss|vmess|trojan|vless|http|https|socks5|hysteria2)\s*,\s*([^,\s]+)\s*,\s*(\d+)\s*(?:,\s*([\s\S]*))?$/i);
      if (!m) continue;
      var ln = null;
      try { ln = surgeToLoon(unq(m[1]), m[2].toLowerCase(), m[3].trim(), m[4].trim(), parseKV(m[5] || '')); } catch (e) { ln = null; }
      if (ln) out.push(ln);
    }
    return out;
  }

  function surgeToLoon(name, type, server, port, kv) {
    if (!name || !server || !port) return null;
    var common = [];
    if (truthy(kv['udp-relay']) || truthy(kv.udp)) common.push('udp=true');
    if (truthy(kv['skip-cert-verify'])) common.push('skip-cert-verify=true');
    var sni = unq(kv.sni || kv['peer-name'] || kv['tls-sni'] || '');
    var wsPath = unq(kv['ws-path'] || '');
    var wsHost = unq(kv['ws-headers'] || '');
    if (wsHost && wsHost.toLowerCase().indexOf('host:') === 0) wsHost = wsHost.slice(5).trim();
    var tlsOn = truthy(kv.tls) || truthy(kv['over-tls']);

    if (type === 'ss') {
      var a = ['Shadowsocks', server, port, unq(kv['encrypt-method'] || kv.method || 'aes-128-gcm'),
               '"' + unq(kv.password) + '"'];
      var obfs = unq(kv.obfs || '');
      if (obfs === 'http' || obfs === 'tls') {
        a.push('obfs-name=' + obfs);
        if (kv['obfs-host']) a.push('obfs-host=' + unq(kv['obfs-host']));
        if (kv['obfs-uri']) a.push('obfs-uri=' + unq(kv['obfs-uri']));
      }
      return name + '=' + a.concat(common).join(',');
    }

    if (type === 'vmess') {
      var c = ['VMess', server, port, unq(kv['encrypt-method'] || kv.method || 'auto'),
               '"' + unq(kv.username || kv.password) + '"', 'alterId=' + (kv.alterId || 0)];
      if (truthy(kv.ws)) {
        c.push('transport=ws');
        if (wsPath) c.push('path=' + wsPath);
        if (wsHost) c.push('host=' + wsHost);
      } else {
        c.push('transport=tcp');
      }
      if (tlsOn) c.push('over-tls=true');
      if (sni) c.push('sni=' + sni);
      return name + '=' + c.concat(common).join(',');
    }

    if (type === 'vless') {
      var d = ['VLESS', server, port, '"' + unq(kv.username || kv.password) + '"'];
      if (truthy(kv.ws)) {
        d.push('transport=ws');
        if (wsPath) d.push('path=' + wsPath);
        if (wsHost) d.push('host=' + wsHost);
      } else {
        d.push('transport=tcp');
      }
      if (kv.flow) d.push('flow=' + unq(kv.flow));
      if (tlsOn) d.push('over-tls=true');
      if (sni) d.push('sni=' + sni);
      return name + '=' + d.concat(common).join(',');
    }

    if (type === 'trojan') {
      var e;
      if (truthy(kv.ws)) {
        e = ['Trojan', server, port, '"' + unq(kv.password) + '"', 'transport=ws'];
        if (wsPath) e.push('path=' + wsPath);
        if (wsHost) e.push('host=' + wsHost);
      } else {
        e = ['Trojan', server, port, '"' + unq(kv.password) + '"', 'transport=tcp'];
      }
      if (sni) e.push('sni=' + sni);
      return name + '=' + e.concat(common).join(',');
    }

    if (type === 'hysteria2') {
      var f = ['Hysteria2', server, port, '"' + unq(kv.password || kv.auth) + '"'];
      if (sni) f.push('sni=' + sni);
      return name + '=' + f.concat(common).join(',');
    }

    if (type === 'http' || type === 'https' || type === 'socks5') {
      var h = [type === 'socks5' ? 'socks5' : 'http', server, port];
      if (kv.username) h.push(unq(kv.username));
      if (kv.password) h.push('"' + unq(kv.password) + '"');
      if (type === 'https' || tlsOn) h.push('over-tls=true');
      if (sni) h.push('sni=' + sni);
      return name + '=' + h.concat(common).join(',');
    }

    return null;
  }

  /* ==================== 7. URI -> Loon ==================== */
  function parseQuery(qs) {
    var o = {};
    if (!qs) return o;
    qs.split('&').forEach(function (kv) {
      var i = kv.indexOf('=');
      if (i > 0) {
        var k = kv.slice(0, i), v = kv.slice(i + 1);
        try { o[k] = decodeURIComponent(v); } catch (e) { o[k] = v; }
      }
    });
    return o;
  }

  function uriToLoon(line) {
    var s = line.trim();
    var sep = s.indexOf('://');
    if (sep < 0) return null;
    var scheme = s.slice(0, sep).toLowerCase();
    var rest = s.slice(sep + 3);

    var hash = rest.indexOf('#');
    var name = '';
    if (hash >= 0) {
      var rawName = rest.slice(hash + 1);
      try { name = decodeURIComponent(rawName); } catch (e) { name = rawName; }
      rest = rest.slice(0, hash);
    }

    if (scheme === 'ssr') return parseSSR(line);

    if (scheme === 'ss') {
      var qp = rest.indexOf('?');
      var query = qp >= 0 ? rest.slice(qp + 1) : '';
      var main = qp >= 0 ? rest.slice(0, qp) : rest;
      var at = main.lastIndexOf('@');
      var cred, hp;
      if (at >= 0) {
        cred = main.slice(0, at); hp = main.slice(at + 1);
        var d1 = b64(cred);
        if (d1 && d1.indexOf(':') >= 0) cred = d1;
        else { try { cred = decodeURIComponent(cred); } catch (e) {} }
      } else {
        var d2 = b64(main);
        if (!d2) return null;
        var at2 = d2.lastIndexOf('@');
        cred = d2.slice(0, at2); hp = d2.slice(at2 + 1);
      }
      var ci = cred.indexOf(':');
      if (ci < 0) return null;
      var cipher = cred.slice(0, ci), pwd = cred.slice(ci + 1);
      var sp = splitHostPort(hp);
      var out = ['Shadowsocks', sp[0], sp[1], cipher, '"' + pwd + '"'];
      var q = parseQuery(query);
      if (q.plugin) {
        var pl = decodeURIComponent(q.plugin);
        if (pl.indexOf('obfs') === 0) {
          var po = parseQuery(pl.replace(/^obfs[^;]*;/, '').replace(/;/g, '&'));
          if (po.mode) out.push('obfs-name=' + po.mode);
          if (po.host) out.push('obfs-host=' + po.host);
        }
      }
      return (name || sp[0] + ':' + sp[1]) + '=' + out.join(',');
    }

    if (scheme === 'vmess') {
      var j = b64(rest);
      if (!j) return null;
      var v;
      try { v = JSON.parse(j); } catch (e) { return null; }
      var server = unq(v.add), port = unq(v.port), uuid = unq(v.id);
      if (!server || !port) return null;
      var nm = name || unq(v.ps) || (server + ':' + port);
      var t = ['VMess', server, port, unq(v.scy || v.security || 'auto'), '"' + uuid + '"',
               'transport=' + transName(v.net || 'tcp'), 'alterId=' + (v.aid || 0)];
      if (v.net === 'ws') {
        if (v.path) t.push('path=' + unq(v.path));
        if (v.host) t.push('host=' + unq(v.host));
      } else if (v.net === 'grpc') {
        if (v.path) t.push('grpc-service-name=' + unq(v.path));
      }
      if (v.tls === 'tls' || v.tls === true || v.tls === 'reality') t.push('over-tls=true');
      if (v.sni) t.push('sni=' + unq(v.sni));
      return nm + '=' + t.join(',');
    }

    // 通用 userinfo@host:port?query 结构
    var qm = rest.indexOf('?');
    var query2 = qm >= 0 ? rest.slice(qm + 1) : '';
    var main2 = qm >= 0 ? rest.slice(0, qm) : rest;
    var at3 = main2.lastIndexOf('@');
    if (at3 < 0) return null;
    var userinfo = main2.slice(0, at3);
    try { userinfo = decodeURIComponent(userinfo); } catch (e) {}
    var sp2 = splitHostPort(main2.slice(at3 + 1));
    var q2 = parseQuery(query2);
    var nm2 = name || sp2[0] + ':' + sp2[1];
    var params = [];
    var net2 = q2.type || q2.net || 'tcp';

    if (scheme === 'vless') {
      var vl = ['VLESS', sp2[0], sp2[1], '"' + userinfo + '"', 'transport=' + transName(net2)];
      if (net2 === 'ws') {
        if (q2.path) vl.push('path=' + q2.path);
        if (q2.host) vl.push('host=' + q2.host);
      } else if (net2 === 'grpc') {
        if (q2.serviceName) vl.push('grpc-service-name=' + q2.serviceName);
      }
      if (q2.flow) vl.push('flow=' + q2.flow);
      if (q2.pbk) vl.push('public-key="' + q2.pbk + '"');
      if (q2.sid) vl.push('short-id=' + q2.sid);
      if (q2.security === 'tls' || q2.security === 'reality' || q2.tls === '1') vl.push('over-tls=true');
      if (q2.sni) vl.push('sni=' + q2.sni);
      if (q2.fp) vl.push('tls-profile=' + mapFp(q2.fp));
      if (q2.allowInsecure === '1' || q2.insecure === '1') vl.push('skip-cert-verify=true');
      return nm2 + '=' + vl.join(',');
    }

    if (scheme === 'trojan' || scheme === 'trojan-go') {
      var tr = ['Trojan', sp2[0], sp2[1], '"' + userinfo + '"', 'transport=' + transName(net2)];
      if (net2 === 'ws') {
        if (q2.path) tr.push('path=' + q2.path);
        if (q2.host) tr.push('host=' + q2.host);
      } else if (net2 === 'grpc') {
        if (q2.serviceName) tr.push('grpc-service-name=' + q2.serviceName);
      }
      if (q2.sni) tr.push('sni=' + q2.sni);
      if (q2.allowInsecure === '1' || q2.insecure === '1') tr.push('skip-cert-verify=true');
      return nm2 + '=' + tr.join(',');
    }

    if (scheme === 'hysteria2' || scheme === 'hy2') {
      var hy = ['Hysteria2', sp2[0], sp2[1], '"' + userinfo + '"'];
      if (q2.sni) hy.push('sni=' + q2.sni);
      if (q2.obfs) hy.push('obfs=' + q2.obfs);
      if (q2['obfs-password']) hy.push('obfs-password=' + q2['obfs-password']);
      if (q2.insecure === '1' || q2.allowInsecure === '1') hy.push('skip-cert-verify=true');
      return nm2 + '=' + hy.join(',');
    }

    if (scheme === 'anytls') {
      var an = ['anytls', sp2[0], sp2[1], '"' + userinfo + '"'];
      if (q2.sni) an.push('sni=' + q2.sni);
      if (q2.insecure === '1' || q2.allowInsecure === '1') an.push('skip-cert-verify=true');
      return nm2 + '=' + an.join(',');
    }

    if (scheme === 'socks' || scheme === 'socks5' || scheme === 'http' || scheme === 'https') {
      var ui = userinfo.split(':');
      var h2 = [scheme.indexOf('socks') === 0 ? 'socks5' : 'http', sp2[0], sp2[1]];
      if (ui[0]) h2.push(ui[0]);
      if (ui[1]) h2.push('"' + ui.slice(1).join(':') + '"');
      if (scheme === 'https') h2.push('over-tls=true');
      return nm2 + '=' + h2.join(',');
    }

    return null;
  }

  /* ==================== 8. 前缀 ==================== */
  function addPrefix(line) {
    var s = line.replace(/\r$/, '');
    var t = s.trim();
    if (!t || t.charAt(0) === '#') return line;
    var eq = t.indexOf('=');
    if (eq > 0 && LOON_PROTOCOLS.test(t.slice(eq + 1).trim())) {
      var nm = t.slice(0, eq).replace(/\s+$/, '');
      if (nm.indexOf(PREFIX) === 0) return line;
      return PREFIX + nm + t.slice(eq);
    }
    var hash = t.indexOf('#');
    if (t.indexOf('://') > 0) {
      if (hash >= 0) return t.slice(0, hash + 1) + PREFIX + t.slice(hash + 1);
      return t + '#' + PREFIX + 'Node';
    }
    return line;
  }

  /* ==================== 9. 主流程 ==================== */
  function parseLineList(text) {
    var out = [];
    var lines = text.split('\n');
    for (var i = 0; i < lines.length; i++) {
      var l = lines[i];
      var t = l.trim();
      if (!t || t.charAt(0) === '#') continue;
      if (t.indexOf('://') > 0) {
        var conv = null;
        try { conv = uriToLoon(t); } catch (e) { conv = null; }
        out.push(conv || l);
      } else if (t.indexOf('=') > 0 && LOON_PROTOCOLS.test(t.slice(t.indexOf('=') + 1).trim())) {
        out.push(l);
      } else {
        out.push(l);
      }
    }
    return out;
  }

  function tryStructured(text) {
    var t = text.trim();
    if (t.charAt(0) === '{') {
      var obj = null;
      try { obj = JSON.parse(t); } catch (e) { obj = null; }
      if (obj) {
        var res = null;
        try {
          if (isSingBox(obj)) res = parseSingBox(obj);
          else if (isV2ray(obj)) res = parseV2ray(obj);
        } catch (e) { res = null; }
        if (res && res.length) return dedupe(res.map(addPrefix)).join('\n');
      }
      return null;
    }
    if (/^\s*proxies\s*:/m.test(text)) {
      var y = null;
      try { y = parseYaml(text); } catch (e) { y = null; }
      if (y && y.length) return dedupe(y.map(addPrefix)).join('\n');
      return null;
    }
    if (isQX(text)) {
      var q = null;
      try { q = parseQX(text); } catch (e) { q = null; }
      if (q && q.length) return dedupe(q.map(addPrefix)).join('\n');
      return null;
    }
    if (isSurge(text)) {
      var sg = null;
      try { sg = parseSurge(text); } catch (e) { sg = null; }
      if (sg && sg.length) return dedupe(sg.map(addPrefix)).join('\n');
      return null;
    }
    return null;
  }

  function transform(raw) {
    var text = String(raw || '').replace(/^\uFEFF/, '');
    if (!text.trim()) return text;

    var s1 = tryStructured(text);
    if (s1 !== null) return s1;

    var hasUri = /:\/\//.test(text);
    var hasLoon = /\S\s*=\s*(shadowsocks|vmess|vless|trojan|anytls|hysteria2?|ss|socks5)\b/i.test(text);
    if (!hasUri && !hasLoon) {
      var dec = b64(text);
      if (dec) {
        var s2 = tryStructured(dec);
        if (s2 !== null) return s2;
        if (/:\/\//.test(dec) || /\S\s*=\s*(shadowsocks|vmess|vless|trojan|anytls|hysteria2?|ss|socks5)\b/i.test(dec)) text = dec;
      }
    }

    var lines = parseLineList(text);
    return lines.map(function (l) {
      try { return addPrefix(l); } catch (e) { return l; }
    }).join('\n');
  }

  var output = transform(INPUT);
  if (typeof $done === 'function') $done({ body: output });
})();
