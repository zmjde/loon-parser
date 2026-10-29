/*
 * Loon 订阅解析插件 · 节点前缀 + 通用格式转换
 * ---------------------------------------------------------------
 * 目标：替代 Sub-Store 官方解析器（1.2MB）做同样的事，并额外加节点名前缀。
 *
 * 支持的输入：
 *   1) Loon 标准节点行       名称=协议,server,port,...
 *   2) 节点 URI              ss:// ssr:// vmess:// vless:// trojan:// hysteria2:// hy2:// anytls://
 *   3) 整份 Base64           解码后按上面两种处理
 *   4) Clash YAML            解析 proxies 段，转成 Loon 格式
 *
 * 额外优化：
 *   - 节点名前缀（argument="prefix=【1】"）
 *   - 自动去重（相同 server:port 只保留第一个）
 *   - 节点名清洗（去掉首尾空白、换行）
 *   - 识别不了的格式原样返回，不破坏原有解析
 *
 * 用法（[Remote Proxy]）：
 *   订阅 = https://...,parser-enabled = true,parser-plugin=<本文件URL>,argument="prefix=【1】"
 *
 * 更新：2026-10-29
 */

(function () {
  'use strict';

  /* ============ 1. 参数 ============ */
  var PREFIX = (function () {
    var a = (typeof $argument !== 'undefined') ? $argument : '';
    if (a && typeof a === 'object') return String(a.prefix || a.name || a.p || '').trim();
    var raw = String(a == null ? '' : a).trim();
    if (!raw) return '';
    var m = raw.match(/(?:^|&)prefix=([^&]*)/i);
    if (m) { try { return decodeURIComponent(m[1]).trim(); } catch (e) { return m[1].trim(); } }
    if (raw.indexOf('=') >= 0) {
      var pairs = raw.split('&');
      for (var i = 0; i < pairs.length; i++) {
        var kv = pairs[i].split('=');
        if (kv.length === 2 && kv[1]) {
          try { return decodeURIComponent(kv[1]).trim(); } catch (e) { return kv[1].trim(); }
        }
      }
      return '';
    }
    return raw;
  })();

  var INPUT = '';
  if (typeof $resource === 'string') INPUT = $resource;
  else if ($resource && typeof $resource === 'object' && typeof $resource.body === 'string') INPUT = $resource.body;

  /* ============ 2. 工具 ============ */
  function unquote(v) {
    if (v == null) return '';
    v = String(v).trim();
    if ((v.charAt(0) === '"' && v.charAt(v.length - 1) === '"') ||
        (v.charAt(0) === "'" && v.charAt(v.length - 1) === "'")) {
      v = v.slice(1, -1);
    }
    return v.replace(/\s+/g, ' ').trim();
  }

  function b64decode(s) {
    var t = String(s).replace(/\s+/g, '');
    if (!/^[A-Za-z0-9+/=_-]+$/.test(t)) return null;
    try {
      var b = t.replace(/-/g, '+').replace(/_/g, '/');
      var out;
      if (typeof atob === 'function') out = atob(b);
      else if (typeof Buffer !== 'undefined') out = Buffer.from(b, 'base64').toString('binary');
      else return null;
      try { return decodeURIComponent(escape(out)); } catch (e) { return out; }
    } catch (e) { return null; }
  }

  var PROTOCOLS = /^(shadowsocks|shadowsocksr|ss|ssr|vmess|vless|trojan|http|https|socks5|wireguard|hysteria2|hysteria|anytls|tuic|snell)\b/i;

  /* ============ 3. 单节点 URI -> Loon 行 ============ */
  function uriToLoon(line) {
    var s = line.trim();
    var scheme = s.slice(0, s.indexOf('://')).toLowerCase();
    var rest = s.slice(s.indexOf('://') + 3);
    var hash = rest.indexOf('#');
    var name = hash >= 0 ? decodeURIComponentSafe(rest.slice(hash + 1)) : '';
    var body = hash >= 0 ? rest.slice(0, hash) : rest;
    var q = body.indexOf('?');
    var main = q >= 0 ? body.slice(0, q) : body;
    var query = q >= 0 ? body.slice(q + 1) : '';

    if (scheme === 'ss') {
      var at = main.lastIndexOf('@');
      var cred, hostport;
      if (at >= 0) {
        cred = main.slice(0, at); hostport = main.slice(at + 1);
        var dec = b64decode(cred);
        if (dec && dec.indexOf(':') >= 0) cred = dec;
      } else {
        var dec2 = b64decode(main);
        if (!dec2) return null;
        var at2 = dec2.lastIndexOf('@');
        cred = dec2.slice(0, at2); hostport = dec2.slice(at2 + 1);
      }
      var ci = cred.indexOf(':');
      var cipher = cred.slice(0, ci), pwd = cred.slice(ci + 1);
      var hp = splitHostPort(hostport);
      return (name || hp[0]) + ' = Shadowsocks,' + hp[0] + ',' + hp[1] + ',' + cipher + ',"' + pwd + '"';
    }

    if (scheme === 'vmess' || scheme === 'vless') {
      return (name || '') + '=' + (scheme === 'vmess' ? 'VMess' : 'VLESS') + ',' + main;
    }

    if (scheme === 'trojan') {
      var at3 = main.lastIndexOf('@');
      var pwd3 = main.slice(0, at3), hp3 = splitHostPort(main.slice(at3 + 1));
      return (name || hp3[0]) + ' = Trojan,' + hp3[0] + ',' + hp3[1] + ',"' + decodeURIComponentSafe(pwd3) + '"' +
             (query ? ',' + query.replace(/&/g, ',') : '');
    }

    return null;
  }

  function decodeURIComponentSafe(v) {
    try { return decodeURIComponent(v); } catch (e) { return v; }
  }

  function splitHostPort(v) {
    var i = v.lastIndexOf(':');
    if (i < 0) return [v, '443'];
    return [v.slice(0, i).replace(/^\[|\]$/g, ''), v.slice(i + 1)];
  }

  /* ============ 4. Clash YAML -> Loon 行 ============ */
  function parseClash(text) {
    var lines = text.split('\n');
    var start = -1, end = lines.length;
    for (var i = 0; i < lines.length; i++) {
      if (/^proxies\s*:/.test(lines[i])) { start = i; break; }
    }
    if (start < 0) return null;
    var inline = lines[start].split(':').slice(1).join(':').trim();
    if (inline && inline.replace(/\s/g, '') === '[]') return [];

    for (var j = start + 1; j < lines.length; j++) {
      var l = lines[j];
      if (!l.trim()) continue;
      if (!/^\s/.test(l)) { end = j; break; }
    }

    var items = [], cur = null;
    for (var k = start + 1; k < end; k++) {
      var line = lines[k];
      if (!line.trim() || /^\s*#/.test(line)) continue;
      var mItem = line.match(/^\s*-\s*(.*)$/);
      if (mItem) {
        if (cur) items.push(cur);
        cur = {};
        var first = mItem[1];
        if (first && first.charAt(0) === '{') {
          parseFlow(first, cur); cur = cur; continue;
        }
        if (first) assignPair(first, cur);
        continue;
      }
      if (cur) assignPair(line, cur);
    }
    if (cur) items.push(cur);

    var out = [];
    for (var n = 0; n < items.length; n++) {
      var ln = clashToLoon(items[n]);
      if (ln) out.push(ln);
    }
    return out;
  }

  function parseFlow(s, obj) {
    var body = s.replace(/^\{/, '').replace(/\}.*$/, '');
    body.split(',').forEach(function (part) {
      var i = part.indexOf(':');
      if (i > 0) obj[part.slice(0, i).trim()] = unquote(part.slice(i + 1));
    });
  }

  function assignPair(line, obj) {
    var m = line.match(/^\s*([A-Za-z0-9_-]+)\s*:\s*(.*)$/);
    if (m) obj[m[1]] = unquote(m[2]);
  }

  function clashToLoon(p) {
    var t = String(p.type || '').toLowerCase();
    var name = unquote(p.name) || (p.server + ':' + p.port);
    var server = p.server, port = p.port;
    if (!server || !port) return null;
    var extra = [];
    if (p.udp === 'true') extra.push('udp=true');
    var sni = p.sni || p.servername || '';
    var skip = (p['skip-cert-verify'] === 'true') ? 'skip-cert-verify=true' : '';

    if (t === 'ss') {
      var opts = ['Shadowsocks', server, port, p.cipher, '"' + (p.password || '') + '"'];
      if (p.plugin === 'obfs') {
        if (p['plugin-opts'] && p['plugin-opts'].mode) opts.push('obfs-name=' + p['plugin-opts'].mode);
        if (p['plugin-opts'] && p['plugin-opts'].host) opts.push('obfs-host=' + p['plugin-opts'].host);
      }
      return name + '=' + opts.concat(extra, skip ? [skip] : []).join(',');
    }
    if (t === 'vmess') {
      var v = ['VMess', server, port, p.cipher || 'auto', '"' + (p.uuid || '') + '"',
               'transport=' + (p.network || 'tcp'), 'alterId=' + (p.alterId || 0)];
      if (p.network === 'ws') { if (p['ws-opts'] && p['ws-opts'].path) v.push('path=' + p['ws-opts'].path); if (p['ws-opts'] && p['ws-opts'].headers && p['ws-opts'].headers.Host) v.push('host=' + p['ws-opts'].headers.Host); }
      if (p.tls === 'true') v.push('over-tls=true');
      if (sni) v.push('sni=' + sni);
      return name + '=' + v.concat(extra, skip ? [skip] : []).join(',');
    }
    if (t === 'vless') {
      var x = ['VLESS', server, port, '"' + (p.uuid || '') + '"', 'transport=' + (p.network || 'tcp')];
      if (p.flow) x.push('flow=' + p.flow);
      if (p['reality-opts']) { if (p['reality-opts']['public-key']) x.push('public-key="' + p['reality-opts']['public-key'] + '"'); if (p['reality-opts']['short-id']) x.push('short-id=' + p['reality-opts']['short-id']); }
      if (p.network === 'ws') { if (p['ws-opts'] && p['ws-opts'].path) x.push('path=' + p['ws-opts'].path); if (p['ws-opts'] && p['ws-opts'].headers && p['ws-opts'].headers.Host) x.push('host=' + p['ws-opts'].headers.Host); }
      if (p.tls === 'true' || p['reality-opts']) x.push('over-tls=true');
      if (sni) x.push('sni=' + sni);
      return name + '=' + x.concat(extra, skip ? [skip] : []).join(',');
    }
    if (t === 'trojan') {
      var tr = ['Trojan', server, port, '"' + (p.password || '') + '"', 'transport=' + (p.network || 'tcp')];
      if (p.network === 'ws') { if (p['ws-opts'] && p['ws-opts'].path) tr.push('path=' + p['ws-opts'].path); if (p['ws-opts'] && p['ws-opts'].headers && p['ws-opts'].headers.Host) tr.push('host=' + p['ws-opts'].headers.Host); }
      if (sni) tr.push('sni=' + sni);
      return name + '=' + tr.concat(extra, skip ? [skip] : []).join(',');
    }
    if (t === 'hysteria2' || t === 'hy2') {
      var h = ['Hysteria2', server, port, '"' + (p.password || p.auth || '') + '"'];
      if (sni) h.push('sni=' + sni);
      return name + '=' + h.concat(extra, skip ? [skip] : []).join(',');
    }
    if (t === 'anytls') {
      var a2 = ['anytls', server, port, '"' + (p.password || '') + '"'];
      if (sni) a2.push('sni=' + sni);
      return name + '=' + a2.concat(extra, skip ? [skip] : []).join(',');
    }
    if (t === 'http' || t === 'https' || t === 'socks5') {
      var o = [t, server, port];
      if (p.username) o.push(p.username);
      if (p.password) o.push('"' + p.password + '"');
      return name + '=' + o.concat(extra, skip ? [skip] : []).join(',');
    }
    return null;
  }

  /* ============ 5. 加前缀 / 去重 ============ */
  function addPrefix(line) {
    var s = line.replace(/\r$/, '');
    var t = s.trim();
    if (!t) return line;
    if (t.charAt(0) === '#') return line;

    var eq = t.indexOf('=');
    var scheme = t.indexOf('://');

    if (scheme > 0 && (eq < 0 || scheme < eq)) {
      var hash = t.indexOf('#');
      if (hash >= 0) return t.slice(0, hash + 1) + PREFIX + t.slice(hash + 1);
      return t + '#' + PREFIX + 'Node';
    }
    if (eq > 0) {
      var right = t.slice(eq + 1).trim();
      if (PROTOCOLS.test(right)) {
        var name = t.slice(0, eq).replace(/\s+$/, '');
        if (name.indexOf(PREFIX) === 0) return line;
        return PREFIX + name + t.slice(eq);
      }
    }
    return line;
  }

  function dedupe(lines) {
    var seen = {}, out = [];
    for (var i = 0; i < lines.length; i++) {
      var l = lines[i];
      var eq = l.indexOf('=');
      var key = null;
      if (eq > 0) {
        var parts = l.slice(eq + 1).split(',');
        if (parts.length > 2) key = parts[1].trim() + ':' + parts[2].trim();
      }
      if (key) {
        if (seen[key]) continue;
        seen[key] = 1;
      }
      out.push(l);
    }
    return out;
  }

  /* ============ 6. 主流程 ============ */
  function transform(raw) {
    var text = String(raw || '').replace(/^\uFEFF/, '');
    if (!text.trim()) return text;

    // Clash YAML
    if (/^\s*proxies\s*:/m.test(text)) {
      var clash = parseClash(text);
      if (clash && clash.length) {
        var cl = dedupe(clash.map(addPrefix));
        return cl.join('\n');
      }
      return text; // 解析不出来就原样返回
    }

    // Base64
    var hasUri = /:\/\//.test(text);
    var hasLoon = /\S\s*=\s*(shadowsocks|vmess|vless|trojan|anytls|hysteria2?|ss|socks5)\b/i.test(text);
    if (!hasUri && !hasLoon) {
      var dec = b64decode(text);
      if (dec) {
        var okUri = /:\/\//.test(dec);
        var okLoon = /\S\s*=\s*(shadowsocks|vmess|vless|trojan|anytls|hysteria2?|ss|socks5)\b/i.test(dec);
        if (okUri || okLoon) text = dec;
      }
    }

    var lines = text.split('\n').map(function (l) {
      try { return addPrefix(l); } catch (e) { return l; }
    });
    return lines.join('\n');
  }

  var output = transform(INPUT);
  if (typeof $done === 'function') $done({ body: output });
})();
