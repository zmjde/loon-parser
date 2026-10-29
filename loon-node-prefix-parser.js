/*
 * Loon 订阅解析插件 · 节点名前缀
 * ---------------------------------------------------------------
 * 作用：Loon 拉取订阅后，给每个节点名加上指定前缀，避免多条机场
 *      订阅出现同名节点（如都叫「香港1」）互相覆盖。
 *
 * 用法（主配置 [Remote Proxy]）：
 *   订阅别名 = https://机场订阅地址,parser-enabled=true,parser-plugin=<本文件 raw 地址>,argument="【1】",enabled=true
 *
 * argument 就是这个前缀，可以是任意文本：【1】、[1]、A- 等。
 *
 * 支持的输入：Loon 标准节点行（名称=协议,...）、SS/VMess/VLESS/Trojan/
 *            Hysteria2/AnyTLS 等 URI 行、以及整份 Base64 编码的 URI 列表。
 *            其他内容（如 Clash YAML）原样返回，不做改动。
 *
 * 更新：2026-10-29
 */

(function () {
  'use strict';

  // ---- 1. 取前缀参数 ----
  // 兼容三种写法：
  //   argument="【1】"            （纯文本）
  //   argument="prefix=【1】"      （Loon 文档推荐的 key=value 形式）
  //   argument 被解析成对象 {prefix: "【1】"}
  var PREFIX = (function () {
    var a = (typeof $argument !== 'undefined') ? $argument : '';

    if (a && typeof a === 'object') {
      return String(a.prefix || a.name || a.p || '').trim();
    }

    var raw = String(a == null ? '' : a).trim();
    if (!raw) return '';

    // key=value[&key=value] 形式
    var m = raw.match(/(?:^|&)prefix=([^&]*)/i);
    if (m) {
      try { return decodeURIComponent(m[1]).trim(); } catch (e) { return m[1].trim(); }
    }
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

  // ---- 2. 取订阅原文 ----
  var INPUT = '';
  if (typeof $resource === 'string') {
    INPUT = $resource;
  } else if ($resource && typeof $resource === 'object' && typeof $resource.body === 'string') {
    INPUT = $resource.body;
  }

  // ---- 3. 工具函数 ----
  function decodeBase64(s) {
    var t = String(s).replace(/\s+/g, '');
    if (!/^[A-Za-z0-9+/=_-]+$/.test(t)) return null;
    try {
      var b64 = t.replace(/-/g, '+').replace(/_/g, '/');
      var out;
      if (typeof atob === 'function') {
        out = atob(b64);
      } else if (typeof Buffer !== 'undefined') {
        out = Buffer.from(b64, 'base64').toString('binary');
      } else {
        return null;
      }
      return decodeURIComponent(escape(out)); // 处理 UTF-8
    } catch (e) {
      return null;
    }
  }

  // Loon 支持的协议名（用于判断 "名称=协议,..." 里 = 的位置是否真的是分隔符）
  var PROTOCOLS = /^(shadowsocks|shadowsocksr|ss|ssr|vmess|vless|trojan|http|https|socks5|wireguard|hysteria2|hysteria|anytls|tuic|snell)\b/i;

  function prefixLoonLine(line) {
    var s = line.replace(/\r$/, '');
    var trimmed = s.trim();
    if (!trimmed) return line;
    if (trimmed.charAt(0) === '#') return line;

    var eq = trimmed.indexOf('=');
    var scheme = trimmed.indexOf('://');

    // URI 格式：名字在 # 之后
    if (scheme > 0 && (eq < 0 || scheme < eq)) {
      var hash = trimmed.indexOf('#');
      if (hash >= 0) {
        return trimmed.slice(0, hash + 1) + PREFIX + trimmed.slice(hash + 1);
      }
      return trimmed + '#' + PREFIX + 'Node';
    }

    // Loon 格式：名称 = 协议,...（确认 = 右侧确实以协议名开头）
    if (eq > 0) {
      var right = trimmed.slice(eq + 1).trim();
      if (PROTOCOLS.test(right)) {
        var name = trimmed.slice(0, eq).replace(/\s+$/, '');
        if (name.indexOf(PREFIX) === 0) return line; // 已加过前缀，避免重复
        return PREFIX + name + trimmed.slice(eq);
      }
    }
    return line;
  }

  function transform(raw) {
    var text = String(raw || '').replace(/^\uFEFF/, '');
    if (!text.trim()) return text;

    // 判断是否为 Clash/YAML，是则原样返回，避免破坏
    if (/^\s*(mixed-port|port|proxies|proxy-groups)\s*:/m.test(text.slice(0, 3000))) {
      return text;
    }

    // 整份 Base64 的订阅：解码后再处理
    var looksLikeUris = /:\/\//.test(text);
    var looksLikeLoon = /\S\s*=\s*(shadowsocks|vmess|vless|trojan|anytls|hysteria2?|ss|socks5)\b/i.test(text);
    if (!looksLikeUris && !looksLikeLoon) {
      var decoded = decodeBase64(text);
      if (decoded) {
        // 解码后可能是 URI 列表，也可能是 Loon 标准行，两种都接受
        var okUri = /:\/\//.test(decoded);
        var okLoon = /\S\s*=\s*(shadowsocks|vmess|vless|trojan|anytls|hysteria2?|ss|socks5)\b/i.test(decoded);
        if (okUri || okLoon) text = decoded;
      }
    }

    if (!PREFIX) return text;

    return text
      .split('\n')
      .map(function (line) {
        try {
          return prefixLoonLine(line);
        } catch (e) {
          return line;
        }
      })
      .join('\n');
  }

  var output = transform(INPUT);

  if (typeof $done === 'function') {
    $done({ body: output });
  }
})();
