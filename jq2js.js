/*!
 * jq2js — 把 Quantumult X 的 jsonjq-response-body 表达式翻译成 Loon 可执行的 JS
 * 用于 Loon 插件迁移（QX/Surge → Loon）。Loon 不支持 jsonjq，只能用脚本实现。
 *
 * 支持：赋值 / 管道 / map(select()) / test() / IN() / del() / and / or
 * 用法：node jq2js.js '.data=[]'       → 打印 JS
 *       const { jqToJs } = require('./jq2js')
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.jq2js = factory();
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // 只在括号/引号外按 | 分割；|= 是操作符不分割
  function splitPipe(s) {
    var out = [], depth = 0, inq = null, cur = '';
    for (var i = 0; i < s.length; i++) {
      var c = s[i];
      if (inq) {
        cur += c;
        if (c === inq && s[i - 1] !== '\\') inq = null;
      } else if (c === '"' || c === "'") {
        inq = c; cur += c;
      } else if (c === '(' || c === '[' || c === '{') {
        depth++; cur += c;
      } else if (c === ')' || c === ']' || c === '}') {
        depth--; cur += c;
      } else if (c === '|' && depth === 0 && s[i + 1] !== '=') {
        out.push(cur); cur = '';
      } else {
        cur += c;
      }
    }
    out.push(cur);
    return out.map(function (x) { return x.trim(); }).filter(Boolean);
  }

  function jsPath(p) {
    p = p.trim().replace(/^\./, '');
    return 'd' + (p ? '.' + p : '');
  }

  function jstr(v) { return JSON.stringify(v); }

  // map(select(...)) 的条件
  function convSelect(path, cond) {
    cond = cond.trim();
    var mt = cond.match(/^\.(\w+)\s*\|\s*test\("(.*)"\)\s*\|\s*not$/);
    if (mt) {
      return path + '=(' + path + '||[]).filter(x=>!new RegExp(' + jstr(mt[2]) + ').test(x.' + mt[1] + '));';
    }
    var mi = cond.match(/^\.(\w+)\s*\|\s*IN\((.*)\)\s*\|\s*not$/);
    if (mi) {
      var items = mi[2].split(',').map(function (v) {
        return jstr(v.trim().replace(/^["']|["']$/g, ''));
      });
      return path + '=(' + path + '||[]).filter(x=>![' + items.join(',') + '].includes(x.' + mi[1] + '));';
    }
    var c = cond.replace(/(^|[^\w.])\.(\w+)/g, function (_, pre, f) { return pre + 'x.' + f; });
    c = c.replace(/(!=|==)\s*"([^"]*)"/g, function (_, op, v) { return op + '=' + jstr(v); });
    c = c.replace(/(!=|==)\s*'([^']*)'/g, function (_, op, v) { return op + '=' + jstr(v); });
    c = c.replace(/\band\b/g, '&&').replace(/\bor\b/g, '||');
    return path + '=(' + path + '||[]).filter(x=>' + c + ');';
  }

  function jqToJs(expr) {
    var out = [];
    splitPipe(expr).forEach(function (part) {
      var m;
      if ((m = part.match(/^([.\w]+)\s*\|=\s*map\(select\((.*)\)\)$/))) {
        out.push(convSelect(jsPath(m[1]), m[2])); return;
      }
      if ((m = part.match(/^([.\w]+)\s*\|=\s*(.+)$/))) {
        out.push(jsPath(m[1]) + '=' + m[2] + ';'); return;
      }
      if ((m = part.match(/^([.\w]+)\s*=\s*(.+)$/))) {
        out.push(jsPath(m[1]) + '=' + m[2].trim() + ';'); return;
      }
      if ((m = part.match(/^del\(([.\w]+)\)$/))) {
        out.push('delete ' + jsPath(m[1]) + ';'); return;
      }
    });
    return out.join(' ');
  }

  return { jqToJs: jqToJs, splitPipe: splitPipe, convSelect: convSelect };
}));
