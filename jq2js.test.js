const { jqToJs } = require('./jq2js');
const cases = [
  ['.data.list=[] | .data.ad_list=[] | .data.show=[] | .data.ad_loc=false'],
  ['.data=[]'],
  ['.data.flash={"id":0,"title":""}'],
  ['.data.home_type |= map(select(.name!="初夏纯爱！" and .name!="妖气村"))'],
  ['.data |= map(select(.keyName | test("config\\.(ad|search|recommend)") | not))'],
  ['.entrance_region_res_list |= map(select(.region_name | IN("工具区", "我页面灯泡", "banner区") | not))'],
  ['.data |= map(select(.card_type != 1))'],
  ['del(.data.ad)'],
];
let ok = 0;
for (const [e] of cases) {
  const r = jqToJs(e);
  const pass = r && !r.includes('map(select') && !r.includes('| not');
  if (pass) ok++; else console.log('FAIL:', e, '→', r);
  console.log((pass ? '✓ ' : '✗ ') + r.slice(0, 130));
}
console.log(`\n${ok}/${cases.length} passed`);
