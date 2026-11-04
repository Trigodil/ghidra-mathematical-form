'use strict';
// Only parse input text. Never import, link, evaluate, or execute recovered code.
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const input = process.argv[2];
const output = process.argv[3];
const records = JSON.parse(fs.readFileSync(path.join(input, 'modules.json'), 'utf8'));
const rows = [];
for (const record of records) {
  if (!/\.(?:m?js)$/.test(record.path) && record.index !== 7) continue;
  const file = path.join(input, record.decompressed || record.extracted);
  const source = fs.readFileSync(file, 'utf8');
  try {
    // Construction parses/compiles to bytecode; no link() or evaluate() call.
    new vm.SourceTextModule(source, {identifier: record.path});
    rows.push({path: record.path, status: 'parsed'});
  } catch (error) {
    rows.push({path: record.path, status: 'parser_rejected', reason: error.message});
  }
}
const summary = {files: rows.length, parsed: rows.filter(x=>x.status==='parsed').length,
  rejected: rows.filter(x=>x.status!=='parsed'),
  scope: 'V8 SourceTextModule syntax compilation with JIT disabled. No linking or evaluation; recovered code was never executed.'};
fs.writeFileSync(path.join(output, 'syntax.json'), JSON.stringify({summary, rows}, null, 2)+'\n');
console.log(JSON.stringify(summary, null, 2));
