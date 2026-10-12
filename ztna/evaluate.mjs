import {readFile} from 'node:fs/promises';
import {checkAccess} from './check.mjs';
// Baseline policy is only read. The XDR module adds a temporary deny gate.
export async function evaluateAccess(destination,at=Date.now()){
  const [baseline,dynamic]=await Promise.all([
    readFile(new URL('./rules.json',import.meta.url),'utf8'),
    readFile(new URL('../xdr/temporary-deny.json',import.meta.url),'utf8')
  ]);
  const saved=JSON.parse(dynamic);
  if(!Array.isArray(saved))throw new Error('Temporary deny policies must be an array');
  return checkAccess(destination,saved,at,JSON.parse(baseline));
}
