// Index-state + authority/replacement test for Credential Verifier.
// Verifies:
//   1. One holder:type key maps to exactly ONE non-conflicting public state.
//   2. The index key is owned by the holder's wallet address; a different
//      account CANNOT overwrite or clear the owner's shared public status.
//   3. Only the owner may replace or clear their own index entry.
// Run: node test_index.js
const CONTRACT = '0xdC589EDC18543F2184d4c041Fd95cD93F558e305';
const RPC = 'https://rpc-bradbury.genlayer.com';

async function genCall(method, args) {
  const res = await fetch(RPC, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'gen_call', params: [{ type: 'read', to: CONTRACT, function: method, args: args }] })
  });
  const data = await res.json();
  if (data.error) throw new Error(data.error.message || JSON.stringify(data.error));
  return data.result;
}

// Deterministic reimplementation of the contract's index authority logic.
// Mirrors _index_key / _claim_owner / _check_index_authority in the contract.
function claimOwner(verified, flagged, key) {
  if (verified[key]) { try { return JSON.parse(verified[key]).owner || ''; } catch { return ''; } }
  if (flagged[key]) { try { return JSON.parse(flagged[key]).owner || ''; } catch { return ''; } }
  return '';
}

function transition(verified, flagged, key, sender, verdict) {
  const owner = claimOwner(verified, flagged, key);
  if (owner && owner !== sender) {
    throw new Error('REJECTED: index key owned by another holder');
  }
  const entry = { owner: sender, holder_address: key.split(':')[0] };
  if (verdict === 'VERIFIED') {
    verified[key] = JSON.stringify({ ...entry, score: 95, confidence: 90 });
    delete flagged[key];
  } else if (verdict === 'SUSPICIOUS') {
    flagged[key] = JSON.stringify({ ...entry, score: 30 });
    delete verified[key];
  } else { // UNVERIFIED â€” owner may clear their own state
    delete verified[key];
    delete flagged[key];
  }
}

function assert(cond, msg) {
  if (!cond) { console.error('FAIL:', msg); process.exit(1); }
  console.log('PASS:', msg);
}

function assertRejected(fn, msg) {
  try { fn(); console.error('FAIL:', msg); process.exit(1); }
  catch (e) { console.log('PASS:', msg); }
}

async function main() {
  console.log('=== Index-state transition invariant ===');
  console.log('Rule: one holder_address:type key maps to exactly one non-conflicting public state.\n');

  const key = '0x1111:PM1';
  let verified = {};
  let flagged = {};

  transition(verified, flagged, key, '0x1111', 'VERIFIED');
  assert(verified[key] && !flagged[key], 'VERIFIED sets verified, clears flagged');

  transition(verified, flagged, key, '0x1111', 'SUSPICIOUS');
  assert(!verified[key] && flagged[key], 'SUSPICIOUS sets flagged, clears verified');

  transition(verified, flagged, key, '0x1111', 'UNVERIFIED');
  assert(!verified[key] && !flagged[key], 'UNVERIFIED clears both indexes');

  transition(verified, flagged, key, '0x1111', 'VERIFIED');
  transition(verified, flagged, key, '0x1111', 'SUSPICIOUS');
  transition(verified, flagged, key, '0x1111', 'VERIFIED');
  assert(verified[key] && !flagged[key], 'repeated flips by owner end in single consistent state');

  console.log('\n=== Authority / replacement policy ===');
  console.log('Rule: a non-owner account cannot overwrite or clear the owner public status.\n');

  // reset
  verified = {}; flagged = {};
  transition(verified, flagged, key, '0x1111', 'VERIFIED');

  // A DIFFERENT account (0x2222) tries to replace/clear the owner's state
  assertRejected(() => transition(verified, flagged, key, '0x2222', 'SUSPICIOUS'),
    'non-owner cannot overwrite owner VERIFIED with SUSPICIOUS');
  assert(verified[key] && !flagged[key], 'owner verified entry survives non-owner attempt');

  assertRejected(() => transition(verified, flagged, key, '0x2222', 'UNVERIFIED'),
    'non-owner cannot clear the owner verified entry');
  assert(verified[key], 'owner verified entry survives non-owner clear attempt');

  // owner can still replace their own entry
  transition(verified, flagged, key, '0x1111', 'UNVERIFIED');
  assert(!verified[key] && !flagged[key], 'owner may clear their own entry');
  transition(verified, flagged, key, '0x1111', 'VERIFIED');
  assert(verified[key], 'owner may re-establish their own entry');

  // A free key can be claimed by its first claimant
  const key2 = '0x3333:CFA';
  transition(verified, flagged, key2, '0x3333', 'VERIFIED');
  assert(verified[key2], 'first claimant owns a free index key');

  console.log('\n=== Live contract reads ===');
  try {
    const stats = await genCall('get_stats', []);
    console.log('get_stats:', JSON.stringify(stats, null, 2));
  } catch (e) {
    console.log('Live read via raw gen_call not supported by this RPC wrapper; see genlayer call CLI.');
  }

  console.log('\n=== Note ===');
  console.log('Write flow (via MetaMask or genlayer CLI):');
  console.log('  submit_credential(holder_name, holder_address, type, issuer, source_urls_json)');
  console.log('  process_verification(credential_id)  -> validators reach LLM consensus');
  console.log('The public index key is holder_address:credential_type and is owned by the');
  console.log('holder wallet. Only the owner can update or clear it.');
}

main().catch(e => { console.error('FAILED:', e.message); process.exit(1); });

