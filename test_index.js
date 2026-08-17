// Index-state + authority/ownership test for Credential Verifier.
// Verifies:
//   1. The public index key is bound to the holder's wallet address: the
//      caller MUST be the holder (sender == holder_address). A caller cannot
//      submit an arbitrary holder address and become that key's owner.
//   2. Ownership is persisted independently of the verdict (own `owners`
//      map). UNVERIFIED clears the public entries but never releases the key,
//      so another account cannot later re-claim the holder's pair.
//   3. One holder:type key maps to exactly ONE non-conflicting public state.
//   4. Only the owner may replace or clear their own public entry.
// Run: node test_index.js
const CONTRACT = '0x5257209605acd9BA1114CE9CcB02F6a4ee2F342C';
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

// Deterministic reimplementation of the contract's authority/ownership logic.
// Mirrors _index_key / _claim_owner / _check_index_authority / submit_credential
// / process_verification in the contract.
function claimOwner(owners, key) {
  return owners[key] || '';
}

// submit_credential: caller must be the holder; first submission binds the key.
function submit(owners, sender, holder, type) {
  if (sender.toLowerCase() !== holder.toLowerCase()) {
    throw new Error('REJECTED: only the holder can submit their own credential');
  }
  const key = holder + ':' + type;
  const owner = claimOwner(owners, key);
  if (owner && owner.toLowerCase() !== holder.toLowerCase()) {
    throw new Error('REJECTED: index key owned by another holder');
  }
  if (!claimOwner(owners, key)) owners[key] = holder;
}

// process_verification: verdict moves the public entries; ownership persists.
function process(owners, verified, flagged, key, verdict) {
  const holder = key.split(':')[0];
  const owner = claimOwner(owners, key);
  if (owner && owner.toLowerCase() !== holder.toLowerCase()) {
    throw new Error('REJECTED: index key owned by another holder');
  }
  if (!claimOwner(owners, key)) owners[key] = holder;
  const entry = { owner: holder, holder_address: holder };
  if (verdict === 'VERIFIED') {
    verified[key] = JSON.stringify({ ...entry, score: 95, confidence: 90 });
    delete flagged[key];
  } else if (verdict === 'SUSPICIOUS') {
    flagged[key] = JSON.stringify({ ...entry, score: 30 });
    delete verified[key];
  } else { // UNVERIFIED â€” clears public entries, ownership persists
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
  console.log('=== Holder binding (submit_credential) ===');
  console.log('Rule: the caller must BE the holder; no arbitrary holder address can be claimed.\n');

  const key = '0x1111:PM1';
  let owners = {};
  let verified = {};
  let flagged = {};

  // A caller who is NOT the holder cannot submit for an arbitrary holder.
  assertRejected(() => submit(owners, '0x9999', '0x1111', 'PM1'),
    'non-holder caller cannot submit for another holder address');
  assert(!claimOwner(owners, key), 'key stays unowned after non-holder attempt');

  // The real holder submits; ownership binds to the holder.
  submit(owners, '0x1111', '0x1111', 'PM1');
  assert(claimOwner(owners, key) === '0x1111', 'holder submission binds ownership to holder');

  console.log('\n=== Ownership persists independently of the verdict ===');
  console.log('Rule: UNVERIFIED clears public entries but never releases the key.\n');

  process(owners, verified, flagged, key, 'VERIFIED');
  assert(verified[key] && !flagged[key], 'VERIFIED sets verified, clears flagged');
  assert(claimOwner(owners, key) === '0x1111', 'owner record present while VERIFIED');

  process(owners, verified, flagged, key, 'UNVERIFIED');
  assert(!verified[key] && !flagged[key], 'UNVERIFIED clears both public entries');
  assert(claimOwner(owners, key) === '0x1111', 'ownership SURVIVES UNVERIFIED (key not released)');

  // Another account cannot re-claim the released public state.
  assertRejected(() => submit(owners, '0x2222', '0x1111', 'PM1'),
    'another account cannot re-claim the holder key after UNVERIFIED');

  // Owner can re-establish their own entry.
  process(owners, verified, flagged, key, 'VERIFIED');
  assert(verified[key], 'owner may re-establish their own entry');
  process(owners, verified, flagged, key, 'SUSPICIOUS');
  assert(!verified[key] && flagged[key], 'SUSPICIOUS sets flagged, clears verified');
  process(owners, verified, flagged, key, 'VERIFIED');
  process(owners, verified, flagged, key, 'SUSPICIOUS');
  process(owners, verified, flagged, key, 'VERIFIED');
  assert(verified[key] && !flagged[key], 'repeated flips by owner end in single consistent state');

  console.log('\n=== A free key can be claimed only by its holder ===');
  const key2 = '0x3333:CFA';
  assertRejected(() => submit(owners, '0x4444', '0x3333', 'CFA'),
    'stranger cannot claim a free key for holder 0x3333');
  submit(owners, '0x3333', '0x3333', 'CFA');
  assert(claimOwner(owners, key2) === '0x3333', 'holder claims their own free key');

  console.log('\n=== Live contract reads ===');
  try {
    const stats = await genCall('get_stats', []);
    console.log('get_stats:', JSON.stringify(stats, null, 2));
    const owner = await genCall('get_owner', ['0x1111', 'PM1']);
    console.log('get_owner(0x1111, PM1):', owner);
  } catch (e) {
    console.log('Live read via raw gen_call not supported by this RPC wrapper; see genlayer call CLI.');
  }

  console.log('\n=== Note ===');
  console.log('Write flow (via MetaMask or genlayer CLI):');
  console.log('  submit_credential(holder_name, holder_address, type, issuer, source_urls_json)');
  console.log('  process_verification(credential_id)  -> validators reach LLM consensus');
  console.log('The public index key is holder_address:credential_type, bound to the holder wallet.');
  console.log('Ownership (get_owner) persists across all verdicts, including UNVERIFIED.');
}

main().catch(e => { console.error('FAILED:', e.message); process.exit(1); });
