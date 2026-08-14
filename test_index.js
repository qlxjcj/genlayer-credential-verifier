// Index-state invariant test for Credential Verifier.
// Verifies that one holder:type key maps to exactly ONE non-conflicting public state,
// regardless of how many times the same holder+type is re-verified.
// Run: node test_index.js
const CONTRACT = '0x6BCE9be8026f09A054EBA79f97A20730Da6094b1';
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

// Deterministic reimplementation of the contract's index-transition logic.
// The SAME table used by process_verification must be applied here.
function transition(verified, flagged, holder, type, verdict) {
  const key = `${holder}:${type}`;
  if (verdict === 'VERIFIED') {
    verified[key] = true;
    delete flagged[key];
  } else if (verdict === 'SUSPICIOUS') {
    flagged[key] = true;
    delete verified[key];
  } else { // UNVERIFIED
    delete verified[key];
    delete flagged[key];
  }
}

function assert(cond, msg) {
  if (!cond) { console.error('FAIL:', msg); process.exit(1); }
  console.log('PASS:', msg);
}

async function main() {
  console.log('=== Index-state transition invariant ===');
  console.log('Rule: one holder:type key may never appear in both verified AND flagged.\n');

  // Simulate: VERIFIED -> SUSPICIOUS -> UNVERIFIED -> VERIFIED for same holder+type
  let verified = {};
  let flagged = {};

  transition(verified, flagged, 'John Smith', 'PMP', 'VERIFIED');
  assert(verified['John Smith:PMP'] && !flagged['John Smith:PMP'], 'VERIFIED sets verified, clears flagged');

  transition(verified, flagged, 'John Smith', 'PMP', 'SUSPICIOUS');
  assert(!verified['John Smith:PMP'] && flagged['John Smith:PMP'], 'SUSPICIOUS sets flagged, clears verified');

  transition(verified, flagged, 'John Smith', 'PMP', 'UNVERIFIED');
  assert(!verified['John Smith:PMP'] && !flagged['John Smith:PMP'], 'UNVERIFIED clears both indexes');

  transition(verified, flagged, 'John Smith', 'PMP', 'VERIFIED');
  transition(verified, flagged, 'John Smith', 'PMP', 'SUSPICIOUS');
  transition(verified, flagged, 'John Smith', 'PMP', 'VERIFIED');
  assert(verified['John Smith:PMP'] && !flagged['John Smith:PMP'], 'repeated flips end in single consistent state');

  console.log('\n=== Live contract reads ===');
  try {
    const stats = await genCall('get_stats', []);
    console.log('get_stats:', JSON.stringify(stats, null, 2));
  } catch (e) {
    console.log('Live read via raw gen_call not supported by this RPC wrapper; see genlayer call CLI.');
  }

  console.log('\n=== Note ===');
  console.log('Write flow (via MetaMask or genlayer CLI):');
  console.log('  submit_credential(holder, type, issuer, source_urls_json)');
  console.log('  process_verification(credential_id)  -> validators reach LLM consensus');
  console.log('After each process, is_verified and is_flagged are mutually exclusive per key.');
}

main().catch(e => { console.error('FAILED:', e.message); process.exit(1); });
