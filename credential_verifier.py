# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
import json
from dataclasses import dataclass
from genlayer import *


@allow_storage
@dataclass
class Credential:
    credential_id: u256
    submitter: str
    holder_name: str
    holder_address: str
    credential_type: str
    issuer: str
    source_urls: str
    status: str
    result: str
    validity_score: u256
    confidence: u256
    findings: str


class CredentialVerifier(gl.Contract):
    credentials: TreeMap[u256, str]
    credential_count: u256
    verified: TreeMap[str, str]  # key -> {owner, holder_address, issuer, score, confidence}
    flagged: TreeMap[str, str]   # key -> {owner, holder_address, score, findings}
    owners: TreeMap[str, str]    # key -> owner address; persists independent of any verdict

    def __init__(self):
        pass

    def _verify_credential(self, holder_name: str, credential_type: str, issuer: str, source_urls: str) -> dict:
        def gather_and_verify() -> dict:
            def fetch(urls_json: str) -> list:
                texts = []
                try:
                    urls = json.loads(urls_json)
                except Exception:
                    urls = [urls_json] if urls_json else []
                for url in urls:
                    try:
                        content = gl.nondet.web.get(url)
                        texts.append(f"[{url}]\n{content.body.decode('utf-8', errors='replace')[:2500]}")
                    except Exception:
                        texts.append(f"[{url}] [FETCH_FAILED]")
                return texts

            sources = fetch(source_urls)

            task = f"""
Credential check: holder {holder_name}, type {credential_type}, issuer {issuer}.
SOURCES:
{chr(10).join(sources) if sources else "[none submitted]"}

Decide if this credential appears in an authoritative registry.
Respond ONLY JSON: {{"result": "VERIFIED" or "UNVERIFIED" or "SUSPICIOUS", "validity_score": int, "confidence": int, "findings": [str]}}
"""
            result = gl.nondet.exec_prompt(task).replace("```json", "").replace("```", "")
            return json.loads(result)

        principle = "result must be exactly the same (VERIFIED/UNVERIFIED/SUSPICIOUS), validity_score and confidence must be the same integers."
        return gl.eq_principle.prompt_comparative(gather_and_verify, principle)

    # Authority policy: the public index key for a holder's credential is
    # BOUND to the holder's wallet address at submission time. The caller must
    # BE the holder (sender == holder_address); a caller cannot submit an
    # arbitrary holder address and become that key's owner. Ownership lives in
    # its own `owners` map and is persisted independently of any verdict, so an
    # UNVERIFIED result clears the public entries but never releases the key.
    def _index_key(self, holder_address: str, credential_type: str) -> str:
        return f"{self._addr_hex(holder_address)}:{credential_type}"

    def _addr_hex(self, a) -> str:
        # Address objects (from calldata ADDR encoding or sender) -> hex string.
        if hasattr(a, "as_hex"):
            return a.as_hex
        return str(a)

    def _claim_owner(self, key: str) -> str:
        return self.owners.get(key, "")

    def _check_index_authority(self, key: str, holder_address: str):
        owner = self._claim_owner(key)
        if owner and owner.lower() != self._addr_hex(holder_address).lower():
            raise Exception("Index key owned by another holder; replacement not permitted")

    @gl.public.write
    def submit_credential(self, holder_name: str, holder_address: str, credential_type: str, issuer: str, source_urls_json: str):
        sender = gl.message.sender_address.as_hex
        holder_address = self._addr_hex(holder_address)
        # The caller must be the holder themself. Binding the holder address to
        # the caller prevents anyone from claiming another party's key.
        if sender.lower() != holder_address.lower():
            raise Exception("Only the holder can submit their own credential")

        key = self._index_key(holder_address, credential_type)
        self._check_index_authority(key, holder_address)
        if not self._claim_owner(key):
            self.owners[key] = holder_address

        self.credential_count += 1
        credential_id = self.credential_count

        credential = Credential(
            credential_id=credential_id, submitter=sender,
            holder_name=holder_name, holder_address=holder_address,
            credential_type=credential_type,
            issuer=issuer, source_urls=source_urls_json, status="PENDING",
            result="", validity_score=0, confidence=0, findings="[]",
        )
        self.credentials[credential_id] = json.dumps(credential.__dict__)

    @gl.public.write
    def process_verification(self, credential_id: u256):
        sender = gl.message.sender_address
        credential = json.loads(self.credentials.get(credential_id, "{}"))
        if not credential:
            raise Exception("Credential not found")
        if credential["submitter"] != sender.as_hex:
            raise Exception("Only submitter can process")
        if credential["status"] != "PENDING":
            raise Exception("Already processed")

        credential["status"] = "PROCESSING"
        self.credentials[credential_id] = json.dumps(credential)

        result = self._verify_credential(
            credential["holder_name"],
            credential["credential_type"],
            credential["issuer"],
            credential["source_urls"],
        )

        result_label = result.get("result", "UNVERIFIED")
        if result_label not in ("VERIFIED", "UNVERIFIED", "SUSPICIOUS"):
            result_label = "UNVERIFIED"

        score = int(result.get("validity_score", 0))
        score = max(0, min(100, score))
        conf = int(result.get("confidence", 0))
        conf = max(0, min(100, conf))
        findings = result.get("findings", [])
        if not isinstance(findings, list):
            findings = [str(findings)]

        credential["status"] = "VERIFIED"
        credential["result"] = result_label
        credential["validity_score"] = score
        credential["confidence"] = conf
        credential["findings"] = json.dumps(findings)
        self.credentials[credential_id] = json.dumps(credential)

        # Authority + replacement policy:
        # The key is bound to the holder's wallet address. Ownership is stored
        # in its own `owners` map and persists independently of the verdict:
        # UNVERIFIED clears the public entries but never releases the key, so
        # another account cannot later re-claim the holder's pair.
        key = self._index_key(credential["holder_address"], credential["credential_type"])
        self._check_index_authority(key, credential["holder_address"])
        if not self._claim_owner(key):
            self.owners[key] = credential["holder_address"]

        owner_entry = {
            "owner": credential["holder_address"],
            "holder_address": credential["holder_address"],
            "issuer": credential["issuer"],
        }
        if result_label == "VERIFIED":
            self.verified[key] = json.dumps({**owner_entry, "score": score, "confidence": conf})
            self.flagged.pop(key, None)
        elif result_label == "SUSPICIOUS":
            self.flagged[key] = json.dumps({**owner_entry, "score": score, "findings": findings})
            self.verified.pop(key, None)
        else:  # UNVERIFIED — clears public entries, ownership record persists
            self.verified.pop(key, None)
            self.flagged.pop(key, None)

    @gl.public.view
    def get_credential(self, credential_id: u256) -> str:
        return self.credentials.get(credential_id, "{}")

    @gl.public.view
    def is_verified(self, holder_address: str, credential_type: str) -> str:
        return self.verified.get(self._index_key(holder_address, credential_type), "{}")

    @gl.public.view
    def is_flagged(self, holder_address: str, credential_type: str) -> str:
        return self.flagged.get(self._index_key(holder_address, credential_type), "{}")

    @gl.public.view
    def get_owner(self, holder_address: str, credential_type: str) -> str:
        # Ownership is independent of the current verdict; it persists across
        # VERIFIED / SUSPICIOUS / UNVERIFIED transitions.
        return self.owners.get(self._index_key(holder_address, credential_type), "")

    @gl.public.view
    def get_credential_count(self) -> int:
        return self.credential_count

    @gl.public.view
    def get_stats(self) -> dict:
        verified = unverified = suspicious = pending = 0
        for v in self.credentials.values():
            c = json.loads(v)
            if c["status"] == "PENDING": pending += 1
            elif c["status"] == "VERIFIED":
                if c["result"] == "VERIFIED": verified += 1
                elif c["result"] == "UNVERIFIED": unverified += 1
                elif c["result"] == "SUSPICIOUS": suspicious += 1
        return {
            "total": len(self.credentials), "pending": pending,
            "verified": verified, "unverified": unverified,
            "suspicious": suspicious,
            "verified_count": len(self.verified),
            "flagged_count": len(self.flagged),
        }

    @gl.public.view
    def list_credentials(self) -> dict:
        result = {}
        for k, v in self.credentials.items():
            c = json.loads(v)
            result[str(k)] = {
                "holder": c["holder_name"],
                "holder_address": c["holder_address"],
                "type": c["credential_type"],
                "issuer": c["issuer"],
                "status": c["status"],
                "result": c["result"],
                "score": c["validity_score"],
            }
        return result
