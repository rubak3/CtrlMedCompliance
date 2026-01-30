import os
from langchain.agents import create_agent
from langchain.tools import tool
from langchain.messages import HumanMessage, AIMessage, SystemMessage
from supabase import create_client, Client
import json
import hashlib
import requests
from typing import Optional, Tuple, Dict, Any
from web3 import Web3
from langgraph.checkpoint.memory import InMemorySaver 

# ---------------------------
# CONFIG
# ---------------------------
os.environ["OPENAI_API_KEY"] = "Your-API-Key"

# Initialize Supabase client
SUPABASE_URL = "Your-SUPABASE-URL"
SUPABASE_KEY = "Your-SUPABASE-Key"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

IPFS_GATEWAY = "https://gateway.pinata.cloud/ipfs/"

rpc_url = "https://sepolia.infura.io/v3/Your-Infura-ID"
shipping_contract_address = ""
compliance_contract_address = ""
w3 = Web3(Web3.HTTPProvider(rpc_url))
shipping_contract_abi = []
compliance_contract_abi = []

shipping_contract = w3.eth.contract(address=Web3.to_checksum_address(shipping_contract_address), abi=shipping_contract_abi)
compliance_contract = w3.eth.contract(address=Web3.to_checksum_address(compliance_contract_address), abi=compliance_contract_abi)

# ---------------------------
# SYSTEM INSTRUCTIONS
# ---------------------------
SYSTEM_INSTRUCTIONS_INCB = """
    You are the International Quota Validation Agent (INCB version).
    Your job is to validate a shipment against INCB global quotas and (only upon explicit user approval) update global consumption.

    SCOPE & SIDES:
    You MUST always validate BOTH sides of a shipment:
    • EXPORT SIDE  → (country=export_country, mode="export")
    • IMPORT SIDE  → (country=import_country, mode="import")

    BEHAVIORAL REQUIREMENT (ORDERED STEPS FOR EACH SIDE):
    1) Call `get_caps_from_ipfs(cid, mode, country, substance, year)` to fetch authoritative caps for that side.
    2) Call `get_incb_quota_cap(country, substance, year, mode)` to read the DB record for that side.
    3) Verify integrity:
        - The IPFS incbCap must match the DB incbCap.
        - The IPFS national cap (nationalExport or nationalImport, per mode) must match the DB national cap.
        - If any mismatch → set status="cap_doc_integrity_failed" for that side (no recomputation, no updates).
    4) Compute remaining quota for that side:
        remaining = incbCap - (usedExport or usedImport).
        If shipment quantity (in grams) ≤ remaining → status="within_quota" for that side.
        Otherwise → status="exceeds_quota" for that side.
    5) Database updates:
        - `update_incb_quota_usage(...)` MUST be called ONLY if the user explicitly requests an update AND
        ONLY AFTER you present the exact proposed change (field, old value, new value, side) and receive explicit approval.
        - Without explicit user approval of the exact change, DO NOT update the DB.

    GLOBAL VERDICT:
    Combine both sides:
    - If BOTH sides end as "within_quota" (or become valid after permitted recomputation), the shipment is valid.
    - If either side is "cap_doc_integrity_failed" → overall valid=false with that status highlighted.

    RULES:
    - Always use base units (grams); convert before comparison.
    - Prefer IPFS + chain-derived values over DB.
    - If any tool call fails, return the appropriate error status for that side: "sc_error" | "ipfs_error" | "db_error".
    - Do NOT perform any DB update without explicit user approval of the exact diff.

    INPUTS EXPECTED (provided by caller):
    - export_country: string (ISO-3, bytes3-compatible)
    - import_country: string (ISO-3, bytes3-compatible)
    - substance: string
    - year: int
    - quantity_base: int (grams)
    - update_requested: bool (default false)

    OUTPUT FORMAT (JSON ONLY; no extra text):
    {
        "valid": true|false,
        "export_side": {
            "status": "within_quota" | "exceeds_quota" | "recomputed" | "cap_doc_integrity_failed" | "sc_error" | "ipfs_error" | "db_error",
            "evaluated_against": { "incbCap": <int>, "consumed_base": <int>, "remaining_base": <int>, "unit_base": "g" },
            "update_proposed": { "field": "usedExport", "old": <int>, "new": <int> } | null,
            "updated": true|false
        },
        "import_side": {
            "status": "within_quota" | "exceeds_quota" | "recomputed" | "cap_doc_integrity_failed" | "sc_error" | "ipfs_error" | "db_error",
            "evaluated_against": { "incbCap": <int>, "consumed_base": <int>, "remaining_base": <int>, "unit_base": "g" },
            "update_proposed": { "field": "usedImport", "old": <int>, "new": <int> } | null,
            "updated": true|false
        },
        "notes": "<short reason; optional>"
    }

    APPROVAL PROTOCOL FOR UPDATES:
    - If update_requested=true AND a side is valid:
        • Propose the exact change in `update_proposed` (field, old, new).
        • WAIT for explicit user confirmation.
        • Only after approval, call `update_incb_quota_usage(...)` and set `updated=true`.
    - If no approval, do not update and set `updated=false`.

    OUTPUT CONSTRAINT:
    Only output valid JSON as specified. No explanations outside the JSON payload.
"""

SYSTEM_INSTRUCTIONS_GLOBAL_COMPLIANCE = """
    You are the Global Compliance Agent (INCB version).
    Your responsibility is to validate international controlled-medication shipments across all dimensions of compliance:
    - National rules and INCB policies for both export and import sides.
    - Validity of the export and import permits (retrieved from IPFS).
    - Quota compliance of both countries according to the INCB Quota Validation Agent.

    You act as the final compliance verifier before shipment approval or rejection.

    -------------------------------------------------------------------------
    OPERATIONAL SEQUENCE (MUST FOLLOW IN ORDER)
    -------------------------------------------------------------------------

    1) FETCH SHIPMENT DETAILS:
        - Call `get_shipment_details(shipment_id)` to obtain on-chain data.
        - Extract exporter/importer addresses, origin and destination countries, substance, quantity, year, and permit IDs.

    2) LOAD COUNTRY COMPLIANCE RULES:
        - Call `read_country_incb_rules_file(export_country)` and `read_country_incb_rules_file(import_country)`.
        - Analyze both files to identify prohibitions, restrictions, or conditions for the shipment’s substance, quantity, or flow direction.
        - If any rule forbids this transaction (e.g., banned export, restricted import, prohibited substance):
            → Immediately reject the shipment and clearly state which rule caused the violation.
            → STOP all further actions.

    3) VERIFY PERMITS (IPFS):
        - Call `get_export_permit(export_permit_id)` and `get_import_permit(import_permit_id)` to retrieve text from IPFS.
        - Verify that:
            • The permits belong to the correct shipment (ID, parties, substance, quantity, year).
            • Both are valid (not expired, revoked, or mismatched).
            • Quantities and substances align with shipment details.
        - If any inconsistency or invalid permit is found:
            → Reject the shipment and clearly explain the issue.
            → STOP.

    4) QUOTA VALIDATION (BOTH SIDES):
        - Prepare a natural-language query summarizing shipment details:
          "Verify whether {quantity} g of {substance} in year {year} is within export cap for {export_country} and import cap for {import_country}."
        - Call `call_quota_validation_agent(query)` and interpret results.
        - If both sides are within caps → proceed to step 6.
        - If either side exceeds caps → go to step 5.

    5) QUOTA DISCREPANCY RESOLUTION:
        - Recalculate on-chain consumption totals:
            • `get_quota_consumed_events_sum(export_country, substance, year, "export")`
            • `get_quota_consumed_events_sum(import_country, substance, year, "import")`
        - Compare recalculated values with INCB DB results.
            • If the recalculated values match INCB DB but caps are exceeded:
                → Conclude potential NCA data manipulation.
                → Reject shipment and state that the NCA database must be corrected.
            • If the recalculated values differ and show that shipment is actually within caps:
                → Propose an update to the INCB DB (show exact old and new values).
                → Ask for explicit user approval before any update.
                    - If user approves → update the DB via `call_quota_validation_agent` and approve shipment.
                    - If user denies → approve the shipment (as on-chain correct) but note DB inconsistency.

    6) FINAL DECISION:
        - If all checks (rules, permits, quotas) pass → Approve shipment.
        - If any stage fails → Reject shipment.
        - The response should always clearly explain:
            • Which steps were performed.
            • Whether each side (export/import) passed.
            • The reason for final approval or rejection.

    7) Update Quota Consumption:
        - If user requested to update quota consumption at any time:
            update the DB via `call_quota_validation_agent` by asking it to update the quota consumption.
            
    -------------------------------------------------------------------------
    RULES AND BEHAVIORAL REQUIREMENTS
    -------------------------------------------------------------------------
    • Always validate BOTH export and import sides independently.
    • Never call `get_quota_consumed_events_sum` unless:
        - The quota validation shows discrepancies, OR
        - The user explicitly requests recomputation.
    • Never perform any database update without:
        - Presenting the exact proposed changes (field names, old and new values), AND
        - Receiving explicit user approval.
    • Always treat on-chain and IPFS data as the authoritative source.
    • Convert all quantities to base units (grams) before comparisons.
    • If a tool fails, mention which tool failed (e.g., “permit retrieval failed” or “smart contract access failed”).
    • Be concise and factual — no extra commentary beyond reasoning or conclusions.

    -------------------------------------------------------------------------
    OUTPUT FORMAT AND STYLE
    -------------------------------------------------------------------------
    • Summarize reasoning clearly, step by step.
    • Provide a final verdict in plain text:
        - “APPROVED” → if all checks passed.
        - “REJECTED” → with a clear reason (rule violation, invalid permit, quota exceeded, or DB discrepancy).
        - “APPROVED WITH WARNING” → if approved but database or policy inconsistencies detected.
    • When user approval is required for a DB update, explicitly ask for consent using natural language:
        “I can proceed to update the database with the corrected quota values. Do you approve these exact changes (yes/no)?”

    -------------------------------------------------------------------------
    SUMMARY OF YOUR ROLE
    -------------------------------------------------------------------------
    - You are the INCB’s global compliance controller.
    - Your mission: verify every shipment’s legality, legitimacy, and quota correctness.
    - You must stop at the first proven violation.
    - You must never modify records without user consent.
    - You must reason transparently and deliver a short, human-readable compliance decision.
"""



# ---------------------------
# TOOLS
# ---------------------------
@tool
def get_incb_quota_cap(country: str, substance: str, year: int, mode: str):
    """
    Retrieve INCB quota cap record for the given country, substance, and year.

    Args:
        country: ISO country code
        substance: Controlled substance name
        year: Target year
        mode: "export" or "import"
    """
    try:
        # Validate mode
        mode = mode.lower()
        if mode not in ("export", "import"):
            raise ValueError("Mode must be 'export' or 'import'")

        # Query the record
        response = (
            supabase.table("incb_quotas")
            .select("incbcap, nationalexport, nationalimport, usedexport, usedimport")
            .eq("country", country)
            .eq("substance", substance)
            .eq("year", year)
            .execute()
        )

        if not response.data:
            print("No quota cap record found.")
            return None

        record = response.data[0]

        # Return selected fields based on mode
        if mode == "export":
            return {
                "incbCap": record["incbcap"],
                "nationalExport": record["nationalexport"],
                "usedExport": record["usedexport"],
            }
        else:  # mode == "import"
            return {
                "incbCap": record["incbcap"],
                "nationalImport": record["nationalimport"],
                "usedImport": record["usedimport"],
            }

    except Exception as e:
        print(f"Error fetching INCB quota cap: {e}")
        return None

@tool
def update_incb_quota_usage(country: str, substance: str, year: int, mode: str, quantity: int):
    """
    Update the usedExport or usedImport value in the incb_quotas table.

    Args:
        country: ISO country code
        substance: Controlled substance name
        year: Target year
        mode: 'export' or 'import'
        quantity (int): The quantity to add or set (in base units)
    """

    try:
        mode = mode.lower()
        if mode not in ("export", "import"):
            raise ValueError("Mode must be 'export' or 'import'")

        field_name = "usedexport" if mode == "export" else "usedimport"

        # Fetch the existing record first
        response = (
            supabase.table("incb_quotas")
            .select("id, usedexport, usedimport")
            .eq("country", country)
            .eq("substance", substance)
            .eq("year", year)
            .execute()
        )

        if not response.data:
            print("No matching INCB quota record found.")
            return None

        record = response.data[0]
        record_id = record["id"]

        # Determine new value
        current_value = record[field_name] or 0
        new_value = current_value + quantity

        # Perform the update
        update_response = (
            supabase.table("incb_quotas")
            .update({field_name: new_value})
            .eq("id", record_id)
            .execute()
        )

        if update_response.data:
            print(f"✅ Successfully updated {field_name} to {new_value} for {country}-{substance}-{year}")
            return update_response.data[0]
        else:
            print("⚠️ Update query executed, but no data returned.")
            return None

    except Exception as e:
        print(f"❌ Error updating INCB quota usage: {e}")
        return None
    
class IPFSError(Exception):
    """Raised when an IPFS retrieval or integrity check fails."""

def _fetch_ipfs_json(cid: str,gateway_url: str = IPFS_GATEWAY,timeout: int = 20) -> Tuple[Dict[str, Any] | list, str]:
    """Fetch JSON from IPFS via Pinata gateway; return (obj, sha256_hex).
       If canonicalize=True, hash is over canonical JSON (sorted keys, no spaces)."""
    # Normalize base
    if not gateway_url.endswith("/"):
        gateway_url += "/"
    url = f"{gateway_url}{cid}"

    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()

        # Parse JSON content
        content = response.json()
        return content

    except requests.RequestException as e:
        raise Exception(f"Error fetching IPFS content for CID {cid}: {e}")

    except ValueError as e:
        raise Exception(f"Invalid JSON content for CID {cid}: {e}")

def _norm_country(s: Optional[str]) -> Optional[str]:
    return s.upper().strip() if isinstance(s, str) else s

def _to_int(y: Any) -> Optional[int]:
    try:
        return int(y)
    except Exception:
        return None

def _extract_record_generic(data: Any, country: str, substance: str, year: int) -> Optional[Dict[str, Any]]:
    """
    Find record for (country, substance, year) in common shapes:
      1) List[ { country, substance, year, incbCap, nationalExport, nationalImport } ]
      2) Nested dict: data[country][substance][year] -> { ... }
      3) Wrapper: { "records": [ ...as in (1)... ] }
    """
    C = _norm_country(country)
    S = str(substance).strip().lower()
    Y = int(year)

    # Case A: list
    if isinstance(data, list):
        for rec in data:
            if not isinstance(rec, dict):
                continue
            rc = _norm_country(rec.get("country") or rec.get("Country"))
            rs = str(rec.get("substance") or rec.get("Substance") or "").strip().lower()
            ry = _to_int(rec.get("year") or rec.get("Year"))
            if rc == C and rs == S and ry == Y:
                return rec

    # Case B: wrapper
    if isinstance(data, dict) and "records" in data and isinstance(data["records"], list):
        return _extract_record_generic(data["records"], country, substance, year)

    # Case C: nested dict
    if isinstance(data, dict):
        for c_key, c_val in data.items():
            if _norm_country(c_key) != C:
                continue
            if isinstance(c_val, dict):
                for s_key, s_val in c_val.items():
                    if str(s_key).strip().lower() != S:
                        continue
                    if isinstance(s_val, dict):
                        if str(Y) in s_val and isinstance(s_val[str(Y)], dict):
                            return s_val[str(Y)]
                        if Y in s_val and isinstance(s_val[Y], dict):
                            return s_val[Y]

    return None

def _pick_case_insensitive(rec: Dict[str, Any], *keys: str):
    # exact first
    for k in keys:
        if k in rec:
            return rec[k]
    # case-insensitive fallback
    lower_map = {str(k).lower(): v for k, v in rec.items()}
    for k in keys:
        if lower_map.get(k.lower()) is not None:
            return lower_map[k.lower()]
    return None

def _to_int_or_raise(v: Any, name: str) -> int:
    try:
        return int(v)
    except Exception:
        raise IPFSError(f"Field '{name}' must be integer-like, got: {v!r}")

@tool
def get_caps_from_ipfs(mode: str,country: str,substance: str,year: int) -> Dict[str, Any]:
    """
    Get IPFS CID from smart contract and then fetch an IPFS JSON doc and return caps for (country, substance, year) based on mode.
    - mode='export' -> { 'incbCap', 'nationalExport'}
    - mode='import' -> { 'incbCap', 'nationalImport'}

    Args:
        mode: 'export' or 'import'
        country: ISO country code (case-insensitive)
        substance: substance key/name (case-insensitive)
        year: year as integer
    """
    
    try:
        ipfs_hash = compliance_contract.functions.getIncbCapIpfs().call()
        print(f"✅ IPFS CID retrieved: {ipfs_hash}")
    
        data = _fetch_ipfs_json(
            cid=ipfs_hash,
            gateway_url=IPFS_GATEWAY,
        )

        rec = _extract_record_generic(data, country=country, substance=substance, year=year)
        if rec is None:
            raise IPFSError(f"No matching record for {country}-{substance}-{year} in CID {ipfs_hash}")

        incb_cap = _pick_case_insensitive(rec, "incbCap", "incbcap", "INCB_CAP", "INCBcap")
        if incb_cap is None:
            raise IPFSError("Missing 'incbCap' in the matched IPFS record")
        incb_cap = _to_int_or_raise(incb_cap, "incbCap")

        if mode == "export":
            nat_export = _pick_case_insensitive(rec, "nationalExport", "national_export", "nationalexport")
            if nat_export is None:
                raise IPFSError("Missing 'nationalExport' in the matched IPFS record")
            return {
                "incbCap": incb_cap,
                "nationalExport": _to_int_or_raise(nat_export, "nationalExport")
            }
        else:
            nat_import = _pick_case_insensitive(rec, "nationalImport", "national_import", "nationalimport")
            if nat_import is None:
                raise IPFSError("Missing 'nationalImport' in the matched IPFS record")
            return {
                "incbCap": incb_cap,
                "nationalImport": _to_int_or_raise(nat_import, "nationalImport")
            }
        
    except Exception as e:
        print(f"❌ Error calling getIncbCapIpfs(): {e}")
        return None

def _encode_bytes3(code: str) -> bytes:
    """
    Encode a 3-letter country code to bytes3 (ASCII). Raises if not exactly 3 chars.
    """
    code = (code or "").strip().upper()
    if len(code) != 3:
        raise ValueError("country code must be exactly 3 characters (e.g., 'ARE', 'SAU', 'DEU')")
    b = code.encode("ascii")
    if len(b) != 3:
        raise ValueError("country code must be ASCII encodable and 3 bytes long")
    return b

def _encode_bytes32_substance(substance: str) -> bytes:
    """
    Encode a short substance key/name to bytes32 by UTF-8 then right-padding with zeros.
    (If you already emit a bytes32 from Solidity, pass the exact same encoding when comparing.)
    """
    s = (substance or "").strip()
    b = s.encode("utf-8")
    if len(b) > 32:
        raise ValueError("substance string too long to fit in bytes32 (max 32 bytes)")
    return b.ljust(32, b"\x00")

@tool
def get_quota_consumed_events_sum(mode: str, country: str, substance: str, year: int) -> int:
    """
    Retrieve all ExportQuotaConsumed or ImportQuotaConsumed events from the contract,
    filter by provided fields, return the list of quantities and the total sum.

    Args:
        mode: 'export' -> listen ExportQuotaConsumed, 'import' -> listen ImportQuotaConsumed
        country: 3-letter import/export country ISO (bytes3)
        substance: substance key/name (will be encoded into bytes32 as UTF-8 padded)
        year: uint16 year to match
    """

    # Pick the right event
    if mode == "export":
        event = compliance_contract.events.ExportQuotaConsumed()
    elif mode == "import":
        event = compliance_contract.events.ImportQuotaConsumed()
    else:
        raise ValueError("mode must be 'export' or 'import'")

    # Pull logs (we filter in Python because args are not indexed in the ABI)
    logs = event.get_logs(fromBlock=0, toBlock="latest")

    # Pre-encode filters
    country_b3 = _encode_bytes3(country)
    substance_b32 = _encode_bytes32_substance(substance)
    year_i = int(year)

    quantities: List[int] = []
    matched = 0

    for lg in logs:
        args = lg["args"]

        # Each field expected as bytes/ints by web3.py
        ev_country = bytes(args["country"])
        ev_subst = bytes(args["substance"])
        ev_year = int(args["year"])
        ev_qty = int(args["qty"])

        # Apply filters if provided
        if ev_country != country_b3:
            continue
        if ev_subst != substance_b32:
            continue
        if ev_year != year_i:
            continue

        matched += 1
        quantities.append(ev_qty)

    return sum(quantities)  

@tool
def get_shipment_details(shipment_id: int) -> dict:
    """
    Retrieve a shipment record from the blockchain and return it as a JSON object.

    Args:
        shipment_id (int): ID of the shipment to retrieve.
    """
    
    # Call the smart contract function
    shipment = shipping_contract.functions.getShipmentDetails(shipment_id).call()

    # Convert the Shipment struct into a readable JSON object
    shipment_json = {
        "exporter": shipment[0],
        "importer": shipment[1],
        "currentCustodian": shipment[2],
        "originISO": shipment[3].decode('utf-8').rstrip('\x00'),
        "destISO": shipment[4].decode('utf-8').rstrip('\x00'),
        "substance": shipment[5].hex(),
        "quantity": int(shipment[6]),
        "ipfsHash": shipment[7].hex(),
        "exportPermitId": int(shipment[8]),
        "importPermitId": int(shipment[9]),
        "year": int(shipment[10]),
        "state": int(shipment[11]),
    }

    return shipment_json

@tool
def get_export_permit(permit_id: int) -> str:
    """
    Retrieve the IPFS file of an export permit.

    Steps:
      1) Call contract.getExportPermitHash(permit_id) -> bytes32 raw digest (sha2-256).
      2) Convert to CIDv0 (Base58) by prepending multihash prefix 0x12 0x20.
      3) Fetch from Pinata gateway and parse JSON if possible.

    Args:
        permit_id (int): ID of the export permit to retrieve.
    """
    # --- 1) Call the contract function ---
    ipfs_hash_bytes: bytes = compliance_contract.functions.getExportPermitHash(permit_id).call()

    # Handle empty hash (all zeros)
    if not ipfs_hash_bytes or set(ipfs_hash_bytes) == {0}:
        raise ValueError(f"Permit {permit_id} has a zero/empty IPFS hash.")

    # --- 2) Convert bytes32 → CIDv0 (Base58) ---
    try:
        import base58
    except ImportError as e:
        raise ImportError("Install 'base58' to enable CID conversion (pip install base58).") from e

    # Prepend IPFS CIDv0 multihash prefix (sha2-256: 0x12 0x20)
    multihash = b"\x12\x20" + ipfs_hash_bytes
    cid = base58.b58encode(multihash).decode("utf-8")

    # --- 3) Fetch from Pinata gateway ---
    gateway_base = os.getenv("PINATA_GATEWAY_BASE", "https://gateway.pinata.cloud").rstrip("/")
    url = f"{gateway_base}/ipfs/{cid}"

    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
    except requests.RequestException as e:
        raise ConnectionError(f"Failed to fetch from Pinata gateway: {e}")

    # --- 4) Return text content only ---
    return resp.text.strip()

@tool
def get_import_permit(permit_id: int) -> str:
    """
    Retrieve the IPFS file of an import permit.

    Steps:
      1) Call contract.getImportPermitHash(permit_id) -> bytes32 raw digest (sha2-256).
      2) Convert to CIDv0 (Base58) by prepending multihash prefix 0x12 0x20.
      3) Fetch from Pinata gateway and parse JSON if possible.

    Args:
        permit_id (int): ID of the import permit to retrieve.
    """
    # --- 1) Call the contract function ---
    ipfs_hash_bytes: bytes = compliance_contract.functions.getImportPermitHash(permit_id).call()

    # Handle empty hash (all zeros)
    if not ipfs_hash_bytes or set(ipfs_hash_bytes) == {0}:
        raise ValueError(f"Permit {permit_id} has a zero/empty IPFS hash.")

    # --- 2) Convert bytes32 → CIDv0 (Base58) ---
    try:
        import base58
    except ImportError as e:
        raise ImportError("Install 'base58' to enable CID conversion (pip install base58).") from e

    # Prepend IPFS CIDv0 multihash prefix (sha2-256: 0x12 0x20)
    multihash = b"\x12\x20" + ipfs_hash_bytes
    cid = base58.b58encode(multihash).decode("utf-8")

    # --- 3) Fetch from Pinata gateway ---
    gateway_base = os.getenv("PINATA_GATEWAY_BASE", "https://gateway.pinata.cloud").rstrip("/")
    url = f"{gateway_base}/ipfs/{cid}"

    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
    except requests.RequestException as e:
        raise ConnectionError(f"Failed to fetch from Pinata gateway: {e}")

    # --- 4) Return text content only ---
    return resp.text.strip()

@tool
def read_country_incb_rules_file(country_name: str) -> str:
    """
    Read and return the text content of a country's file that contains the INCB rules for that country.

    Args:
        country_name (str): Country name (without .txt extension).
    """
    import os

    # Construct full file path
    file_path = os.path.join(base_path, f"{country_name}.txt")

    # Read the file safely
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read().strip()
            return content
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {file_path}")
    except UnicodeDecodeError:
        raise UnicodeDecodeError("utf-8", b"", 0, 1, f"Unable to decode {file_path}")

@tool
def call_quota_validation_agent(query: str) -> str:
    """
    Send a natural-language query to the INCB Quota Validation Agent and return its response text.

    Args:
        query (str): Natural-language query or command for the agent containing all shipment details.
    """
    try:
        result_incb = agent_incb.invoke(
            {"messages": [{"role": "user", "content": query}]}
        )

        # Extract and return the agent's reply text
        return result_incb["messages"][-1].content

    except Exception as e:
        return f"❌ Error while invoking INCB agent: {e}"


tools_incb = [get_caps_from_ipfs, update_incb_quota_usage, get_incb_quota_cap]
tools_global_compliance = [get_shipment_details, read_country_incb_rules_file, get_export_permit, get_import_permit, get_quota_consumed_events_sum, call_quota_validation_agent]

agent_incb = create_agent("gpt-4o", tools=tools_incb, system_prompt=SYSTEM_INSTRUCTIONS_INCB)


def main():
    # ---------------------------
    # BUILD GLOBAL COMPLIANCE AGENT
    # ---------------------------
    agent_global_compliance = create_agent(
        "gpt-4o",
        tools=tools_global_compliance,
        system_prompt=SYSTEM_INSTRUCTIONS_GLOBAL_COMPLIANCE,
        checkpointer=InMemorySaver(),
    )

    print("🤖 INCB Global Compliance Chatbot")
    print("Type 'exit' or 'quit' to stop.\n")

    while True:
        user_message = input("> ").strip()

        if user_message.lower() in {"exit", "quit"}:
            print("Exiting chatbot.")
            break

        try:
            result = agent_global_compliance.invoke(
                {"messages": [{"role": "user", "content": user_message}]},
                {"configurable": {"thread_id": "global_chat"}},
            )

            # Extract agent reply
            reply = result["messages"][-1].content

            print("\n🤖 Agent Response:\n")
            print(reply)
            print()

        except Exception as e:
            print(f"\n❌ Error invoking agent: {e}\n")
            
            
            
# ---------------------------
# Minimal web UI integration (append this block at the end of your file)
# Requires: pip install fastapi uvicorn
# ---------------------------

try:
    # FastAPI imports (allowed here)
    from fastapi import FastAPI, Request, HTTPException
    from fastapi.responses import HTMLResponse, JSONResponse
    import uvicorn
    import uuid
    import json
    from typing import Optional, Dict, Any
except Exception as e:
    print("To run the built-in web UI you must install fastapi and uvicorn: pip install fastapi uvicorn")
    raise

# In-memory stores (demo)
_SESSIONS: Dict[str, Dict[str, Any]] = {}
_PENDING_UPDATES: Dict[str, Dict[str, Any]] = {}

# Ensure an agent_global_compliance exists (create-on-demand)
if "agent_global_compliance" not in globals() or agent_global_compliance is None:
    try:
        agent_global_compliance = create_agent(
            "gpt-4o",
            tools=globals().get("tools_global_compliance", []),
            system_prompt=globals().get("SYSTEM_INSTRUCTIONS_GLOBAL_COMPLIANCE", ""),
            checkpointer=InMemorySaver(),
        )
        print("✅ agent_global_compliance created for web UI.")
    except Exception as e:
        print(f"⚠️ Could not create agent_global_compliance for web UI: {e}")
        agent_global_compliance = None

# Helper to safely extract agent reply text
def _extract_agent_text(result: Any) -> str:
    try:
        return result["messages"][-1].content
    except Exception:
        try:
            return result.get("output_text") or str(result)
        except Exception:
            return str(result)

# Create FastAPI app
app = FastAPI(title="INCB Chatbot UI")

@app.get("/", response_class=HTMLResponse)
async def index():
    html = """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>INCB Chatbot</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style>
      body { font-family: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial; background:#f3f4f6; padding:20px; }
      #chat { max-width:900px; margin:auto; background:white; border-radius:8px; padding:18px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
      #messages { height: 60vh; overflow:auto; border:1px solid #e5e7eb; padding:12px; border-radius:6px; background:#fff; display:flex; flex-direction:column; gap:8px; }
      .row { display:flex; align-items:flex-end; gap:8px; }
      .row.agent { justify-content:flex-start; }
      .row.user { justify-content:flex-end; }
      .bubble { display:inline-block; padding:10px 12px; border-radius:12px; max-width:78%; box-shadow: 0 1px 0 rgba(0,0,0,0.02); }
      .bubble.user { background:#dbeafe; color:#0c4a6e; border-bottom-right-radius:4px; }
      .bubble.agent { background:#f3f4f6; color:#111827; border-bottom-left-radius:4px; }
      .icon { width:36px; height:36px; flex:0 0 36px; display:flex; align-items:center; justify-content:center; border-radius:9999px; }
      .icon.user { background: linear-gradient(135deg,#bfdbfe,#60a5fa); }
      .icon.agent { background: linear-gradient(135deg,#e6eef7,#dbeafe); }
      .icon svg { width:18px; height:18px; display:block; }
      .controls { display:flex; gap:8px; margin-top:12px; }
      input[type="text"]{ flex:1; padding:10px; border-radius:8px; border:1px solid #d1d5db; }
      button{ padding:10px 12px; border-radius:8px; border:0; background:#2563eb; color:white; }
      button.secondary{ background:#10b981; }
      small{ color:#6b7280; }
      .meta { font-size:0.85rem; color:#6b7280; margin-top:6px; display:flex; justify-content:space-between; align-items:center; }
      .pending-badge { background:#fde68a; color:#92400e; padding:4px 8px; border-radius:6px; font-weight:600; }
    </style>
  </head>
  <body>
    <div id="chat">
      <h2>INCB Compliance Chatbot</h2>
      <div id="messages"></div>
      <div style="margin-top:8px;"><small>Type messages (e.g., "Validate shipment 123")</small></div>
      <div class="controls">
        <input id="input" type="text" placeholder="Type your question and press Send" />
        <button id="send">Send</button>
        <button id="approve" class="secondary">Approve pending</button>
        <button id="reject">Reject pending</button>
      </div>
      <div class="meta">
        <div id="session">Session: (new)</div>
        <div id="pending"></div>
      </div>
      <div style="margin-top:8px;color:#6b7280;font-size:0.9em;">Note: the backend must be running in the same host:port. This demo keeps updates in-memory and requests exact diffs from you when you approve.</div>
    </div>

    <script>
      let sessionId = null;
      let pendingId = null;
      const messagesEl = document.getElementById('messages');
      const sessionEl = document.getElementById('session');
      const pendingEl = document.getElementById('pending');

      // SVG icons as strings
      const userSvg = '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 12c2.761 0 5-2.239 5-5s-2.239-5-5-5-5 2.239-5 5 2.239 5 5 5z" fill="white"/><path d="M4 20c0-2.21 3.582-4 8-4s8 1.79 8 4v1H4v-1z" fill="white"/></svg>';
      const agentSvg = '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 2a9 9 0 100 18 9 9 0 000-18zm1 5h3v2h-3v3h-2V9H8V7h3V4h2v3z" fill="#0f172a"/></svg>';

      function addMessage(role, text){
        const row = document.createElement('div');
        row.className = 'row ' + (role === 'user' ? 'user' : 'agent');

        // icon element
        const iconWrap = document.createElement('div');
        iconWrap.className = 'icon ' + (role === 'user' ? 'user' : 'agent');
        iconWrap.innerHTML = role === 'user' ? userSvg : agentSvg;

        // bubble element
        const bubble = document.createElement('div');
        bubble.className = 'bubble ' + (role === 'user' ? 'user' : 'agent');
        bubble.textContent = text;

        if(role === 'agent'){
          // agent: icon left, bubble right
          row.appendChild(iconWrap);
          row.appendChild(bubble);
        } else {
          // user: bubble left, icon right (mirror)
          row.appendChild(bubble);
          row.appendChild(iconWrap);
        }

        messagesEl.appendChild(row);
        messagesEl.scrollTop = messagesEl.scrollHeight;
      }

      async function sendMessage(){
        const input = document.getElementById('input');
        const text = input.value.trim();
        if(!text) return;
        addMessage('user', text);
        input.value = '';
        try {
          const res = await fetch('/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: sessionId, message: text })
          });
          const j = await res.json();
          sessionId = j.session_id || sessionId;
          if(sessionId) sessionEl.textContent = 'Session: ' + sessionId;
          const reply = j.agent_text || '(no reply)';
          addMessage('agent', reply);
          if(j.pending_update_id){
            pendingId = j.pending_update_id;
            pendingEl.innerHTML = '<span class="pending-badge">Pending: ' + pendingId + '</span>';
          }
        } catch (e) {
          addMessage('agent', 'Error: ' + String(e));
        }
      }

      async function attachPayloadAndApprove(){
        if(!pendingId){ alert('No pending update'); return; }
        const country = prompt('country (ISO3), e.g. AE:');
        if(!country) return;
        const substance = prompt('substance (key), e.g. morphine:');
        if(!substance) return;
        const year = prompt('year, e.g. 2025:');
        if(!year) return;
        const mode = prompt("mode ('export' or 'import'):", 'export');
        if(!mode) return;
        const quantity = prompt('quantity (grams):');
        if(!quantity) return;

        try{
          const attach = await fetch('/pending_payload', {
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body: JSON.stringify({
              pending_update_id: pendingId,
              country, substance, year: parseInt(year), mode, quantity: parseInt(quantity)
            })
          });
          if(!attach.ok){ throw new Error('attach failed ' + attach.status); }
          const aprov = await fetch('/approve', {
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body: JSON.stringify({ pending_update_id: pendingId, approve: true })
          });
          const apj = await aprov.json();
          addMessage('agent', 'Update applied: ' + JSON.stringify(apj.result || apj));
          pendingId = null;
          pendingEl.innerHTML = '';
        }catch(e){ addMessage('agent', 'Approve error: ' + String(e)); }
      }

      async function rejectPending(){
        if(!pendingId){ alert('No pending update'); return; }
        try{
          const res = await fetch('/approve', {
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body: JSON.stringify({ pending_update_id: pendingId, approve: false })
          });
          const j = await res.json();
          addMessage('agent', 'Pending rejected');
          pendingId = null;
          pendingEl.innerHTML = '';
        }catch(e){ addMessage('agent', 'Reject error: ' + String(e)); }
      }

      document.getElementById('send').addEventListener('click', sendMessage);
      document.getElementById('input').addEventListener('keydown', (e)=>{ if(e.key === 'Enter') sendMessage(); });
      document.getElementById('approve').addEventListener('click', attachPayloadAndApprove);
      document.getElementById('reject').addEventListener('click', rejectPending);
    </script>
  </body>
</html>
    """
    return HTMLResponse(content=html, status_code=200)


@app.post("/chat")
async def chat_endpoint(req: Request):
    payload = await req.json()
    message = payload.get("message")
    which = payload.get("which", "global")
    session_id = payload.get("session_id") or str(uuid.uuid4())
    # store session history minimally
    _SESSIONS.setdefault(session_id, {"history":[]})
    _SESSIONS[session_id]["history"].append({"role":"user","content":message})

    if which == "incb":
        if "agent_incb" not in globals() or agent_incb is None:
            return JSONResponse({"error": "INCB agent not available"}, status_code=500)
        try:
            res = agent_incb.invoke({"messages":[{"role":"user","content":message}]})
            reply = _extract_agent_text(res)
        except Exception as e:
            reply = f"Error invoking INCB agent: {e}"
    else:
        if "agent_global_compliance" not in globals() or agent_global_compliance is None:
            return JSONResponse({"error": "Global agent not available"}, status_code=500)
        try:
            res = agent_global_compliance.invoke({"messages":[{"role":"user","content":message}]}, {"configurable":{"thread_id": session_id}})
            reply = _extract_agent_text(res)
        except Exception as e:
            reply = f"Error invoking global agent: {e}"

    # Heuristic: detect if agent proposed an update. If it did, create a pending id.
    pending_id = None
    if isinstance(reply, str) and ("propose" in reply.lower() or "update the database" in reply.lower() or "proposed" in reply.lower()):
        pending_id = str(uuid.uuid4())
        _PENDING_UPDATES[pending_id] = {
            "session_id": session_id,
            "agent_text": reply,
            "update_payload": None,
            "approved": None,
        }

    _SESSIONS[session_id]["history"].append({"role":"agent","content":reply})

    return JSONResponse({"session_id": session_id, "agent_text": reply, "pending_update_id": pending_id})

@app.post("/pending_payload")
async def pending_payload(req: Request):
    payload = await req.json()
    pid = payload.get("pending_update_id")
    if not pid or pid not in _PENDING_UPDATES:
        raise HTTPException(status_code=404, detail="pending_update_id not found")
    # require exact payload fields
    required = ["country","substance","year","mode","quantity"]
    for f in required:
        if f not in payload:
            raise HTTPException(status_code=400, detail=f"missing field {f}")
    _PENDING_UPDATES[pid]["update_payload"] = {
        "country": payload["country"],
        "substance": payload["substance"],
        "year": int(payload["year"]),
        "mode": payload["mode"],
        "quantity": int(payload["quantity"]),
    }
    return JSONResponse({"ok": True, "pending_update_id": pid})

@app.post("/approve")
async def approve(req: Request):
    payload = await req.json()
    pid = payload.get("pending_update_id")
    approve = payload.get("approve", False)
    if not pid or pid not in _PENDING_UPDATES:
        raise HTTPException(status_code=404, detail="pending_update_id not found")
    pending = _PENDING_UPDATES[pid]
    if approve is False:
        pending["approved"] = False
        return JSONResponse({"ok": True, "pending_update_id": pid, "action":"rejected"})
    # approve true -> require update_payload present
    up = pending.get("update_payload")
    if not up:
        raise HTTPException(status_code=400, detail="no update_payload attached for this pending id")
    # call the update function (use your update_incb_quota_usage tool)
    try:
        # call tool directly; returns DB row or None per your implementation
        res = update_incb_quota_usage(
            country=up["country"],
            substance=up["substance"],
            year=up["year"],
            mode=up["mode"],
            quantity=up["quantity"],
        )
        pending["approved"] = True
        pending["applied_result"] = res
        return JSONResponse({"ok": True, "pending_update_id": pid, "action":"applied", "result": res})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"apply update failed: {e}")

# Run server when the script is executed directly
if __name__ == "__main__":
    print("Starting web UI on http://127.0.0.1:8000 — press CTRL+C to stop")
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=False)
