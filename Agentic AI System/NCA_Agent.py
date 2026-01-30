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
import io
import time
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


# ---------------------------
# CONFIG
# ---------------------------
os.environ["OPENAI_API_KEY"] = ""

# Initialize Supabase client
SUPABASE_URL = ""
SUPABASE_KEY = ""
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

IPFS_GATEWAY = "https://gateway.pinata.cloud/ipfs/"

rpc_url = ""
shipping_contract_address = ""
registration_contract_address = ""
w3 = Web3(Web3.HTTPProvider(rpc_url))
shipping_contract_abi = []
registration_contract_abi = []

#shipping_contract = w3.eth.contract(address=Web3.to_checksum_address(shipping_contract_address), abi=shipping_contract_abi)
#registration_contract = w3.eth.contract(address=Web3.to_checksum_address(registration_contract_address), abi=registration_contract_abi)

# ---------------------------
# SYSTEM INSTRUCTIONS
# ---------------------------
SYSTEM_INSTRUCTIONS_NCA = """
    You are the National Quota Validation Agent (NCA version).
    You validate a shipment against your country's NATIONAL quota and (only with explicit user approval) update national usage.

    TOOLS AVAILABLE:
        • get_nca_quota_cap(country, substance, year, mode)
        • update_nca_quota_usage(country, substance, year, mode, quantity)

    SCOPE:
    - You operate ONLY at the national level for the provided `country`.
    - Validate ONE side per call based on `mode`:
        mode="export"  → check nationalExport vs usedExport
        mode="import"  → check nationalImport vs usedImport

    REQUIRED INPUTS (from caller):
    - country: string (ISO-3, your NCA’s country)
    - substance: string
    - year: int
    - mode: "export" | "import"
    - quantity_base: int (grams)
    - update_requested: bool (default false)

    ORDERED STEPS (ALWAYS IN THIS ORDER):
    1) Call `get_nca_quota_cap(country, substance, year, mode)` to retrieve:
        - For export:  { nationalExport, usedExport }
        - For import:  { nationalImport, usedImport }
        If no record is found → return status="missing_caps", valid=false.

    2) Compute remaining quota for the selected mode:
       - export:  remaining = nationalExport - usedExport
       - import:  remaining = nationalImport - usedImport
       If quantity_base ≤ remaining → status="within_quota", valid=true
       Else → status="exceeds_quota", valid=false   
    
    3) Database update protocol (ONLY IF update_requested=true AND valid=true):
        - You MUST present the exact proposed change (field, old value, new value) and WAIT for explicit user approval.
        - Only after explicit approval, call:
            `update_nca_quota_usage(country, substance, year, mode, quantity_base)`
            Set `updated=true` on success; otherwise `updated=false`.
        - If user does not approve, DO NOT update.
    RULES:
    - All math MUST use integer base units (grams).
    - No changes to any data without explicit user approval of the exact diff.
    - No cross-border/global updates; do not reference INCB or other countries.
    - On tool failures, return the appropriate error status: "db_error".
    - Output ONLY the specified JSON—no extra text.

    OUTPUT FORMAT (JSON ONLY):
    {
        "valid": true|false,
        "status": "within_quota" | "exceeds_quota" | "missing_caps" | "db_error",
        "evaluated_against": {
            "nationalCap": <int>,      // nationalExport or nationalImport based on mode
            "consumed_base": <int>,    // usedExport or usedImport based on mode
            "remaining_base": <int>,
            "mode": "<export|import>"
        },
        "update_proposed": { "field": "<usedExport|usedImport>", "old": <int>, "new": <int> } | null,
        "updated": true|false,
        "notes": "<short reason>"
    }
"""

SYSTEM_INSTRUCTIONS_NATIONAL_VERIFICATION_AGENT = """
    You are the National Competent Authority (NCA) Auditing and Verification Agent.
    Your purpose is to validate and authorize export/import permit requests for controlled-medication shipments
    in accordance with national and INCB rules, and to generate the final permit authorization document (PDF)
    when all checks have been passed.

    -------------------------------------------------------------------------
    INPUTS EXPECTED FROM THE USER:
    -------------------------------------------------------------------------
    - country_name: string (name of the country of the NCA)
    - actor_address: string (blockchain address of the exporter/importer)
    - shipment_id: integer (shipment ID stored on-chain)
    - mode: "export" or "import"

    -------------------------------------------------------------------------
    SEQUENTIAL OPERATIONS (IN ORDER)
    -------------------------------------------------------------------------

    1) RETRIEVE ACTOR LICENSING:
        - Call `get_licensing_ipfs_doc(actor_address, country_name, mode)` to retrieve the actor’s licensing document from IPFS.
        - Analyze the document to ensure:
            • The license is valid and active.
            • The actor (exporter or importer) is authorized to handle the specified controlled substance.
            • The license dates cover the current shipment period.
        - If the license is invalid, expired, missing, or mismatched → STOP and inform the user that authorization cannot proceed.

    2) RETRIEVE SHIPMENT DETAILS:
        - Call `get_shipment_details(shipment_id)` to fetch the on-chain shipment record.
        - Then call `get_shipment_ipfs_doc(shipment_id)` to retrieve the corresponding shipment document stored on IPFS.
        - Compare the on-chain data and IPFS document to ensure consistency:
            • Same exporter/importer addresses.
            • Same countries, substance, quantity, and year.
            • Same permit IDs if already linked.
        - If any mismatch or inconsistency is found → STOP and inform the user.

    3) VALIDATE NATIONAL RULES AND POLICIES:
        - Call `read_country_nca_rules_file(country_name, mode)` to retrieve the text of the national import/export rules.
        - Analyze whether the requested shipment is allowed:
            • Check if the substance is permitted for export/import.
            • Confirm that the quantity and conditions meet the policy requirements.
            • Identify any prohibition, quota, or authorization constraint.
        - If any violation, ban, or policy restriction is found → STOP and inform the user.

    4) VALIDATE NATIONAL QUOTAS:
        - Construct a natural-language query containing all shipment details:
          "Verify if the shipment of {quantity} g of {substance} in year {year} by {country_name} ({mode}) is within the national quota and does not exceed the remaining available quantity."
        - Call `call_quota_validation_agent(query)` to perform the quota verification.
        - If within caps → continue.
        - If exceeds caps or inconsistency detected → STOP and inform the user.

    5) GENERATE PERMIT AUTHORIZATION:
        - If all validations passed:
            • Prepare a text version of the authorization document, including:
                - Country name, mode (export/import)
                - Actor details (address, license number if available)
                - Substance, quantity, year
                - Shipment ID and validation results
                - Authorization timestamp and signature placeholder
            • Call `save_permit_to_pdf(file_text, mode, country_name, year)` to generate and store the permit locally as a PDF.
            • Inform the user that the permit has been successfully generated, and display the local file path.

    6) OPTIONAL: UPDATE LOCAL QUOTA USAGE (ONLY IF USER REQUESTS):
        - The agent may call `call_quota_validation_agent` again with an update command to adjust the consumed quantity in the local DB.
        - This action is performed **only if**:
            • The user explicitly requests the update.
            • The agent presents the exact proposed change (substance, year, mode, old_used, new_used).
            • The user gives explicit approval.
        - Without explicit approval, no database update is performed.

    -------------------------------------------------------------------------
    VIOLATION HANDLING:
    -------------------------------------------------------------------------
    - At any stage, if a check fails (invalid license, rule violation, permit mismatch, or quota excess):
        • STOP immediately.
        • Inform the user with a clear, concise explanation of the violation.
        • Do not attempt to continue to the next steps.

    -------------------------------------------------------------------------
    FINAL OUTPUT STYLE:
    -------------------------------------------------------------------------
    - Respond in natural text, clearly summarizing:
        • Each step’s result (passed/failed)
        • The specific reason for any failure
        • The final outcome: APPROVED, REJECTED, or REQUIRES USER APPROVAL
    - When a permit is successfully generated, include the local PDF file path in your message.
    - If a user approval is required (for quota DB update), explicitly ask:
        "Do you approve updating the local quota database with the following change (yes/no)?"

    -------------------------------------------------------------------------
    SUMMARY OF ROLE:
    -------------------------------------------------------------------------
    - You represent the National Competent Authority for the given country.
    - You ensure the actor is licensed, the shipment is legitimate, the policies are met, and quotas are respected.
    - You must never authorize a shipment that violates any rule or exceeds national limits.
    - You must stop at the first sign of violation and clearly explain why.
    - You only generate and save a permit if every validation stage succeeds.
    - You only perform DB updates with explicit user consent.
"""


# ---------------------------
# TOOLS
# ---------------------------
@tool
def get_nca_quota_cap(substance: str, year: int, mode: str):
    """
    Retrieve NCA quota cap record for the given substance, and year.

    Args:
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
def update_nca_quota_usage(substance: str, year: int, mode: str, quantity: int):
    """
    Update the usedExport or usedImport value in the nca_quotas table.

    Args:
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
            supabase.table("nca_quotas")
            .select("id, usedexport, usedimport")
            .eq("substance", substance)
            .eq("year", year)
            .execute()
        )

        if not response.data:
            print("No matching NCA quota record found.")
            return None

        record = response.data[0]
        record_id = record["id"]

        # Determine new value
        current_value = record[field_name] or 0
        new_value = current_value + quantity

        # Perform the update
        update_response = (
            supabase.table("nca_quotas")
            .update({field_name: new_value})
            .eq("id", record_id)
            .execute()
        )

        if update_response.data:
            print(f"✅ Successfully updated {field_name} to {new_value} for {substance}-{year}")
            return update_response.data[0]
        else:
            print("⚠️ Update query executed, but no data returned.")
            return None

    except Exception as e:
        print(f"❌ Error updating NCA quota usage: {e}")
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
        ipfs_hash = contract.functions.getIncbCapIpfs().call()
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
def get_shipment_ipfs_doc(shipment_id: int) -> str:
    """
    Retrieve the IPFS file of a shipment.

    Steps:
      1) Call contract.getShipmentIpfsHash(shipment_id) -> bytes32 raw digest (sha2-256).
      2) Convert to CIDv0 (Base58) by prepending multihash prefix 0x12 0x20.
      3) Fetch from Pinata gateway and parse JSON if possible.

    Args:
        shipment_id (int): ID of the shipment to retrieve.
    """
    # --- 1) Call the contract function ---
    ipfs_hash_bytes: bytes = shipping_contract.functions.getShipmentIpfsHash(shipment_id).call()

    # Handle empty hash (all zeros)
    if not ipfs_hash_bytes or set(ipfs_hash_bytes) == {0}:
        raise ValueError(f"Shipment {shipment_id} has a zero/empty IPFS hash.")
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

def get_licensing_ipfs_doc(user_address: str) -> str:
    """
    Retrieve the IPFS file of a user license.

    Steps:
      1) Call contract.getLicenseIpfsHash(shipment_id) -> bytes32 raw digest (sha2-256).
      2) Convert to CIDv0 (Base58) by prepending multihash prefix 0x12 0x20.
      3) Fetch from Pinata gateway and parse JSON if possible.

    Args:
        user_address (str): Ethereum address of the user to retrieve the license for.
    """
    # --- 1) Call the contract function ---
    ipfs_hash_bytes: bytes = registration_contract.functions.getLicenseIpfsHash(user_address).call()

    # Handle empty hash (all zeros)
    if not ipfs_hash_bytes or set(ipfs_hash_bytes) == {0}:
        raise ValueError(f"Shipment {shipment_id} has a zero/empty IPFS hash.")
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
def read_country_nca_rules_file(country_name: str, mode: str) -> str:
    """
    Read and return the text content of a country's import/export file that contains the NCA rules for that country.

    Args:
        country_name (str): Country name (without .txt extension).
        mode (str): "export" or "import"
    """
    
    # Validate mode
    mode = mode.lower().strip()
    if mode not in {"export", "import"}:
        raise ValueError("Mode must be either 'export' or 'import'.")

    # Construct full file path (e.g., France_export.txt)
    file_name = f"{country_name}_{mode}.txt"
    file_path = os.path.join(base_path, file_name)

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
    Send a natural-language query to the NCA Quota Validation Agent and return its response text.

    Args:
        query (str): Natural-language query or command for the agent containing all shipment details.
    """
    try:
        result_nca = agent_nca.invoke(
            {"messages": [{"role": "user", "content": query}]}
        )

        # Extract and return the agent's reply text
        return result_nca["messages"][-1].content

    except Exception as e:
        return f"❌ Error while invoking INCB agent: {e}"

#@tool
def save_permit_to_pdf(file_text: str, mode: str, country: str) -> str:
    """
    Save permit authorization text content to a local PDF file.

    Args:
        file_text (str): The text content of the permit (authorization details).
        mode (str): "export" or "import".
        country (str): Optional country name/code to include in the filename.
    """
    
    base_path = "."
    
    # Validate mode
    mode = (mode or "").strip().lower()
    if mode not in {"export", "import"}:
        raise ValueError("mode must be 'export' or 'import'")

    # Generate filename
    filename = f"permit_{country}_{mode}_{int(time.time())}.pdf"
    file_path = os.path.join(base_path, filename)

    # Create PDF
    c = canvas.Canvas(file_path, pagesize=A4)
    width, height = A4

    # Simple margin and line spacing
    x_margin = 50
    y_position = height - 60
    line_height = 14

    # Write content line by line
    for line in file_text.splitlines():
        c.drawString(x_margin, y_position, line)
        y_position -= line_height
        if y_position < 50:  # new page if too long
            c.showPage()
            y_position = height - 60

    c.save()

    return file_path


tools_nca = [update_nca_quota_usage, get_nca_quota_cap]
tools_national_verification = [get_licensing_ipfs_doc, get_shipment_details, get_shipment_ipfs_doc, read_country_nca_rules_file, call_quota_validation_agent, save_permit_to_pdf]

agent_nca = create_agent("gpt-4o", tools=tools_nca, system_prompt=SYSTEM_INSTRUCTIONS_NCA)
 
    
def main():
    # ---------------------------
    # BUILD AGENT
    # ---------------------------
    agent_national_verification = create_agent("gpt-4o", tools=tools_national_verification, system_prompt=SYSTEM_INSTRUCTIONS_NATIONAL_VERIFICATION, checkpointer=InMemorySaver())
    
    while True:
        user_message = input("\nEnter your question or command for the agent:\n> ")
        if user_message.lower() in {"exit", "quit"}:
            break

        result_national_compliance = agent_national_verification.invoke(
            {"messages": [{"role": "user", "content": user_message}]},
            {"configurable": {"thread_id": "1"}},
        )
        
        # Print agent's response
        print("\n🤖 Agent Response:\n")
        print(result_national_compliance["messages"][-1].content)
    


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
if "agent_national_verification" not in globals() or agent_national_verification is None:
    try:
        agent_national_verification = create_agent(
            "gpt-4o",
            tools=globals().get("tools_national_verification", []),
            system_prompt=globals().get("SYSTEM_INSTRUCTIONS_NATIONAL_VERIFICATION_AGENT", ""),
            checkpointer=InMemorySaver(),
        )
        print("✅ agent_national_verification created for web UI.")
    except Exception as e:
        print(f"⚠️ Could not create agent_national_verification for web UI: {e}")
        agent_national_verification = None

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
app = FastAPI(title="NCA Chatbot UI")

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
      <h2>NCA Verification Chatbot</h2>
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

    if which == "nca":
        if "agent_nca" not in globals() or agent_nca is None:
            return JSONResponse({"error": "NCA agent not available"}, status_code=500)
        try:
            res = agent_nca.invoke({"messages":[{"role":"user","content":message}]})
            reply = _extract_agent_text(res)
        except Exception as e:
            reply = f"Error invoking NCA agent: {e}"
    else:
        if "agent_national_verification" not in globals() or agent_national_verification is None:
            return JSONResponse({"error": "NCA agent not available"}, status_code=500)
        try:
            res = agent_national_verification.invoke({"messages":[{"role":"user","content":message}]}, {"configurable":{"thread_id": session_id}})
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
