"""Smart contract metadata from public verification indexes (Sourcify,
Etherscan). These calls read third-party indexes; they never touch the
target's infrastructure and never send transactions."""

from __future__ import annotations

import re

import httpx

CHAIN_IDS = {
    "Ethereum": 1,
    "Optimism": 10,
    "BNB Chain": 56,
    "Gnosis": 100,
    "Polygon": 137,
    "Sonic": 146,
    "Fantom": 250,
    "zkSync": 324,
    "Mantle": 5000,
    "Base": 8453,
    "Arbitrum": 42161,
    "Avalanche": 43114,
    "Linea": 59144,
    "Blast": 81457,
    "Scroll": 534352,
}

IMPORT_RE = re.compile(r'import\s+(?:[^"\']*from\s+)?["\']([^"\']+)["\']')


def abi_signals(abi: list) -> dict:
    names = {item.get("name") for item in abi or [] if isinstance(item, dict)}
    roles = sorted(n for n in names if n and (n.endswith("_ROLE") or n in {"owner", "admin", "getRoleAdmin", "hasRole", "pendingOwner", "guardian"}))
    upgradeable = bool(names & {"upgradeTo", "upgradeToAndCall", "implementation", "proxiableUUID"})
    return {"admin_roles": roles, "upgradeable": upgradeable}


def dependencies_from_source(source: str) -> list[str]:
    deps = set()
    for imp in IMPORT_RE.findall(source or ""):
        if imp.startswith("@"):
            deps.add("/".join(imp.split("/")[:2]))
        elif not imp.startswith("."):
            deps.add(imp.split("/")[0])
    return sorted(deps)


def from_etherscan(address: str, chain: str, api_key: str, client: httpx.Client) -> dict | None:
    chain_id = CHAIN_IDS.get(chain)
    if not api_key or not chain_id:
        return None
    resp = client.get(
        "https://api.etherscan.io/v2/api",
        params={"chainid": chain_id, "module": "contract", "action": "getsourcecode", "address": address, "apikey": api_key},
    )
    resp.raise_for_status()
    result = (resp.json().get("result") or [None])[0]
    if not isinstance(result, dict):
        return None
    import json

    abi = []
    if result.get("ABI") and not result["ABI"].startswith("Contract source code not verified"):
        try:
            abi = json.loads(result["ABI"])
        except ValueError:
            abi = []
    verified = bool(result.get("SourceCode"))
    signals = abi_signals(abi)
    return {
        "verified_source": verified,
        "verification_source": "etherscan" if verified else None,
        "compiler_version": result.get("CompilerVersion") or None,
        "abi_available": bool(abi),
        "is_proxy": result.get("Proxy") == "1",
        "implementation_address": (result.get("Implementation") or None),
        "upgradeable": signals["upgradeable"] or result.get("Proxy") == "1",
        "admin_roles": signals["admin_roles"],
        "external_dependencies": dependencies_from_source(result.get("SourceCode", "")),
    }


def from_sourcify(address: str, chain: str, client: httpx.Client) -> dict | None:
    chain_id = CHAIN_IDS.get(chain)
    if not chain_id:
        return None
    resp = client.get(
        f"https://sourcify.dev/server/v2/contract/{chain_id}/{address}",
        params={"fields": "abi,compilation,proxyResolution"},
    )
    if resp.status_code == 404:
        return {"verified_source": False, "verification_source": None}
    resp.raise_for_status()
    data = resp.json()
    proxy = data.get("proxyResolution") or {}
    impls = proxy.get("implementations") or []
    signals = abi_signals(data.get("abi") or [])
    return {
        "verified_source": bool(data.get("match")),
        "verification_source": "sourcify" if data.get("match") else None,
        "compiler_version": (data.get("compilation") or {}).get("compilerVersion"),
        "abi_available": bool(data.get("abi")),
        "is_proxy": proxy.get("isProxy"),
        "implementation_address": impls[0].get("address") if impls else None,
        "upgradeable": signals["upgradeable"] or bool(proxy.get("isProxy")),
        "admin_roles": signals["admin_roles"],
    }
