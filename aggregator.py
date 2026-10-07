#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Public Authorized Node Aggregator (公开授权节点聚合器)
Phase 2:
- Read sources.txt (sole input entry point)
- Download content with timeout, HTTP status checks, and response size limits (streaming)
- Robust format detection (Clash YAML, JSON, Base64 subscriptions, URI lines) with false-positive prevention
- Supported protocols: Shadowsocks, VMess, VLESS (Reality & TLS), Trojan
- Normalize into unified internal representation
- Validate nodes (port, server, required credentials)
- Deduplicate nodes with deterministic SHA-256 fingerprint and track source attribution
- Export to Clash / Clash Meta (Mihomo) YAML (output/sub.yaml) with unique naming and source attribution
- Output machine-readable attribution mapping (output/attribution.json)
"""

import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
import re
import sys
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

import requests
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("aggregator")

DEFAULT_MAX_SOURCE_BYTES = 10 * 1024 * 1024


def load_sources(sources_path: str = "sources.txt") -> List[str]:
    """
    Read source URLs or file paths from sources.txt.
    Ignores empty lines and comments starting with '#'.
    """
    if not os.path.exists(sources_path):
        logger.warning(f"Sources file not found at: {sources_path}")
        return []

    sources = []
    with open(sources_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            sources.append(line)

    logger.info(f"Loaded {len(sources)} sources from {sources_path}")
    return sources


def download_sources(
    source_urls: List[str],
    timeout: int = 15,
    max_size_bytes: int = DEFAULT_MAX_SOURCE_BYTES,
) -> Dict[str, Optional[str]]:
    """
    Download raw text from sources using requests with streaming.
    Supports HTTP/HTTPS URLs as well as local file paths for testing.
    Individual failures are logged and do not halt the process.
    Enforces HTTP status check and maximum size limit.
    """
    results: Dict[str, Optional[str]] = {}
    headers = {
        "User-Agent": "ClashForWindows/0.20.39 (Clash.Meta; Open-Source Node Aggregator)"
    }

    for url in source_urls:
        logger.info(f"Fetching source: {url}")
        if url.startswith("http://") or url.startswith("https://"):
            try:
                with requests.get(
                    url,
                    timeout=timeout,
                    headers=headers,
                    stream=True,
                    allow_redirects=True,
                ) as response:
                    # 1. HTTP status check
                    if response.status_code != 200:
                        logger.warning(
                            f"Failed to fetch {url}: HTTP {response.status_code}"
                        )
                        results[url] = None
                        continue

                    # 2. Check Content-Length header if available
                    content_length = response.headers.get("Content-Length")
                    if content_length:
                        try:
                            if int(content_length) > max_size_bytes:
                                logger.warning(
                                    f"Source {url} Content-Length ({content_length} bytes) "
                                    f"exceeds maximum allowed limit ({max_size_bytes} bytes). Skipping."
                                )
                                results[url] = None
                                continue
                        except ValueError:
                            pass

                    # 3. Stream content with strict byte count ceiling
                    downloaded = bytearray()
                    exceeded = False
                    for chunk in response.iter_content(chunk_size=65536):
                        downloaded.extend(chunk)
                        if len(downloaded) > max_size_bytes:
                            logger.warning(
                                f"Source {url} exceeded maximum allowed download size "
                                f"({max_size_bytes} bytes) during streaming. Aborting download."
                            )
                            exceeded = True
                            break

                    if exceeded:
                        results[url] = None
                    else:
                        text_content = downloaded.decode("utf-8", errors="ignore")
                        results[url] = text_content
                        logger.info(
                            f"Successfully downloaded source: {url} ({len(text_content)} characters)"
                        )

            except requests.Timeout:
                logger.warning(f"Connection timeout ({timeout}s) while fetching {url}")
                results[url] = None
            except requests.RequestException as e:
                logger.warning(f"Network error fetching {url}: {e}")
                results[url] = None
            except Exception as e:
                logger.warning(f"Unexpected error fetching {url}: {e}")
                results[url] = None
        else:
            # Local file fallback (useful for offline testing / CI)
            local_path = url[7:] if url.startswith("file://") else url
            if os.path.exists(local_path):
                try:
                    file_size = os.path.getsize(local_path)
                    if file_size > max_size_bytes:
                        logger.warning(
                            f"Local file {local_path} ({file_size} bytes) exceeds limit ({max_size_bytes} bytes)."
                        )
                        results[url] = None
                        continue

                    with open(local_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    results[url] = content
                    logger.info(
                        f"Successfully loaded local file source: {url} ({len(content)} bytes)"
                    )
                except Exception as e:
                    logger.warning(f"Failed reading local file {url}: {e}")
                    results[url] = None
            else:
                logger.warning(
                    f"Source is neither a valid HTTP(S) URL nor an existing local file: {url}"
                )
                results[url] = None

    return results


def _b64_decode_flexible(s: str) -> Optional[str]:
    """
    Decode standard or URL-safe base64 string with missing padding handling.
    """
    s = s.strip()
    s_clean = "".join(s.split())
    if not s_clean:
        return None

    missing_padding = len(s_clean) % 4
    if missing_padding:
        s_clean += "=" * (4 - missing_padding)

    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            decoded_bytes = decoder(s_clean.encode("utf-8"))
            return decoded_bytes.decode("utf-8", errors="ignore")
        except Exception:
            continue
    return None


def parse_uri(uri: str, source_url: str) -> Optional[Dict[str, Any]]:
    """
    Parse a single node URI (ss, vmess, vless, trojan) into normalized node structure.
    """
    uri = uri.strip()
    if not uri:
        return None

    try:
        if uri.startswith("ss://"):
            return _parse_ss_uri(uri, source_url)
        elif uri.startswith("vmess://"):
            return _parse_vmess_uri(uri, source_url)
        elif uri.startswith("vless://"):
            return _parse_vless_uri(uri, source_url)
        elif uri.startswith("trojan://"):
            return _parse_trojan_uri(uri, source_url)
    except Exception as e:
        logger.debug(f"Failed to parse URI {uri[:30]}...: {e}")
        return None

    return None


def _parse_ss_uri(uri: str, source_url: str) -> Optional[Dict[str, Any]]:
    """
    Parse Shadowsocks URI.
    Supports SIP002: ss://base64(method:password)@server:port/?plugin=...#name
    And Legacy: ss://base64(method:password@server:port)#name
    """
    raw = uri[5:]
    name = "Shadowsocks Node"
    if "#" in raw:
        raw, fragment = raw.split("#", 1)
        name = urllib.parse.unquote(fragment).strip() or name

    plugin = ""
    plugin_opts: Dict[str, Any] = {}

    # Check for SIP002 format (contains '@')
    if "@" in raw:
        user_info_b64, server_part = raw.split("@", 1)
        decoded_user = _b64_decode_flexible(user_info_b64)
        if not decoded_user or ":" not in decoded_user:
            return None
        cipher, password = decoded_user.split(":", 1)

        # server_part could have query params like /?plugin=...
        query_str = ""
        if "/" in server_part:
            server_part, rest = server_part.split("/", 1)
            if "?" in rest:
                query_str = rest.split("?", 1)[1]
        elif "?" in server_part:
            server_part, query_str = server_part.split("?", 1)

        if query_str:
            q_params = urllib.parse.parse_qs(query_str)
            if "plugin" in q_params:
                plugin_raw = urllib.parse.unquote(q_params["plugin"][0])
                parts = plugin_raw.split(";")
                plugin = parts[0].strip()
                for part in parts[1:]:
                    part = part.strip()
                    if not part:
                        continue
                    if "=" in part:
                        k, v = part.split("=", 1)
                        k, v = k.strip(), v.strip()
                        if v.lower() == "true":
                            plugin_opts[k] = True
                        elif v.lower() == "false":
                            plugin_opts[k] = False
                        else:
                            plugin_opts[k] = v
                    else:
                        plugin_opts[part] = True

        if ":" not in server_part:
            return None
        server, port_str = server_part.split(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            return None

        extra = {}
        if plugin:
            extra["plugin"] = plugin
            extra["plugin_opts"] = plugin_opts

        raw_node = {
            "name": name,
            "type": "ss",
            "server": server,
            "port": port,
            "credentials": {"cipher": cipher, "password": password},
            "transport": {"network": "tcp"},
            "tls": {"enabled": False},
            "udp": True,
            "extra": extra,
        }
        return normalize_node(raw_node, source_url)
    else:
        # Legacy format: ss://base64(method:password@server:port)
        decoded = _b64_decode_flexible(raw)
        if not decoded or "@" not in decoded:
            return None
        user_info, server_part = decoded.split("@", 1)
        if ":" not in user_info or ":" not in server_part:
            return None
        cipher, password = user_info.split(":", 1)
        server, port_str = server_part.split(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            return None

        raw_node = {
            "name": name,
            "type": "ss",
            "server": server,
            "port": port,
            "credentials": {"cipher": cipher, "password": password},
            "transport": {"network": "tcp"},
            "tls": {"enabled": False},
            "udp": True,
        }
        return normalize_node(raw_node, source_url)


def _parse_vmess_uri(uri: str, source_url: str) -> Optional[Dict[str, Any]]:
    """
    Parse VMess URI: vmess://base64(json_config)
    """
    raw_b64 = uri[8:].strip()
    decoded = _b64_decode_flexible(raw_b64)
    if not decoded:
        return None

    try:
        data = json.loads(decoded)
    except Exception:
        return None

    if not isinstance(data, dict):
        return None

    server = str(data.get("add", "")).strip()
    port_raw = data.get("port", 0)
    try:
        port = int(port_raw)
    except (ValueError, TypeError):
        return None

    name = str(data.get("ps", "")).strip() or "VMess Node"
    uuid_str = str(data.get("id", "")).strip()
    alter_id = int(data.get("aid", 0)) if str(data.get("aid", "")).isdigit() else 0
    cipher = str(data.get("scy", "auto")).strip() or "auto"

    network = str(data.get("net", "tcp")).strip().lower() or "tcp"
    path = urllib.parse.unquote(str(data.get("path", "")).strip())
    host = str(data.get("host", "")).strip()
    sni = str(data.get("sni", "")).strip() or host

    tls_str = str(data.get("tls", "")).strip().lower()
    tls_enabled = tls_str in ("tls", "1", "true")

    transport: Dict[str, Any] = {"network": network}
    if path:
        transport["path"] = path
    if host:
        transport["headers"] = {"Host": host}

    tls_config: Dict[str, Any] = {"enabled": tls_enabled}
    if sni:
        tls_config["sni"] = sni
    fp = str(data.get("fp", "")).strip() or str(data.get("client-fingerprint", "")).strip()
    if fp:
        tls_config["fingerprint"] = fp
    insecure = str(data.get("allowInsecure", "")).strip().lower() in ("1", "true") or str(data.get("insecure", "")).strip().lower() in ("1", "true")
    if insecure:
        tls_config["skip_cert_verify"] = True

    raw_node = {
        "name": name,
        "type": "vmess",
        "server": server,
        "port": port,
        "credentials": {
            "uuid": uuid_str,
            "alterId": alter_id,
            "cipher": cipher,
        },
        "transport": transport,
        "tls": tls_config,
        "udp": True,
    }
    return normalize_node(raw_node, source_url)


def _parse_vless_uri(uri: str, source_url: str) -> Optional[Dict[str, Any]]:
    """
    Parse VLESS URI: vless://uuid@server:port?query_params#name
    Supports VLESS Reality, TLS, gRPC, WebSocket per Clash Meta specifications.
    """
    parsed = urllib.parse.urlsplit(uri)
    if not parsed.hostname or not parsed.port:
        return None

    uuid_str = parsed.username or ""
    server = parsed.hostname
    port = parsed.port

    name = urllib.parse.unquote(parsed.fragment).strip() or "VLESS Node"
    params = urllib.parse.parse_qs(parsed.query)

    def get_first(k: str, default: str = "") -> str:
        return params.get(k, [default])[0]

    security = get_first("security", "none").lower()
    tls_enabled = security in ("tls", "reality")
    sni = get_first("sni") or get_first("peer") or server
    fingerprint = get_first("fp") or get_first("client-fingerprint") or "chrome"

    network = get_first("type", "tcp").lower()
    path = urllib.parse.unquote(get_first("path", ""))
    host = get_first("host", "")
    service_name = get_first("serviceName", "")
    flow = get_first("flow", "")

    transport: Dict[str, Any] = {"network": network}
    if network == "ws":
        if path:
            transport["path"] = path
        if host:
            transport["headers"] = {"Host": host}
    elif network == "grpc":
        if service_name:
            transport["serviceName"] = service_name

    tls_config: Dict[str, Any] = {
        "enabled": tls_enabled,
        "sni": sni,
    }
    if fingerprint:
        tls_config["fingerprint"] = fingerprint

    if security == "reality":
        pbk = get_first("pbk")
        sid = get_first("sid")
        spx = get_first("spx")
        tls_config["reality"] = {
            "public_key": pbk,
            "short_id": sid,
        }
        if spx:
            tls_config["reality"]["spider_x"] = spx

    insecure = get_first("allowInsecure").lower() in ("1", "true") or get_first("insecure").lower() in ("1", "true")
    if insecure:
        tls_config["skip_cert_verify"] = True

    raw_node = {
        "name": name,
        "type": "vless",
        "server": server,
        "port": port,
        "credentials": {"uuid": uuid_str},
        "transport": transport,
        "tls": tls_config,
        "udp": True,
        "extra": {"flow": flow} if flow else {},
    }
    return normalize_node(raw_node, source_url)


def _parse_trojan_uri(uri: str, source_url: str) -> Optional[Dict[str, Any]]:
    """
    Parse Trojan URI: trojan://password@server:port?query_params#name
    """
    parsed = urllib.parse.urlsplit(uri)
    if not parsed.hostname or not parsed.port:
        return None

    password = parsed.username or ""
    server = parsed.hostname
    port = parsed.port

    name = urllib.parse.unquote(parsed.fragment).strip() or "Trojan Node"
    params = urllib.parse.parse_qs(parsed.query)

    def get_first(k: str, default: str = "") -> str:
        return params.get(k, [default])[0]

    sni = get_first("sni") or get_first("peer") or server
    network = get_first("type", "tcp").lower()
    path = urllib.parse.unquote(get_first("path", ""))
    host = get_first("host", "")
    service_name = get_first("serviceName", "")

    transport: Dict[str, Any] = {"network": network}
    if network == "ws":
        if path:
            transport["path"] = path
        if host:
            transport["headers"] = {"Host": host}
    elif network == "grpc":
        if service_name:
            transport["serviceName"] = service_name

    tls_config: Dict[str, Any] = {"enabled": True, "sni": sni}
    fp = get_first("fp") or get_first("client-fingerprint")
    if fp:
        tls_config["fingerprint"] = fp
    insecure = get_first("allowInsecure").lower() in ("1", "true") or get_first("insecure").lower() in ("1", "true")
    if insecure:
        tls_config["skip_cert_verify"] = True
    alpn_str = get_first("alpn")
    if alpn_str:
        tls_config["alpn"] = [x.strip() for x in alpn_str.split(",") if x.strip()]

    raw_node = {
        "name": name,
        "type": "trojan",
        "server": server,
        "port": port,
        "credentials": {"password": password},
        "transport": transport,
        "tls": tls_config,
        "udp": True,
    }
    return normalize_node(raw_node, source_url)


def normalize_node(
    raw_node: Dict[str, Any], source_url: str
) -> Optional[Dict[str, Any]]:
    """
    Standardize a node into the internal canonical representation:
    {
        "name": str,
        "type": str,
        "server": str,
        "port": int,
        "credentials": dict,
        "transport": dict,
        "tls": dict,
        "udp": bool,
        "sources": [source_url],
        "extra": dict
    }
    """
    node_type = str(raw_node.get("type", "")).strip().lower()
    if node_type not in ("ss", "vmess", "vless", "trojan"):
        return None

    server = str(raw_node.get("server", "")).strip()
    try:
        port = int(raw_node.get("port", 0))
    except (ValueError, TypeError):
        return None

    name = str(raw_node.get("name", "")).strip() or f"{node_type}-{server}:{port}"

    credentials = raw_node.get("credentials", {})
    if not isinstance(credentials, dict):
        credentials = {}

    transport = raw_node.get("transport", {})
    if not isinstance(transport, dict):
        transport = {"network": "tcp"}
    if "network" not in transport:
        transport["network"] = "tcp"

    tls = raw_node.get("tls", {})
    if not isinstance(tls, dict):
        tls = {"enabled": False}

    udp = bool(raw_node.get("udp", True))
    extra = raw_node.get("extra", {})

    node = {
        "name": name,
        "type": node_type,
        "server": server,
        "port": port,
        "credentials": credentials,
        "transport": transport,
        "tls": tls,
        "udp": udp,
        "sources": [source_url],
        "extra": extra if isinstance(extra, dict) else {},
    }
    return node


def validate_node(node: Dict[str, Any]) -> bool:
    """
    Perform fundamental sanity checks:
    - server must be a non-empty string and not obvious placeholder
    - port must be a valid integer between 1 and 65535
    - required protocol credentials must be present
    """
    if not isinstance(node, dict):
        return False

    server = node.get("server")
    if not server or not isinstance(server, str) or not server.strip():
        logger.debug(f"Invalid node: missing server ({node.get('name')})")
        return False

    server_clean = server.strip().lower()
    if server_clean in ("0.0.0.0", "localhost", "none", "null"):
        logger.debug(f"Invalid node: illegal server '{server}' ({node.get('name')})")
        return False

    port = node.get("port")
    if not isinstance(port, int) or port < 1 or port > 65535:
        logger.debug(f"Invalid node: port out of range {port} ({node.get('name')})")
        return False

    node_type = node.get("type")
    creds = node.get("credentials", {})

    if node_type == "ss":
        cipher = creds.get("cipher")
        password = creds.get("password")
        if not cipher or not password:
            logger.debug(f"SS node missing cipher or password: {node.get('name')}")
            return False
    elif node_type in ("vmess", "vless"):
        uuid_str = creds.get("uuid")
        if not uuid_str or not isinstance(uuid_str, str) or len(uuid_str.strip()) < 8:
            logger.debug(f"{node_type.upper()} node missing valid uuid: {node.get('name')}")
            return False
    elif node_type == "trojan":
        password = creds.get("password")
        if not password or not isinstance(password, str) or not password.strip():
            logger.debug(f"Trojan node missing password: {node.get('name')}")
            return False
    else:
        return False

    return True


def parse_clash(content: Any, source_url: str) -> List[Dict[str, Any]]:
    """
    Parse Clash configuration dictionary or proxy list.
    """
    nodes: List[Dict[str, Any]] = []
    proxies_raw: List[Any] = []

    if isinstance(content, dict):
        if "proxies" in content and isinstance(content["proxies"], list):
            proxies_raw = content["proxies"]
    elif isinstance(content, list):
        proxies_raw = content

    for p in proxies_raw:
        if not isinstance(p, dict):
            continue

        p_type = str(p.get("type", "")).lower()
        if p_type not in ("ss", "vmess", "vless", "trojan"):
            continue

        name = str(p.get("name", "")).strip()
        server = str(p.get("server", "")).strip()
        port = p.get("port", 0)

        credentials: Dict[str, Any] = {}
        transport: Dict[str, Any] = {"network": str(p.get("network", "tcp")).lower()}
        tls_config: Dict[str, Any] = {"enabled": bool(p.get("tls", False))}

        if p_type == "ss":
            credentials = {
                "cipher": p.get("cipher", ""),
                "password": p.get("password", ""),
            }
        elif p_type == "vmess":
            credentials = {
                "uuid": p.get("uuid", ""),
                "alterId": p.get("alterId", 0),
                "cipher": p.get("cipher", "auto"),
            }
            if p.get("servername"):
                tls_config["sni"] = p.get("servername")
        elif p_type == "vless":
            credentials = {"uuid": p.get("uuid", "")}
            if p.get("servername"):
                tls_config["sni"] = p.get("servername")
            if p.get("client-fingerprint"):
                tls_config["fingerprint"] = p.get("client-fingerprint")
            if "reality-opts" in p and isinstance(p["reality-opts"], dict):
                tls_config["reality"] = {
                    "public_key": p["reality-opts"].get("public-key", ""),
                    "short_id": p["reality-opts"].get("short-id", ""),
                }
        elif p_type == "trojan":
            credentials = {"password": p.get("password", "")}
            tls_config["enabled"] = True
            if p.get("sni"):
                tls_config["sni"] = p.get("sni")

        # Transport options
        if "ws-opts" in p and isinstance(p["ws-opts"], dict):
            if "path" in p["ws-opts"]:
                transport["path"] = p["ws-opts"]["path"]
            if "headers" in p["ws-opts"]:
                transport["headers"] = p["ws-opts"]["headers"]
        elif "grpc-opts" in p and isinstance(p["grpc-opts"], dict):
            if "grpc-service-name" in p["grpc-opts"]:
                transport["serviceName"] = p["grpc-opts"]["grpc-service-name"]

        raw_node = {
            "name": name,
            "type": p_type,
            "server": server,
            "port": port,
            "credentials": credentials,
            "transport": transport,
            "tls": tls_config,
            "udp": p.get("udp", True),
            "extra": {"flow": p.get("flow")} if p.get("flow") else {},
        }
        normalized = normalize_node(raw_node, source_url)
        if normalized and validate_node(normalized):
            nodes.append(normalized)

    return nodes


def parse_json(content: Any, source_url: str) -> List[Dict[str, Any]]:
    """
    Parse JSON data. Supports:
    - Dict with 'proxies' (Clash-like JSON)
    - Dict with 'outbounds' (V2Ray-like JSON)
    - List of proxy objects
    """
    if isinstance(content, dict):
        if "proxies" in content:
            return parse_clash(content, source_url)
        elif "outbounds" in content and isinstance(content["outbounds"], list):
            nodes: List[Dict[str, Any]] = []
            for ob in content["outbounds"]:
                if not isinstance(ob, dict):
                    continue
                protocol = ob.get("protocol", "").lower()
                settings = ob.get("settings", {})
                stream_settings = ob.get("streamSettings", {})
                tag = ob.get("tag", "V2Ray Node")

                if protocol == "vmess" and "vnext" in settings:
                    for vnext in settings.get("vnext", []):
                        address = vnext.get("address", "")
                        port = vnext.get("port", 0)
                        users = vnext.get("users", [{}])
                        user = users[0] if users else {}
                        raw_node = {
                            "name": tag,
                            "type": "vmess",
                            "server": address,
                            "port": port,
                            "credentials": {
                                "uuid": user.get("id", ""),
                                "alterId": user.get("alterId", 0),
                                "cipher": user.get("security", "auto"),
                            },
                            "transport": {
                                "network": stream_settings.get("network", "tcp")
                            },
                            "tls": {
                                "enabled": stream_settings.get("security") == "tls"
                            },
                            "udp": True,
                        }
                        norm = normalize_node(raw_node, source_url)
                        if norm and validate_node(norm):
                            nodes.append(norm)
            return nodes
    elif isinstance(content, list):
        return parse_clash(content, source_url)

    return []


def detect_format(content: str, is_inner: bool = False) -> str:
    """
    Determine the single primary format of the content.
    Returns one of: 'clash_yaml', 'json', 'uri_list', 'base64', 'unknown'.
    Prioritizes structural markers and scheme validation over simple parse attempts.
    """
    if not content or not content.strip():
        return "unknown"

    cleaned = content.strip()

    # 1. Clash YAML detection
    # Checks for structural YAML proxies block or list of proxy items
    if "proxies:" in cleaned or cleaned.startswith("- name:"):
        try:
            yaml_data = yaml.safe_load(cleaned)
            if isinstance(yaml_data, dict) and "proxies" in yaml_data and isinstance(yaml_data["proxies"], list):
                return "clash_yaml"
            elif isinstance(yaml_data, list) and any(
                isinstance(x, dict) and "server" in x and "type" in x for x in yaml_data
            ):
                return "clash_yaml"
        except Exception:
            pass

    # 2. JSON detection
    # Must have JSON object or array delimiters and parse valid JSON with proxy schema
    if (cleaned.startswith("{") and cleaned.endswith("}")) or (
        cleaned.startswith("[") and cleaned.endswith("]")
    ):
        try:
            json_data = json.loads(cleaned)
            if isinstance(json_data, dict) and ("proxies" in json_data or "outbounds" in json_data):
                return "json"
            elif isinstance(json_data, list) and any(
                isinstance(x, dict) and "server" in x and ("type" in x or "protocol" in x) for x in json_data
            ):
                return "json"
        except Exception:
            pass

    # 3. Plaintext URI list detection
    # Must have explicit URI schemes in non-empty, non-comment lines
    URI_SCHEMES = ("ss://", "vmess://", "vless://", "trojan://")
    lines = [l.strip() for l in cleaned.splitlines() if l.strip() and not l.strip().startswith("#")]
    if any(line.startswith(URI_SCHEMES) for line in lines):
        return "uri_list"

    # 4. Base64 encoded subscription detection (only for outer source content)
    if not is_inner:
        cleaned_b64 = "".join(cleaned.split())
        # Base64 feature check: valid charset, length >= 16, no plaintext scheme markers
        if re.match(r"^[A-Za-z0-9+/=_-]+$", cleaned_b64) and len(cleaned_b64) >= 16:
            decoded = _b64_decode_flexible(cleaned_b64)
            if decoded and decoded.strip():
                # Validate decoded content contains recognized node signatures or structure
                signatures = ("ss://", "vmess://", "vless://", "trojan://", "proxies:", '"proxies"', '"outbounds"')
                if any(sig in decoded for sig in signatures):
                    return "base64"

    return "unknown"


def detect_format(content: str, is_inner: bool = False) -> str:
    """
    Determine the single primary format of the content.
    Returns one of: 'clash_yaml', 'json', 'uri_list', 'base64', 'unknown'.
    Prioritizes structural markers and scheme validation over simple parse attempts.
    """
    if not content or not content.strip():
        return "unknown"

    cleaned = content.strip()

    # 1. Clash YAML detection
    # Checks for structural YAML proxies block or list of proxy items
    if "proxies:" in cleaned or cleaned.startswith("- name:"):
        try:
            yaml_data = yaml.safe_load(cleaned)
            if isinstance(yaml_data, dict) and "proxies" in yaml_data and isinstance(yaml_data["proxies"], list):
                return "clash_yaml"
            elif isinstance(yaml_data, list) and any(
                isinstance(x, dict) and "server" in x and "type" in x for x in yaml_data
            ):
                return "clash_yaml"
        except Exception:
            pass

    # 2. JSON detection
    # Must have JSON object or array delimiters and parse valid JSON with proxy schema
    if (cleaned.startswith("{") and cleaned.endswith("}")) or (
        cleaned.startswith("[") and cleaned.endswith("]")
    ):
        try:
            json_data = json.loads(cleaned)
            if isinstance(json_data, dict) and ("proxies" in json_data or "outbounds" in json_data):
                return "json"
            elif isinstance(json_data, list) and any(
                isinstance(x, dict) and "server" in x and ("type" in x or "protocol" in x) for x in json_data
            ):
                return "json"
        except Exception:
            pass

    # 3. Plaintext URI list detection
    # Must have explicit URI schemes in non-empty, non-comment lines
    URI_SCHEMES = ("ss://", "vmess://", "vless://", "trojan://")
    lines = [l.strip() for l in cleaned.splitlines() if l.strip() and not l.strip().startswith("#")]
    if any(line.startswith(URI_SCHEMES) for line in lines):
        return "uri_list"

    # 4. Base64 encoded subscription detection (only for outer source content)
    if not is_inner:
        cleaned_b64 = "".join(cleaned.split())
        # Base64 feature check: valid charset, length >= 16, no plaintext scheme markers
        if re.match(r"^[A-Za-z0-9+/=_-]+$", cleaned_b64) and len(cleaned_b64) >= 16:
            decoded = _b64_decode_flexible(cleaned_b64)
            if decoded and decoded.strip():
                # Validate decoded content contains recognized node signatures or structure
                signatures = ("ss://", "vmess://", "vless://", "trojan://", "proxies:", '"proxies"', '"outbounds"')
                if any(sig in decoded for sig in signatures):
                    return "base64"

    return "unknown"


def parse_base64(raw_content: str, source_url: str) -> List[Dict[str, Any]]:
    """
    Decode base64 subscription and parse the internal nodes quietly.
    Supports base64-encoded URI lists, Clash YAML, or JSON.
    Does not emit top-level source parsing logs (delegated to parse_source).
    """
    decoded = _b64_decode_flexible(raw_content)
    if not decoded:
        return []

    inner_fmt = detect_format(decoded, is_inner=True)
    if inner_fmt == "clash_yaml":
        try:
            yaml_data = yaml.safe_load(decoded)
            return parse_clash(yaml_data, source_url)
        except Exception:
            return []
    elif inner_fmt == "json":
        try:
            json_data = json.loads(decoded)
            return parse_json(json_data, source_url)
        except Exception:
            return []
    elif inner_fmt == "uri_list":
        nodes = []
        for line in decoded.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            node = parse_uri(line, source_url)
            if node and validate_node(node):
                nodes.append(node)
        return nodes

    return []


def parse_source(raw_content: str, source_url: str) -> List[Dict[str, Any]]:
    """
    Identify and parse the single primary format for the source:
    1. Clash YAML
    2. JSON
    3. URI list
    4. Base64 subscription
    """
    if not raw_content or not raw_content.strip():
        return []

    cleaned = raw_content.strip()
    fmt = detect_format(cleaned)

    if fmt == "clash_yaml":
        try:
            yaml_data = yaml.safe_load(cleaned)
            nodes = parse_clash(yaml_data, source_url)
            logger.info(f"Parsed {len(nodes)} nodes as Clash YAML from {source_url}")
            return nodes
        except Exception as e:
            logger.warning(f"Error parsing Clash YAML from {source_url}: {e}")
            return []

    elif fmt == "json":
        try:
            json_data = json.loads(cleaned)
            nodes = parse_json(json_data, source_url)
            logger.info(f"Parsed {len(nodes)} nodes as JSON from {source_url}")
            return nodes
        except Exception as e:
            logger.warning(f"Error parsing JSON from {source_url}: {e}")
            return []

    elif fmt == "uri_list":
        lines = [line.strip() for line in cleaned.splitlines() if line.strip()]
        nodes = []
        for line in lines:
            if line.startswith("#"):
                continue
            node = parse_uri(line, source_url)
            if node and validate_node(node):
                nodes.append(node)
        logger.info(f"Parsed {len(nodes)} nodes as URI list from {source_url}")
        return nodes

    elif fmt == "base64":
        nodes = parse_base64(cleaned, source_url)
        logger.info(f"Parsed {len(nodes)} nodes as Base64 subscription from {source_url}")
        return nodes

    else:
        logger.warning(f"Could not recognize node format for source: {source_url}")
        return []



def generate_fingerprint(node: Dict[str, Any]) -> str:
    """
    Generate a deterministic SHA-256 fingerprint for node deduplication.
    Considers: protocol, server, port, credentials, transport, tls.
    """
    creds = node.get("credentials", {})
    cred_repr = {}
    node_type = node.get("type", "").lower()

    if node_type == "ss":
        cred_repr = {
            "cipher": creds.get("cipher", ""),
            "password": creds.get("password", ""),
        }
    elif node_type == "vmess":
        cred_repr = {
            "uuid": str(creds.get("uuid", "")).lower(),
            "alterId": int(creds.get("alterId", 0)),
            "cipher": str(creds.get("cipher", "auto")).lower(),
        }
    elif node_type == "vless":
        cred_repr = {
            "uuid": str(creds.get("uuid", "")).lower(),
            "flow": str(node.get("extra", {}).get("flow", "")).lower(),
        }
    elif node_type == "trojan":
        cred_repr = {"password": creds.get("password", "")}

    transport = node.get("transport", {})
    tls = node.get("tls", {})

    fp_dict = {
        "protocol": node_type,
        "server": str(node.get("server", "")).lower().strip().rstrip("."),
        "port": int(node.get("port", 0)),
        "credentials": cred_repr,
        "transport": {
            "network": str(transport.get("network", "tcp")).lower(),
            "path": transport.get("path", ""),
            "host": str(transport.get("headers", {}).get("Host", "")).lower(),
            "serviceName": transport.get("serviceName", ""),
        },
        "tls": {
            "enabled": bool(tls.get("enabled", False)),
            "sni": str(tls.get("sni", "")).lower(),
            "fingerprint": str(tls.get("fingerprint", "")).lower(),
            "skip_cert_verify": bool(tls.get("skip_cert_verify", False)),
            "reality_public_key": str(tls.get("reality", {}).get("public_key", "")),
            "reality_short_id": str(tls.get("reality", {}).get("short_id", "")).lower(),
            "reality_spider_x": str(tls.get("reality", {}).get("spider_x", "")),
        },
    }

    serialized = json.dumps(fp_dict, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def deduplicate_nodes(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicate nodes based on deterministic fingerprint.
    When duplicates occur, keep the first occurrence and record all sources.
    """
    dedup_map: Dict[str, Dict[str, Any]] = {}

    for node in nodes:
        fp = generate_fingerprint(node)
        if fp in dedup_map:
            existing = dedup_map[fp]
            for s in node.get("sources", []):
                if s not in existing["sources"]:
                    existing["sources"].append(s)
        else:
            node_copy = copy.deepcopy(node)
            if "sources" not in node_copy:
                node_copy["sources"] = []
            dedup_map[fp] = node_copy

    unique_nodes = list(dedup_map.values())
    logger.info(
        f"Deduplication completed: {len(nodes)} total nodes -> {len(unique_nodes)} unique nodes"
    )
    return unique_nodes


def generate_clash_yaml(
    nodes: List[Dict[str, Any]], output_path: str = "output/sub.yaml"
) -> None:
    """
    Convert normalized nodes into Clash / Clash Meta (Mihomo) YAML configuration.
    Resolves duplicate names by appending suffixes (-01, -02, etc.).
    Preserves source attribution in header comments and writes output/attribution.json.
    """
    clash_proxies: List[Dict[str, Any]] = []
    attribution_map: Dict[str, Dict[str, Any]] = {}
    name_counts: Dict[str, int] = {}

    for node in nodes:
        raw_name = node.get("name", "Proxy")
        if raw_name not in name_counts:
            name_counts[raw_name] = 0
            final_name = raw_name
        else:
            name_counts[raw_name] += 1
            suffix = f"-{name_counts[raw_name]:02d}"
            final_name = f"{raw_name}{suffix}"

        node_type = node["type"]
        p: Dict[str, Any] = {
            "name": final_name,
            "type": node_type,
            "server": node["server"],
            "port": node["port"],
            "udp": node.get("udp", True),
        }

        creds = node.get("credentials", {})
        transport = node.get("transport", {})
        tls = node.get("tls", {})

        if node_type == "ss":
            p["cipher"] = creds.get("cipher", "")
            p["password"] = creds.get("password", "")
            if node.get("extra", {}).get("plugin"):
                p["plugin"] = node["extra"]["plugin"]
                if node["extra"].get("plugin_opts"):
                    p["plugin-opts"] = node["extra"]["plugin_opts"]

        elif node_type == "vmess":
            p["uuid"] = creds.get("uuid", "")
            p["alterId"] = creds.get("alterId", 0)
            p["cipher"] = creds.get("cipher", "auto")
            if tls.get("enabled"):
                p["tls"] = True
                if tls.get("sni"):
                    p["servername"] = tls["sni"]
                if tls.get("fingerprint"):
                    p["client-fingerprint"] = tls["fingerprint"]
                if tls.get("skip_cert_verify"):
                    p["skip-cert-verify"] = True

        elif node_type == "vless":
            p["uuid"] = creds.get("uuid", "")
            if tls.get("enabled"):
                p["tls"] = True
                if tls.get("sni"):
                    p["servername"] = tls["sni"]
                if tls.get("fingerprint"):
                    p["client-fingerprint"] = tls["fingerprint"]
                if tls.get("skip_cert_verify"):
                    p["skip-cert-verify"] = True
                if tls.get("fingerprint"):
                    p["client-fingerprint"] = tls["fingerprint"]
                if tls.get("skip_cert_verify"):
                    p["skip-cert-verify"] = True
                if "reality" in tls and tls["reality"].get("public_key"):
                    reality_opts = {
                        "public-key": tls["reality"]["public_key"],
                        "short-id": tls["reality"].get("short_id", ""),
                    }
                    if tls["reality"].get("spider_x"):
                        reality_opts["spider-x"] = tls["reality"]["spider_x"]
                    p["reality-opts"] = reality_opts
            if node.get("extra", {}).get("flow"):
                p["flow"] = node["extra"]["flow"]

        elif node_type == "trojan":
            p["password"] = creds.get("password", "")
            p["sni"] = tls.get("sni", node["server"])
            if tls.get("fingerprint"):
                p["client-fingerprint"] = tls["fingerprint"]
            if tls.get("skip_cert_verify"):
                p["skip-cert-verify"] = True
            if tls.get("alpn"):
                p["alpn"] = tls["alpn"]

        # Transport configuration
        network = transport.get("network", "tcp")
        if network and network != "tcp":
            p["network"] = network
            if network == "ws":
                ws_opts: Dict[str, Any] = {}
                if "path" in transport:
                    ws_opts["path"] = transport["path"]
                if "headers" in transport:
                    ws_opts["headers"] = transport["headers"]
                if ws_opts:
                    p["ws-opts"] = ws_opts
            elif network == "grpc":
                if "serviceName" in transport:
                    p["grpc-opts"] = {
                        "grpc-service-name": transport["serviceName"]
                    }

        clash_proxies.append(p)

        # Record attribution
        attribution_map[final_name] = {
            "type": node_type,
            "server": node["server"],
            "port": node["port"],
            "sources": node.get("sources", []),
            "fingerprint": generate_fingerprint(node),
        }

    proxy_names = [p["name"] for p in clash_proxies]
    if not proxy_names:
        proxy_names = ["DIRECT"]

    # Build Clash configuration structure
    clash_config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "proxies": clash_proxies,
        "proxy-groups": [
            {
                "name": "PROXY",
                "type": "select",
                "proxies": ["AUTO"] + proxy_names,
            },
            {
                "name": "AUTO",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": proxy_names,
            },
            {
                "name": "FALLBACK",
                "type": "fallback",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "proxies": proxy_names,
            },
        ],
        "rules": [
            "GEOIP,LAN,DIRECT",
            "GEOIP,CN,DIRECT",
            "MATCH,PROXY",
        ],
    }

    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    header_lines = [
        "# ==============================================================================",
        "# Public Authorized Node Subscriptions (Clash / Clash Meta Configuration)",
        "# Generated automatically by aggregator.py",
        f"# Updated: {now_iso}",
        f"# Total Unique Proxies: {len(clash_proxies)}",
        "# ==============================================================================",
        "# Node Source Attribution (节点来源追踪):",
    ]
    for p_name, attr in attribution_map.items():
        src_str = ", ".join(attr.get("sources", [])) or "unknown"
        header_lines.append(f"# - {p_name} ({attr['type']}://{attr['server']}:{attr['port']}) -> [{src_str}]")
    header_lines.append("# ==============================================================================")
    header_lines.append("")

    yaml_body = yaml.dump(
        clash_config,
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
    )

    full_yaml_content = chr(10).join(header_lines) + chr(10) + yaml_body

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(full_yaml_content)

    attribution_file = os.path.join(out_dir or ".", "attribution.json")
    with open(attribution_file, "w", encoding="utf-8") as f:
        json.dump(attribution_map, f, indent=2, ensure_ascii=False)

    logger.info(
        f"Generated Clash YAML successfully: {output_path} with {len(clash_proxies)} proxies."
    )
    logger.info(f"Saved source attribution map to: {attribution_file}")


def run_aggregator(
    sources_path: str = "sources.txt", output_path: str = "output/sub.yaml"
) -> int:
    """
    Main execution pipeline for node aggregation.
    """
    logger.info("Starting Public Authorized Node Aggregation pipeline...")

    # 1. Load source URLs
    source_urls = load_sources(sources_path)
    if not source_urls:
        logger.warning(f"No valid sources found in {sources_path}.")

    # 2. Download contents
    contents = download_sources(source_urls)

    # 3. Parse all sources
    all_nodes: List[Dict[str, Any]] = []
    for source_url, raw_text in contents.items():
        if raw_text is None:
            continue
        try:
            nodes = parse_source(raw_text, source_url)
            all_nodes.extend(nodes)
        except Exception as e:
            logger.error(f"Error parsing source {source_url}: {e}", exc_info=True)

    logger.info(f"Total valid nodes parsed from all sources: {len(all_nodes)}")

    # 4. Deduplicate nodes
    unique_nodes = deduplicate_nodes(all_nodes)

    # 5. Generate Clash YAML output and attribution
    generate_clash_yaml(unique_nodes, output_path)

    logger.info("Pipeline execution completed successfully.")
    return 0


if __name__ == "__main__":
    sources_file = sys.argv[1] if len(sys.argv) > 1 else "sources.txt"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "output/sub.yaml"
    sys.exit(run_aggregator(sources_file, output_file))
