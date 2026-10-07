#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import yaml

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from aggregator import (
    load_sources,
    detect_format,
    download_sources,
    detect_format,
    parse_uri,
    parse_clash,
    parse_json,
    parse_base64,
    parse_source,
    normalize_node,
    validate_node,
    generate_fingerprint,
    deduplicate_nodes,
    generate_clash_yaml,
)


class TestNodeAggregatorPhase2(unittest.TestCase):

    def setUp(self):
        self.sample_uuid = 'a3b2c1d0-1234-5678-9abc-def012345678'
        self.sample_source = 'https://example.com/sub.txt'

    def test_load_sources(self):
        with tempfile.NamedTemporaryFile('w+', delete=False) as f:
            f.write('# Comment\n\nhttps://example.com/s1.yaml\n  # another comment\nhttps://example.com/s2.txt\n\n')
            temp_name = f.name

        try:
            sources = load_sources(temp_name)
            self.assertEqual(len(sources), 2)
            self.assertEqual(sources[0], 'https://example.com/s1.yaml')
            self.assertEqual(sources[1], 'https://example.com/s2.txt')
        finally:
            if os.path.exists(temp_name):
                os.remove(temp_name)

    def test_parse_ss_sip002_with_plugin(self):
        user_info = base64.urlsafe_b64encode(b'aes-256-gcm:mypassword123').decode()
        uri = f'ss://{user_info}@ss.example.com:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com#Tokyo-SS'
        node = parse_uri(uri, self.sample_source)
        self.assertIsNotNone(node)
        self.assertEqual(node['name'], 'Tokyo-SS')
        self.assertEqual(node['type'], 'ss')
        self.assertEqual(node['server'], 'ss.example.com')
        self.assertEqual(node['port'], 8388)
        self.assertEqual(node['credentials']['cipher'], 'aes-256-gcm')
        self.assertEqual(node['credentials']['password'], 'mypassword123')
        self.assertEqual(node['extra']['plugin'], 'obfs-local')
        self.assertEqual(node['extra']['plugin_opts']['obfs'], 'http')
        self.assertTrue(validate_node(node))

    def test_parse_ss_legacy(self):
        raw_b64 = base64.b64encode(b'chacha20-ietf-poly1305:mypass@ss-legacy.example.com:8389').decode()
        uri = f'ss://{raw_b64}#Legacy-SS'
        node = parse_uri(uri, self.sample_source)
        self.assertIsNotNone(node)
        self.assertEqual(node['name'], 'Legacy-SS')
        self.assertEqual(node['type'], 'ss')
        self.assertEqual(node['server'], 'ss-legacy.example.com')
        self.assertEqual(node['port'], 8389)
        self.assertEqual(node['credentials']['cipher'], 'chacha20-ietf-poly1305')
        self.assertEqual(node['credentials']['password'], 'mypass')
        self.assertTrue(validate_node(node))

    def test_parse_vmess_uri(self):
        vmess_json = {
            'v': '2',
            'ps': 'HongKong-VMess',
            'add': 'vmess.example.com',
            'port': 443,
            'id': self.sample_uuid,
            'aid': 0,
            'scy': 'auto',
            'net': 'ws',
            'type': 'none',
            'host': 'vmess.example.com',
            'path': '/ws?ed=2048',
            'tls': 'tls',
            'sni': 'vmess.example.com'
        }
        b64_str = base64.b64encode(json.dumps(vmess_json).encode()).decode()
        uri = f'vmess://{b64_str}'
        node = parse_uri(uri, self.sample_source)
        self.assertIsNotNone(node)
        self.assertEqual(node['name'], 'HongKong-VMess')
        self.assertEqual(node['type'], 'vmess')
        self.assertEqual(node['server'], 'vmess.example.com')
        self.assertEqual(node['port'], 443)
        self.assertEqual(node['credentials']['uuid'], self.sample_uuid)
        self.assertEqual(node['transport']['network'], 'ws')
        self.assertEqual(node['transport']['path'], '/ws?ed=2048')
        self.assertTrue(node['tls']['enabled'])
        self.assertTrue(validate_node(node))

    def test_parse_vless_reality_and_clash_meta_compatibility(self):
        uri = (
            f'vless://{self.sample_uuid}@vless.example.com:443'
            '?encryption=none&security=reality&sni=vless.example.com'
            '&fp=chrome&pbk=fakekey123&sid=1234&type=grpc&serviceName=vless-grpc&flow=xtls-rprx-vision#US-VLESS-Reality'
        )
        node = parse_uri(uri, self.sample_source)
        self.assertIsNotNone(node)
        self.assertEqual(node['name'], 'US-VLESS-Reality')
        self.assertEqual(node['type'], 'vless')
        self.assertEqual(node['server'], 'vless.example.com')
        self.assertEqual(node['port'], 443)
        self.assertEqual(node['credentials']['uuid'], self.sample_uuid)
        self.assertEqual(node['transport']['network'], 'grpc')
        self.assertEqual(node['transport']['serviceName'], 'vless-grpc')
        self.assertTrue(node['tls']['enabled'])
        self.assertEqual(node['tls']['reality']['public_key'], 'fakekey123')
        self.assertEqual(node['tls']['reality']['short_id'], '1234')
        self.assertEqual(node['extra']['flow'], 'xtls-rprx-vision')
        self.assertTrue(validate_node(node))

        with tempfile.NamedTemporaryFile('w+', delete=False, suffix='.yaml') as f:
            temp_yaml = f.name

        try:
            generate_clash_yaml([node], temp_yaml)
            with open(temp_yaml, 'r', encoding='utf-8') as f:
                clash_doc = yaml.safe_load(f)

            p = clash_doc['proxies'][0]
            self.assertEqual(p['type'], 'vless')
            self.assertEqual(p['server'], 'vless.example.com')
            self.assertEqual(p['port'], 443)
            self.assertEqual(p['uuid'], self.sample_uuid)
            self.assertTrue(p['tls'])
            self.assertEqual(p['servername'], 'vless.example.com')
            self.assertEqual(p['client-fingerprint'], 'chrome')
            self.assertEqual(p['flow'], 'xtls-rprx-vision')
            self.assertIn('reality-opts', p)
            self.assertEqual(p['reality-opts']['public-key'], 'fakekey123')
            self.assertEqual(p['reality-opts']['short-id'], '1234')
            self.assertEqual(p['network'], 'grpc')
            self.assertEqual(p['grpc-opts']['grpc-service-name'], 'vless-grpc')
        finally:
            if os.path.exists(temp_yaml):
                os.remove(temp_yaml)

    def test_parse_trojan_uri(self):
        uri = 'trojan://trojanpass123@trojan.example.com:443?security=tls&sni=trojan.example.com&type=ws&path=%2Ftrojan#SG-Trojan'
        node = parse_uri(uri, self.sample_source)
        self.assertIsNotNone(node)
        self.assertEqual(node['name'], 'SG-Trojan')
        self.assertEqual(node['type'], 'trojan')
        self.assertEqual(node['server'], 'trojan.example.com')
        self.assertEqual(node['port'], 443)
        self.assertEqual(node['credentials']['password'], 'trojanpass123')
        self.assertEqual(node['transport']['network'], 'ws')
        self.assertEqual(node['transport']['path'], '/trojan')
        self.assertTrue(node['tls']['enabled'])
        self.assertTrue(validate_node(node))

    def test_validate_node_failures(self):
        bad1 = {'name': 'bad1', 'type': 'ss', 'port': 443, 'credentials': {'cipher': 'c', 'password': 'p'}}
        self.assertFalse(validate_node(bad1))

        bad2 = {'name': 'bad2', 'type': 'ss', 'server': '1.1.1.1', 'port': 70000, 'credentials': {'cipher': 'c', 'password': 'p'}}
        self.assertFalse(validate_node(bad2))

        bad3 = {'name': 'bad3', 'type': 'ss', 'server': '0.0.0.0', 'port': 443, 'credentials': {'cipher': 'c', 'password': 'p'}}
        self.assertFalse(validate_node(bad3))

        bad4 = {'name': 'bad4', 'type': 'trojan', 'server': '1.1.1.1', 'port': 443, 'credentials': {}}
        self.assertFalse(validate_node(bad4))

        bad5 = {'name': 'bad5', 'type': 'vmess', 'server': '1.1.1.1', 'port': 443, 'credentials': {}}
        self.assertFalse(validate_node(bad5))

    def test_false_positive_rejection(self):
        # 1. Plain text with colons (YAML-like string but not Clash)
        res_plain = parse_source('status: 200 OK\nmessage: all good', 'plain.txt')
        self.assertEqual(res_plain, [])

        # 2. Arbitrary Base64 text without any node markers
        random_b64 = base64.b64encode(b'This is just some random text without any proxy config').decode()
        res_b64 = parse_source(random_b64, 'random.b64')
        self.assertEqual(res_b64, [])

        # 3. JSON array of simple strings
        res_json = parse_source('["apple", "banana", "orange"]', 'fruits.json')
        self.assertEqual(res_json, [])

        # 4. JSON object with unrelated fields
        res_obj = parse_source('{"status": "ok", "count": 10}', 'status.json')
        self.assertEqual(res_obj, [])

    def test_deduplicate_nodes_and_track_sources(self):
        node_src1 = {
            'name': 'Node A',
            'type': 'ss',
            'server': 'example.com',
            'port': 8388,
            'credentials': {'cipher': 'aes-256-gcm', 'password': 'p1'},
            'transport': {'network': 'tcp'},
            'tls': {'enabled': False},
            'sources': ['source1.txt'],
        }
        node_src2 = {
            'name': 'Node A (Alias)',
            'type': 'ss',
            'server': 'example.com',
            'port': 8388,
            'credentials': {'cipher': 'aes-256-gcm', 'password': 'p1'},
            'transport': {'network': 'tcp'},
            'tls': {'enabled': False},
            'sources': ['source2.txt'],
        }
        node_diff = {
            'name': 'Node B',
            'type': 'ss',
            'server': 'example.com',
            'port': 8389,
            'credentials': {'cipher': 'aes-256-gcm', 'password': 'p1'},
            'transport': {'network': 'tcp'},
            'tls': {'enabled': False},
            'sources': ['source1.txt'],
        }

        unique = deduplicate_nodes([node_src1, node_src2, node_diff])
        self.assertEqual(len(unique), 2)
        node_a = next(n for n in unique if n['port'] == 8388)
        self.assertIn('source1.txt', node_a['sources'])
        self.assertIn('source2.txt', node_a['sources'])

    def test_source_attribution_output(self):
        nodes = [
            {
                'name': 'JP-Node',
                'type': 'trojan',
                'server': 'jp.example.com',
                'port': 443,
                'credentials': {'password': 'pass1'},
                'transport': {'network': 'tcp'},
                'tls': {'enabled': True},
                'sources': ['source_a.yaml', 'source_b.txt'],
            }
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, 'sub.yaml')
            generate_clash_yaml(nodes, out_file)

            with open(out_file, 'r', encoding='utf-8') as f:
                content = f.read()

            self.assertIn('# Node Source Attribution', content)
            self.assertIn('source_a.yaml', content)
            self.assertIn('source_b.txt', content)

            attr_file = os.path.join(tmpdir, 'attribution.json')
            self.assertTrue(os.path.exists(attr_file))
            with open(attr_file, 'r', encoding='utf-8') as f:
                attr_data = json.load(f)

            self.assertIn('JP-Node', attr_data)
            self.assertEqual(attr_data['JP-Node']['sources'], ['source_a.yaml', 'source_b.txt'])

    @patch('requests.get')
    def test_download_sources_size_limit(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {'Content-Length': '2000'}
        mock_resp.__enter__.return_value = mock_resp

        mock_get.return_value = mock_resp

        res = download_sources(['https://example.com/oversized.txt'], max_size_bytes=1000)
        self.assertIsNone(res['https://example.com/oversized.txt'])

    @patch('requests.get')
    def test_download_sources_handles_failure(self, mock_get):
        mock_resp_success = MagicMock()
        mock_resp_success.status_code = 200
        mock_resp_success.headers = {}
        mock_resp_success.iter_content.return_value = [b'trojan://pass@t.example.com:443#T1']
        mock_resp_success.__enter__.return_value = mock_resp_success

        mock_resp_404 = MagicMock()
        mock_resp_404.status_code = 404
        mock_resp_404.headers = {}
        mock_resp_404.__enter__.return_value = mock_resp_404

        def side_effect(url, **kwargs):
            if 'success' in url:
                return mock_resp_success
            elif 'error' in url:
                import requests
                raise requests.RequestException('Connection timed out')
            else:
                return mock_resp_404

        mock_get.side_effect = side_effect

        sources = [
            'https://example.com/success.txt',
            'https://example.com/error.txt',
            'https://example.com/404.txt',
        ]
        results = download_sources(sources)
        self.assertIsNotNone(results['https://example.com/success.txt'])
        self.assertIsNone(results['https://example.com/error.txt'])
        self.assertIsNone(results['https://example.com/404.txt'])



    def test_detect_format_accuracy(self):
        clash_text = "proxies:\n  - name: test\n    type: ss\n    server: s.com\n    port: 443\n    cipher: c\n    password: p"
        json_text = '{"proxies": [{"name": "t", "type": "ss", "server": "s.com", "port": 443}]}'
        uri_text = "trojan://pass@trojan.com:443#TrojanNode\nss://YWVzLTI1Ni1nY206cGFzc0AxLjEuMS4xOjQ0Mw==#SS"
        
        # Base64 encoded URI list
        raw_uris = "trojan://pass@t.com:443#T\nvmess://eyJ2IjoiMiIsImFkZCI6InYubmV0IiwicG9ydCI6NDQzLCJpZCI6IjExMTExMTExLTIyMjItMzMzMy00NDQ0LTU1NTU1NTU1NTU1NSIsInBzIjoiViJ9"
        b64_text = base64.b64encode(raw_uris.encode()).decode()

        self.assertEqual(detect_format(clash_text), "clash_yaml")
        self.assertEqual(detect_format(json_text), "json")
        self.assertEqual(detect_format(uri_text), "uri_list")
        self.assertEqual(detect_format(b64_text), "base64")
        self.assertEqual(detect_format("random text not proxy"), "unknown")

    def test_base64_not_misidentified_as_uri_list(self):
        raw_uris = "trojan://pass@t.com:443#T\nvmess://eyJ2IjoiMiIsImFkZCI6InYubmV0IiwicG9ydCI6NDQzLCJpZCI6IjExMTExMTExLTIyMjItMzMzMy00NDQ0LTU1NTU1NTU1NTU1NSIsInBzIjoiViJ9"
        b64_text = base64.b64encode(raw_uris.encode()).decode()

        # Primary format must be base64, never uri_list
        self.assertEqual(detect_format(b64_text), "base64")

        # When parsed through parse_source, verify logs: must only log Base64 subscription
        with self.assertLogs("aggregator", level="INFO") as cm:
            nodes = parse_source(b64_text, "source_b64.txt")
            self.assertEqual(len(nodes), 2)
            log_messages = cm.output
            # Should have Base64 log
            self.assertTrue(any("as Base64 subscription" in msg for msg in log_messages))
            # Should NOT have URI list log for this source
            self.assertFalse(any("as URI list" in msg for msg in log_messages))

    def test_json_outbounds_and_proxies_parsing(self):
        json_clash = '{"proxies": [{"name": "J1", "type": "trojan", "server": "j1.com", "port": 443, "password": "p"}]}'
        nodes_clash = parse_source(json_clash, "clash.json")
        self.assertEqual(len(nodes_clash), 1)
        self.assertEqual(nodes_clash[0]["name"], "J1")

        json_v2ray = """{
            "outbounds": [{
                "protocol": "vmess",
                "tag": "V2Node",
                "settings": {
                    "vnext": [{"address": "v2.com", "port": 443, "users": [{"id": "11111111-2222-3333-4444-555555555555"}]}]
                }
            }]
        }"""
        nodes_v2 = parse_source(json_v2ray, "v2ray.json")
        self.assertEqual(len(nodes_v2), 1)
        self.assertEqual(nodes_v2[0]["name"], "V2Node")



    def test_generated_clash_yaml_is_valid_yaml(self):
        """
        Verify that generated Clash YAML is 100% valid YAML parseable by yaml.safe_load().
        Also verify that the header comment contains Chinese characters without corruption.
        """
        nodes = [
            {
                "name": "HK-VMess",
                "type": "vmess",
                "server": "hk.example.com",
                "port": 443,
                "credentials": {"uuid": self.sample_uuid, "alterId": 0, "cipher": "auto"},
                "transport": {"network": "ws", "path": "/ws", "headers": {"Host": "hk.example.com"}},
                "tls": {"enabled": True, "sni": "hk.example.com", "fingerprint": "chrome"},
                "sources": ["source1.yaml"],
            },
            {
                "name": "US-VLESS-Reality",
                "type": "vless",
                "server": "us.example.com",
                "port": 443,
                "credentials": {"uuid": self.sample_uuid},
                "transport": {"network": "grpc", "serviceName": "vless-grpc"},
                "tls": {
                    "enabled": True,
                    "sni": "us.example.com",
                    "fingerprint": "chrome",
                    "reality": {"public_key": "fakekey123", "short_id": "1234", "spider_x": "/spider"},
                    "skip_cert_verify": True,
                },
                "extra": {"flow": "xtls-rprx-vision"},
                "sources": ["source2.txt"],
            },
            {
                "name": "SG-Trojan",
                "type": "trojan",
                "server": "sg.example.com",
                "port": 443,
                "credentials": {"password": "samplepass"},
                "transport": {"network": "ws", "path": "/trojan"},
                "tls": {"enabled": True, "sni": "sg.example.com", "alpn": ["h2", "http/1.1"]},
                "sources": ["source3.txt"],
            },
            {
                "name": "JP-SS",
                "type": "ss",
                "server": "jp.example.com",
                "port": 8388,
                "credentials": {"cipher": "aes-256-gcm", "password": "sspass"},
                "transport": {"network": "tcp"},
                "tls": {"enabled": False},
                "extra": {"plugin": "v2ray-plugin", "plugin_opts": {"tls": True, "mode": "websocket"}},
                "sources": ["source1.yaml", "source2.txt"],
            },
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            out_yaml = os.path.join(tmpdir, "test_sub.yaml")
            generate_clash_yaml(nodes, out_yaml)

            # 1. Read raw text to inspect header
            with open(out_yaml, "r", encoding="utf-8") as f:
                raw_text = f.read()

            self.assertIn("# Node Source Attribution (节点来源追踪):", raw_text)
            self.assertIn("# - HK-VMess", raw_text)
            self.assertIn("# - US-VLESS-Reality", raw_text)

            # 2. Parse with yaml.safe_load - must succeed without error
            doc = yaml.safe_load(raw_text)
            self.assertIsInstance(doc, dict)
            self.assertIn("proxies", doc)
            self.assertEqual(len(doc["proxies"]), 4)
            self.assertIn("proxy-groups", doc)
            self.assertIn("rules", doc)

            # 3. Check VLESS Reality opts in parsed doc
            vless_proxy = next(p for p in doc["proxies"] if p["type"] == "vless")
            self.assertEqual(vless_proxy["reality-opts"]["public-key"], "fakekey123")
            self.assertEqual(vless_proxy["reality-opts"]["short-id"], "1234")
            self.assertEqual(vless_proxy["reality-opts"]["spider-x"], "/spider")
            self.assertTrue(vless_proxy["skip-cert-verify"])
            self.assertEqual(vless_proxy["flow"], "xtls-rprx-vision")

            # 4. Check SS plugin opts in parsed doc
            ss_proxy = next(p for p in doc["proxies"] if p["type"] == "ss")
            self.assertEqual(ss_proxy["plugin"], "v2ray-plugin")
            self.assertEqual(ss_proxy["plugin-opts"]["tls"], True)

    def test_reality_short_id_differentiation(self):
        """
        Ensure two VLESS nodes with identical server, port, uuid, pbk
        but DIFFERENT short_id are NOT considered duplicates.
        """
        node1 = {
            "name": "VLESS-Node-1",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "credentials": {"uuid": self.sample_uuid},
            "transport": {"network": "tcp"},
            "tls": {
                "enabled": True,
                "sni": "example.com",
                "reality": {"public_key": "same_pbk", "short_id": "1111"},
            },
            "sources": ["src1"],
        }
        node2 = {
            "name": "VLESS-Node-2",
            "type": "vless",
            "server": "example.com",
            "port": 443,
            "credentials": {"uuid": self.sample_uuid},
            "transport": {"network": "tcp"},
            "tls": {
                "enabled": True,
                "sni": "example.com",
                "reality": {"public_key": "same_pbk", "short_id": "2222"},
            },
            "sources": ["src2"],
        }
        fp1 = generate_fingerprint(node1)
        fp2 = generate_fingerprint(node2)
        self.assertNotEqual(fp1, fp2)

        deduped = deduplicate_nodes([node1, node2])
        self.assertEqual(len(deduped), 2)


if __name__ == '__main__':
    unittest.main()
