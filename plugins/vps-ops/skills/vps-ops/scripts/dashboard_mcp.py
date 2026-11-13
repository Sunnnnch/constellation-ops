#!/usr/bin/env python3
"""Serve the Constellation Ops dashboard as a local MCP app over stdio."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sqlite3
import sys
from time import monotonic

from dashboard import Dashboard, MAX_TRANSFER_BODY, default_data_dir
from dashboard_credentials import CredentialError
from dashboard_mcp_ui import BRAND_ICON_DATA_URL, build_ui
from dashboard_native import KeyFilePicker


RESOURCE_URI = "ui://vps-ops/dashboard"
RESOURCE_MIME = "text/html;profile=mcp-app"
SERVER_INFO = {"name": "vps-ops", "version": "0.24.10"}
PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
CAPABILITIES = {"tools": {}, "resources": {}}
MAX_REQUEST = MAX_TRANSFER_BODY

RESOURCE = {
    "uri": RESOURCE_URI,
    "name": "星图",
    "description": "星图服务器管理面板。",
    "mimeType": RESOURCE_MIME,
}
RESOURCE_META = {"ui": {"csp": {"connectDomains": [], "resourceDomains": []}}}

ACTIONS = {
    "state": ((), ()),
    "metric_display": (("mode",), ()),
    "add": (("host",), ()),
    "update": (("id", "host"), ()),
    "remove": (("id",), ()),
    "refresh": ((), ("id",)),
    "demo": (("enabled",), ()),
    "ssh_test": (("host",), ()),
    "ssh_terminal": (("host",), ()),
    "key_file_start": ((), ()),
    "key_file_poll": (("ticket",), ()),
    "history": (("id",), ()),
    "inventory_export": ((), ()),
    "inventory_preview": (("inventory",), ()),
    "inventory_import": (("inventory",), ()),
    "terminal_open": (("payload",), ()),
    "terminal_exchange": (("payload",), ()),
    "terminal_close": (("payload",), ()),
    "network_probes": (("payload",), ()),
    "outbound_probes": (("payload",), ()),
    "files": (("payload",), ()),
    "webdav": (("payload",), ()),
    "komari": (("payload",), ()),
    "tunnels": (("payload",), ()),
}
TOOLS = [
    {
        "name": "open_vps_ops",
        "title": "星图",
        "description": "打开星图服务器管理面板。",
        "icons": [{"src": BRAND_ICON_DATA_URL, "mimeType": "image/png", "sizes": ["256x256"]}],
        "inputSchema": {"type": "object", "additionalProperties": False, "properties": {}},
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
        "_meta": {
            "ui": {"resourceUri": RESOURCE_URI},
            "openai/ui": {"entrypoints": [{"type": "global"}, {"type": "thread"}]},
        },
    },
    {
        "name": "vps_ops_ui_request",
        "description": "星图面板使用的本机设备和 SSH 连接接口。",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["action"],
            "properties": {
                "action": {"type": "string", "enum": list(ACTIONS)},
                "id": {"type": "string", "minLength": 1, "maxLength": 80},
                "host": {"type": "object"},
                "enabled": {"type": "boolean"},
                "ticket": {"type": "string", "minLength": 1, "maxLength": 64},
                "inventory": {"type": "object"},
                "payload": {"type": "object"},
                "mode": {"type": "string", "enum": ["gauges", "text"]},
            },
        },
        "_meta": {"ui": {"visibility": ["app"]}},
    },
]


class ProtocolError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def tool_error(message):
    return {
        "isError": True,
        "content": [{"type": "text", "text": message}],
        "structuredContent": {"error": message},
    }


class Server:
    def __init__(self, data_dir, interval, demo):
        self.data_dir = data_dir
        self.interval = interval
        self.demo = demo
        self.panel = None
        self.key_file_picker = KeyFilePicker()
        self.next_refresh = 0
        self.next_network_refresh = 0

    def dashboard_request(self, arguments):
        action = arguments.get("action")
        if not isinstance(action, str) or action not in ACTIONS:
            raise ValueError("操作不存在。")
        required, optional = ACTIONS[action]
        fields = arguments.keys() - {"action"}
        if not set(required) <= fields <= set(required + optional):
            raise ValueError("操作参数无效。")
        host_id = arguments.get("id")
        if "id" in fields and (not isinstance(host_id, str) or not 1 <= len(host_id) <= 80):
            raise ValueError("主机编号无效。")
        host = arguments.get("host")
        if "host" in fields and not isinstance(host, dict):
            raise ValueError("主机配置必须是 JSON 对象。")
        payload = arguments.get("payload")
        if "payload" in fields and not isinstance(payload, dict):
            raise ValueError("操作参数必须是 JSON 对象。")
        enabled = arguments.get("enabled")
        if "enabled" in fields and not isinstance(enabled, bool):
            raise ValueError("演示模式参数无效。")

        if action == "key_file_start":
            return self.key_file_picker.start()
        if action == "key_file_poll":
            ticket = arguments["ticket"]
            if not isinstance(ticket, str) or not 1 <= len(ticket) <= 64:
                raise ValueError("文件选择编号无效。")
            return self.key_file_picker.poll(ticket)
        if self.panel is None:
            self.panel = Dashboard(self.data_dir, self.interval, self.demo)
        panel = self.panel
        if action in ("webdav", "komari"):
            return panel.integration_request(action, payload)
        if action == "tunnels":
            return panel.tunnel_request(payload)
        if action == "metric_display":
            return panel.set_metric_display(arguments["mode"])
        if action in ("terminal_open", "terminal_exchange", "terminal_close"):
            return panel.terminal_request(action.removeprefix("terminal_"), payload)
        if action == "network_probes":
            return panel.probe_request(payload)
        if action == "outbound_probes":
            return panel.outbound_probe_request(payload)
        if action == "files":
            return panel.file_request(payload)
        if action == "ssh_test":
            return panel.test_ssh(host)
        if action == "ssh_terminal":
            return panel.open_ssh(host)
        if action == "history":
            return panel.host_history(host_id)
        if action.startswith("inventory_"):
            return panel.transfer_inventory(action.removeprefix("inventory_"), arguments.get("inventory"))
        if action in ("add", "update", "remove"):
            method = {"add": "POST", "update": "PUT", "remove": "DELETE"}[action]
            panel.change(method, host_id, host)
        elif action == "demo":
            panel.set_demo(enabled)
            self.next_refresh = 0
        elif action == "refresh":
            panel.refresh(host_id)
            if host_id is None:
                self.next_refresh = monotonic() + self.interval
        elif action == "state" and not panel.demo:
            now = monotonic()
            if now >= self.next_refresh:
                # The MCP app samples only while it is in use.
                panel.refresh()
                self.next_refresh = now + self.interval
            if now >= self.next_network_refresh:
                panel.refresh_network_probes()
                self.next_network_refresh = now + 5
        return panel.state()

    def call_tool(self, params):
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            raise ProtocolError(-32602, "Tool arguments must be an object.")
        if name == "open_vps_ops":
            if arguments:
                raise ProtocolError(-32602, "打开星图面板无需参数。")
            return {"content": [{"type": "text", "text": "星图面板已打开。"}]}
        if name != "vps_ops_ui_request":
            raise ProtocolError(-32602, "Unknown tool.")
        try:
            return {"content": [], "structuredContent": self.dashboard_request(arguments)}
        except ValueError as error:
            return tool_error(str(error))
        except CredentialError as error:
            return tool_error(str(error))
        except KeyError:
            return tool_error("主机不存在。")
        except (OSError, sqlite3.Error):
            return tool_error("无法访问主机列表，请检查本机存储。")

    def handle(self, method, params):
        if method == "initialize":
            version = params.get("protocolVersion")
            if not isinstance(version, str):
                raise ProtocolError(-32602, "A protocolVersion is required.")
            return {
                "protocolVersion": version if version in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
                "serverInfo": SERVER_INFO,
                "capabilities": CAPABILITIES,
            }
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": TOOLS}
        if method == "tools/call":
            return self.call_tool(params)
        if method == "resources/list":
            return {"resources": [RESOURCE]}
        if method == "resources/templates/list":
            return {"resourceTemplates": []}
        if method == "resources/read":
            if params.get("uri") != RESOURCE_URI:
                raise ProtocolError(-32002, "Resource not found.")
            return {"contents": [{
                "uri": RESOURCE_URI,
                "mimeType": RESOURCE_MIME,
                "text": build_ui(),
                "_meta": RESOURCE_META,
            }]}
        raise ProtocolError(-32601, "Method not found.")

    def shutdown(self):
        self.key_file_picker.close()
        if self.panel is not None:
            self.panel.shutdown()


def rpc_error(request_id, code, message):
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def dispatch(server, line):
    try:
        request = json.loads(line.decode("utf-8"))
    except (ValueError, RecursionError):
        return rpc_error(None, -32700, "Parse error.")
    if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
        return rpc_error(None, -32600, "Invalid request.")
    method = request.get("method")
    request_id = request.get("id")
    if not isinstance(method, str) or ("id" in request and type(request_id) not in (int, str)):
        return rpc_error(None, -32600, "Invalid request.")
    if "id" not in request:
        # Notifications such as initialized, cancelled and progress have no response.
        return None
    params = request.get("params", {})
    if not isinstance(params, dict):
        return rpc_error(request_id, -32602, "Params must be an object.")
    try:
        result = server.handle(method, params)
    except ProtocolError as error:
        return rpc_error(request_id, error.code, str(error))
    except Exception as error:
        print(f"Constellation Ops MCP: {method}: {type(error).__name__}", file=sys.stderr)
        return rpc_error(request_id, -32603, "Internal error.")
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def serve(server, reader, writer):
    while line := reader.readline(MAX_REQUEST + 1):
        if len(line) > MAX_REQUEST:
            while line and not line.endswith(b"\n"):
                line = reader.readline(MAX_REQUEST + 1)
            response = rpc_error(None, -32600, "Request too large.")
        else:
            response = dispatch(server, line)
        if response is not None:
            writer.write(json.dumps(response, ensure_ascii=True, allow_nan=False).encode("utf-8") + b"\n")
            writer.flush()


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--data-dir", type=Path, default=default_data_dir(), help="本机主机列表目录")
    cli.add_argument("--interval", type=int, default=60, help="面板打开时的巡检间隔，单位秒")
    cli.add_argument("--demo", action="store_true", help="打开演示数据")
    args = cli.parse_args()
    if not 15 <= args.interval <= 3600:
        cli.error("间隔须为 15–3600 秒。")
    server = Server(args.data_dir.expanduser(), args.interval, args.demo)
    try:
        serve(server, sys.stdin.buffer, sys.stdout.buffer)
    except (BrokenPipeError, KeyboardInterrupt):
        pass
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()
