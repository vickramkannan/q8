from fastapi import FastAPI
from pydantic import BaseModel
import os
import requests
import ipaddress
from urllib.parse import urlparse, parse_qs, unquote

app = FastAPI()

SANDBOX_ROOT = "/srv/agent-redteam/sandbox-2e8a8aa36a"

ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org"
}


class ToolRequest(BaseModel):
    tool: str
    arguments: dict


def is_internal_host(host):
    host = host.lower()

    if host == "localhost":
        return True

    try:
        ip = ipaddress.ip_address(host)

        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
        )

    except ValueError:
        return False


def looks_like_internal_target(value):
    value = unquote(value)

    if "://" in value:
        u = urlparse(value)
        return is_internal_host(u.hostname or "")

    return is_internal_host(value)


def safe_path(path):
    root = os.path.realpath(SANDBOX_ROOT)

    if os.path.isabs(path):
        full = os.path.realpath(path)
    else:
        full = os.path.realpath(os.path.join(root, path))

    return full == root or full.startswith(root + os.sep)


def read_file(path):
    with open(os.path.join(SANDBOX_ROOT, path), "r") as f:
        return f.read()


def fetch_url(url):

    u = urlparse(url)
    host = (u.hostname or "").lower()

    if host not in ALLOWED_HOSTS:
        return None, "host not allowed"

    for values in parse_qs(u.query).values():
        for v in values:
            if looks_like_internal_target(v):
                return None, "redirect target blocked"

    r = requests.get(url, timeout=5)

    return r.text, "success"


@app.post("/check")
def check(req: ToolRequest):

    tool = req.tool
    args = req.arguments

    if tool == "read_file":

        path = args.get("path")

        if not safe_path(path):
            return {
                "action": "block",
                "reason": "path outside sandbox"
            }

        try:
            result = read_file(path)

            return {
                "action": "allow",
                "reason": "inside sandbox",
                "result": result
            }

        except Exception as e:
            return {
                "action": "allow",
                "reason": "file read failed",
                "result": str(e)
            }


    elif tool == "fetch_url":

        url = args.get("url")

        result, reason = fetch_url(url)

        if result is None:
            return {
                "action": "block",
                "reason": reason
            }

        return {
            "action": "allow",
            "reason": "allowed host",
            "result": result
        }


    return {
        "action": "allow",
        "reason": "unknown tool"
    }