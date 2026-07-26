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
    host = host.lower().strip()

    if host == "localhost":
        return True

    try:
        ip = ipaddress.ip_address(host)

        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        )

    except ValueError:
        # Normal domain names are not treated as IPs
        return False


def looks_like_internal_target(value):
    value = unquote(value).strip()

    # Only inspect actual URLs
    if "://" not in value:
        return False

    try:
        u = urlparse(value)
        host = u.hostname or ""
        return is_internal_host(host)

    except Exception:
        return False


def safe_path(path):
    root = os.path.normpath(SANDBOX_ROOT)

    if os.path.isabs(path):
        full = os.path.normpath(path)
    else:
        full = os.path.normpath(
            os.path.join(root, path)
        )

    return (
        full == root
        or full.startswith(root + os.sep)
    )


def read_file(path):

    if os.path.isabs(path):
        full = path
    else:
        full = os.path.join(
            SANDBOX_ROOT,
            path
        )

    with open(full, "r") as f:
        return f.read()


def fetch_url(url):

    u = urlparse(url)

    host = (u.hostname or "").lower()

    # Block non-approved hosts
    if host not in ALLOWED_HOSTS:
        return None, "host not allowed"


    # Check redirect-style parameters
    for values in parse_qs(u.query).values():

        for value in values:

            if looks_like_internal_target(value):
                return None, "internal redirect blocked"


    try:
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=False
        )

        # Block real redirects to another host
        if response.is_redirect:

            location = response.headers.get(
                "location",
                ""
            )

            if location:

                redirect_host = (
                    urlparse(location).hostname
                    or ""
                ).lower()

                if redirect_host not in ALLOWED_HOSTS:
                    return None, "redirect blocked"


        return response.text, "success"


    except Exception as e:

        return None, str(e)



@app.post("/check")
def check(req: ToolRequest):

    tool = req.tool
    args = req.arguments


    # FILE TOOL
    if tool == "read_file":

        path = args.get("path", "")


        if not safe_path(path):

            return {
                "action": "block",
                "reason": "path outside sandbox"
            }


        try:

            content = read_file(path)

            return {
                "action": "allow",
                "reason": "inside sandbox",
                "result": content
            }


        except Exception as e:

            return {
                "action": "allow",
                "reason": "file error",
                "result": str(e)
            }



    # NETWORK TOOL
    if tool == "fetch_url":

        url = args.get("url", "")

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
