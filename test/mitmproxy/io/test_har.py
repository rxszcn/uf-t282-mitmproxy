import base64
import io
import json
from pathlib import Path

import pytest

from mitmproxy import exceptions
from mitmproxy.io.har import fix_headers
from mitmproxy.io.har import postdata_to_content
from mitmproxy.io.har import request_to_flow
from mitmproxy.io.io import FlowReader
from mitmproxy.tools.web.app import flow_to_json
from mitmproxy.utils import strutils

data_dir = Path(__file__).parent.parent / "data"


def hardcode_variable_fields_for_tests(flow: dict) -> None:
    flow["id"] = "hardcoded_for_test"
    flow["timestamp_created"] = 0
    flow["server_conn"]["id"] = "hardcoded_for_test"
    flow["client_conn"]["id"] = "hardcoded_for_test"


def file_to_flows(path_name: Path) -> list[dict]:
    file_json = json.loads(path_name.read_bytes())["log"]["entries"]
    flows = []

    for entry in file_json:
        expected = request_to_flow(entry)
        flow_json = flow_to_json(expected)
        hardcode_variable_fields_for_tests(flow_json)
        flows.append(flow_json)

    return flows


def test_corrupt():
    file_json = json.loads(
        Path(data_dir / "corrupted_har/broken_headers.json").read_bytes()
    )
    with pytest.raises(exceptions.OptionsError):
        fix_headers(file_json["headers"])


def test_postdata_base64_marker_restored():
    """A base64-marked request body is decoded back into the original bytes."""
    content = b"\x89PNG\r\n\x1a\n" + bytes(range(64, 256)) * 3
    assert strutils.is_mostly_bin(content)  # sanity: this is a binary payload

    request = {
        "method": "GET",
        "url": "http://example.com/",
        "httpVersion": "HTTP/1.1",
        "headers": [],
        "queryString": [],
        "cookies": [],
        "headersSize": -1,
        "bodySize": len(content),
        "postData": {
            "mimeType": "image/png",
            "text": base64.b64encode(content).decode(),
            "encoding": "base64",
        },
    }
    entry = {
        "startedDateTime": "2023-07-15T13:37:26.000Z",
        "time": 0,
        "request": request,
        "response": {
            "status": 200,
            "statusText": "OK",
            "httpVersion": "HTTP/1.1",
            "headers": [],
            "cookies": [],
            "content": {"size": 0, "mimeType": "text/plain", "text": ""},
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": -1,
        },
    }

    flow = request_to_flow(entry)
    assert flow.request.content == content


def test_postdata_params_only_entry_readable():
    """An entry with only params (no text field) stays readable; the body is assembled."""
    content = postdata_to_content(
        {
            "mimeType": "application/x-www-form-urlencoded",
            "params": [
                {"name": "key1", "value": "value1"},
                {"name": "key2", "value": "value2"},
            ],
        }
    )

    assert content == "key1=value1&key2=value2"


def test_postdata_params_only_entry_to_flow():
    """A params-only entry does not break the whole archive."""
    har = {
        "log": {
            "entries": [
                {
                    "startedDateTime": "2023-07-15T13:37:26.000Z",
                    "time": 0,
                    "request": {
                        "method": "POST",
                        "url": "http://example.com/",
                        "httpVersion": "HTTP/1.1",
                        "headers": [
                            {
                                "name": "content-type",
                                "value": "application/x-www-form-urlencoded",
                            }
                        ],
                        "queryString": [],
                        "cookies": [],
                        "headersSize": -1,
                        "bodySize": 23,
                        "postData": {
                            "mimeType": "application/x-www-form-urlencoded",
                            "params": [
                                {"name": "key1", "value": "value1"},
                                {"name": "key2", "value": "value2"},
                            ],
                        },
                    },
                    "response": {
                        "status": 200,
                        "statusText": "OK",
                        "httpVersion": "HTTP/1.1",
                        "headers": [],
                        "cookies": [],
                        "content": {"size": 0, "mimeType": "text/plain", "text": ""},
                        "redirectURL": "",
                        "headersSize": -1,
                        "bodySize": -1,
                    },
                }
            ]
        }
    }

    flows = list(FlowReader(io.BytesIO(json.dumps(har).encode())).stream())
    assert len(flows) == 1
    assert flows[0].request.content == b"key1=value1&key2=value2"


def test_postdata_unknown_encoding_marker():
    """An encoding marker outside our spec is treated as unmarked text, not an error."""
    assert postdata_to_content({"text": "hello", "encoding": "gzip"}) == "hello"
    assert postdata_to_content({"text": "hello"}) == "hello"
    assert postdata_to_content({}) == ""


@pytest.mark.parametrize(
    "har_file", [pytest.param(x, id=x.stem) for x in data_dir.glob("har_files/*.har")]
)
def test_har_to_flow(har_file: Path):
    expected_file = har_file.with_suffix(".json")

    expected_flows = json.loads(expected_file.read_bytes())
    actual_flows = file_to_flows(har_file)

    for expected, actual in zip(expected_flows, actual_flows):
        actual = json.loads(json.dumps(actual))

        assert actual == expected


if __name__ == "__main__":
    for path_name in data_dir.glob("har_files/*.har"):
        print(path_name)

        flows = file_to_flows(path_name)

        with open(data_dir / f"har_files/{path_name.stem}.json", "w") as f:
            json.dump(flows, f, indent=4)
