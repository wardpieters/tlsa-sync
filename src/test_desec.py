import json
from functools import partial

import httpx
import pytest

from providers.desec import DesecClient


@pytest.mark.parametrize("exists", [False, True], ids=["create", "replace"])
def test_upsert_writes_to_collection_and_caches_result(tmp_path, monkeypatch, exists):
    collection_path = "/api/v1/domains/example.com/rrsets/"
    subname = "_25._tcp.mail"
    detail_path = f"{collection_path}{subname}/TLSA/"
    old_records = [f"3 1 1 {'0' * 64}"]
    records = (f"3 1 1 {'1' * 64}",)
    expected = {"subname": subname, "type": "TLSA", "ttl": 300, "records": list(records)}
    requests = []

    def serve(request):
        method, path = request.method, request.url.path
        requests.append((method, path))
        if (method, path) == ("GET", detail_path):
            if not exists:
                return httpx.Response(404)
            return httpx.Response(200, json={**expected, "records": old_records})
        if (method, path) == ("PUT", collection_path):
            assert json.loads(request.content) == [expected]
            return httpx.Response(200, json=[expected])
        if (method, path) == ("PUT", detail_path) and exists:
            return httpx.Response(400)
        return httpx.Response(404)

    client_factory = partial(httpx.Client, transport=httpx.MockTransport(serve))
    monkeypatch.setattr(httpx, "Client", client_factory)
    client = DesecClient("test-token", 5, cache_file=str(tmp_path / "cache.json"))
    try:
        assert client.upsert_rrset("example.com", subname, records, 300)
        assert not client.upsert_rrset("example.com", subname, records, 300)
    finally:
        client.close()

    assert requests == [("GET", detail_path), ("PUT", collection_path)]
