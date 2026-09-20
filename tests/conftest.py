"""No network, model calls, or container engines are needed by this suite."""
from pathlib import Path
import socket
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("Tests must not access the network")
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)

# Pytest creates basetemp, but its parent must exist on a fresh checkout.
(Path(__file__).resolve().parents[1] / '.build').mkdir(exist_ok=True)
