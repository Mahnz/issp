from __future__ import annotations

import base64
import json
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from . import _log as log

if TYPE_CHECKING:
    from collections.abc import Callable

type JSONMessage = dict[str, str | bytes]


class Layer(ABC):
    @abstractmethod
    def send(self, msg: bytes) -> None:
        pass

    @abstractmethod
    def receive(self) -> bytes | None:
        pass

    def __init__(self, layer: Layer | None = None) -> None:
        self.upper_layer: Layer | None = None
        self.lower_layer = layer
        if layer:
            layer.upper_layer = self

    def __or__(self, lower_layer: object) -> Layer:
        if not isinstance(lower_layer, Layer):
            err_msg = f"Unsupported operand type(s) for |: '{type(self)}' and '{type(lower_layer)}'"
            raise TypeError(err_msg)
        root_layer = self.bottom_layer()
        if isinstance(root_layer, PhysicalLayer):
            err_msg = "You've hit rock bottom, my friend"
            raise TypeError(err_msg)
        root_layer.lower_layer = lower_layer
        lower_layer.upper_layer = root_layer
        return self

    def get_layer(self, depth: int) -> Layer:
        if depth == 0:
            return self
        if depth < 0:
            if self.lower_layer is None:
                return self
            return self.lower_layer.get_layer(depth + 1)
        if self.upper_layer is None:
            return self
        return self.upper_layer.get_layer(depth - 1)

    def top_layer(self) -> Layer:
        return self if self.upper_layer is None else self.upper_layer.top_layer()

    def bottom_layer(self) -> Layer:
        return self if self.lower_layer is None else self.lower_layer.bottom_layer()


class PhysicalLayer(Layer):
    pass


class Channel(PhysicalLayer):
    def __init__(self) -> None:
        super().__init__()
        self._msg: bytes | None = None

    def send(self, msg: bytes) -> None:
        self._msg = msg

    def receive(self) -> bytes | None:
        return self._msg


class AntiReplayLayer(Layer):
    # Note: This is only secure if the underlying layers provide authentication.

    COUNTER_SIZE = 8

    def __init__(self, layer: Layer | None = None) -> None:
        super().__init__(layer)
        self._counter = 0

    def send(self, msg: bytes) -> None:
        self._counter += 1
        self.lower_layer.send(msg + self._counter.to_bytes(self.COUNTER_SIZE))

    def receive(self) -> bytes | None:
        if (msg := self.lower_layer.receive()) is None:
            return None
        if int.from_bytes(msg[-self.COUNTER_SIZE :]) < self._counter:
            err_msg = "Replay attack detected"
            raise ValueError(err_msg)
        return msg[: -self.COUNTER_SIZE]


class Actor:
    def __init__(self, name: str, *, quiet: bool = False) -> None:
        self.name = name
        self.quiet = quiet

    def send(self, layer: Layer, msg: bytes | object) -> None:
        try:
            layer.send(_try_encode(msg))
        except Exception as e:
            self._log("was unable to send: %s (%s)", msg, str(e))
        else:
            self._log("sent: %s", _try_decode(msg))

    def receive(self, layer: Layer, *, decode: bool = True) -> bytes | object | None:
        try:
            msg = layer.receive()
        except Exception as e:
            self._log("was unable to receive: %s", str(e))
            return None
        if decode:
            msg = _try_decode(msg)
        self._log("received: %s", msg)
        return msg

    def _log(self, fmt: str, *args: object) -> None:
        if not self.quiet:
            log.info("%s " + fmt, self.name, *args)


class Server(Actor):
    def __init__(self, name: str, *, quiet: bool = False) -> None:
        super().__init__(name, quiet=quiet)
        self.handlers: dict[str, Callable[[JSONMessage], JSONMessage]] = {}

    def handle_request(self, channel: Channel) -> None:
        action = None
        try:
            msg = self.receive(channel)
            action = msg["action"]
            response = self._handle_message(action, msg)
        except Exception as e:
            log.error("Error handling request: %s", str(e))
            response = {"status": "invalid request"}
        self.send(channel, {"action": action} | response if action else response)

    def _handle_message(self, action: str, msg: JSONMessage) -> JSONMessage:
        return self.handlers[action](msg)


class BankServer(Server, ABC):
    @abstractmethod
    def register(self, msg: JSONMessage) -> bool:
        pass

    @abstractmethod
    def authenticate(self, msg: JSONMessage) -> bool:
        pass

    def __init__(self, name: str, *, quiet: bool = False) -> None:
        super().__init__(name, quiet=quiet)
        self.db: dict[str, dict] = {}
        self.handlers["register"] = self._register
        self.handlers["perform_transaction"] = self._perform_transaction

    def _register(self, msg: JSONMessage) -> JSONMessage:
        return {"status": "success" if self.register(msg) else "failure"}

    def _perform_transaction(self, msg: JSONMessage) -> JSONMessage:
        if not self.authenticate(msg):
            return {"status": "authentication failure"}

        user = msg["user"]
        recipient = msg["recipient"]
        user_record = self.db[user]
        recipient_record = self.db[recipient]
        amount = msg["amount"]

        if user_record["balance"] < amount:
            return {"status": "insufficient funds"}

        user_record["balance"] -= amount
        recipient_record["balance"] += amount

        log.info("Current balances: %s", {k: v["balance"] for k, v in self.db.items()})

        return {"status": "success", "user": user, "recipient": recipient, "amount": amount}


def _preprocess_bytes(obj: object) -> object:
    if isinstance(obj, dict):
        new_obj = {}
        for key, value in obj.items():
            if isinstance(value, bytes):
                new_obj[f"{key}_b64"] = base64.b64encode(value).decode("ascii")
            elif isinstance(value, dict | list):
                new_obj[key] = _preprocess_bytes(value)
            else:
                new_obj[key] = value
        return new_obj
    if isinstance(obj, list):
        return [_preprocess_bytes(item) for item in obj]
    return obj


def _postprocess_bytes(obj: object) -> object:
    if isinstance(obj, dict):
        new_obj = {}
        for key, value in obj.items():
            if key.endswith("_b64"):
                new_obj[key[:-4]] = base64.b64decode(value)
            elif isinstance(value, dict | list):
                new_obj[key] = _postprocess_bytes(value)
            else:
                new_obj[key] = value
        return new_obj
    if isinstance(obj, list):
        return [_postprocess_bytes(item) for item in obj]
    return obj


class BytesAwareJSONEncoder(json.JSONEncoder):
    def encode(self, o: json.Any) -> str:
        return super().encode(_preprocess_bytes(o))


class BytesAwareJSONDecoder(json.JSONDecoder):
    def decode(self, s: str) -> json.Any:
        return _postprocess_bytes(super().decode(s))


def _try_encode(msg: bytes | object) -> bytes:
    if isinstance(msg, bytes):
        return msg
    try:
        return json.dumps(msg, cls=BytesAwareJSONEncoder).encode()
    except Exception:
        return msg


def _try_decode(msg: bytes | None) -> bytes | object | None:
    try:
        return None if msg is None else json.loads(msg, cls=BytesAwareJSONDecoder)
    except Exception:
        return msg
