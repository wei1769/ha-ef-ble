from unittest.mock import AsyncMock, Mock

import pytest

from custom_components.ef_ble.eflib.connection import (
    Connection,
    ConnectionState,
    derive_auth_key,
)
from custom_components.ef_ble.eflib.exceptions import (
    AuthErrors,
    UnsupportedBluetoothProtocol,
)
from custom_components.ef_ble.eflib.packet import Packet

SERIAL = "R631TEST1234"


async def _data_parse(_packet: Packet) -> bool:
    return False


async def _packet_parse(data: bytes) -> Packet:
    return Packet.from_bytes(data)


def _connection(*, accountless: bool = True) -> Connection:
    ble_device = Mock(address="AA:BB:CC:DD:EE:FF")
    return Connection(
        ble_device,
        SERIAL,
        "" if accountless else "1234",
        _data_parse,
        _packet_parse,
        accountless=accountless,
    )


def test_derive_accountless_key_in_both_supported_cases() -> None:
    assert derive_auth_key("", SERIAL, uppercase=False) == (
        b"b17975c56fcd2aac6b4a453907d5fc76"
    )
    assert derive_auth_key("", SERIAL, uppercase=True) == (
        b"B17975C56FCD2AAC6B4A453907D5FC76"
    )


@pytest.mark.parametrize(
    ("accountless", "expected"),
    [
        (True, b"b17975c56fcd2aac6b4a453907d5fc76"),
        (False, derive_auth_key("1234", SERIAL, uppercase=True)),
    ],
)
async def test_check_auth_key_source_and_case(
    accountless: bool, expected: bytes
) -> None:
    connection = _connection(accountless=accountless)
    connection.send_packet = AsyncMock()

    await connection._auto_authentication()

    packet = connection.send_packet.await_args.args[0]
    assert packet.cmd_id == 0x86
    assert packet.payload == expected


async def test_accountless_first_bind_writes_key_once_and_requires_reconnect() -> None:
    connection = _connection()
    connection._set_state(ConnectionState.AUTHENTICATING)
    connection._client = Mock()
    connection.send_packet = AsyncMock()

    async def disconnect() -> None:
        connection._client = None

    connection._disconnect_client = AsyncMock(side_effect=disconnect)
    reply = Packet(0x35, 0x21, 0x35, 0x86, b"\x04", 0x01, 0x01, 0x03)

    assert await connection._check_auth(reply) is False

    bind_packet = connection.send_packet.await_args.args[0]
    assert bind_packet.cmd_id == 0x85
    assert bind_packet.payload == b"b17975c56fcd2aac6b4a453907d5fc76"
    assert connection.send_packet.await_args.kwargs == {
        "wait_for_response": False,
        "raise_on_failure": True,
    }
    assert connection._accountless_reconnect_pending is True
    assert connection._accountless_bind_attempted is True

    with pytest.raises(AuthErrors.NeedBindInstallFirst):
        await connection._check_auth(reply)
    assert connection.send_packet.await_count == 1


async def test_accountless_requires_explicit_success_reply() -> None:
    connection = _connection()
    connection._set_state(ConnectionState.AUTHENTICATING)
    connection._client = Mock()
    connection._data_parse = AsyncMock(return_value=True)
    telemetry = Packet(0x02, 0x21, 0xFE, 0x15, b"data", 0x01, 0x01, 0x03)

    await connection._process_packets([telemetry])

    assert connection._state is ConnectionState.AUTHENTICATING
    connection._data_parse.assert_awaited_once_with(telemetry)


async def test_accountless_bind_disconnect_schedules_immediate_reconnect() -> None:
    connection = _connection()
    connection._accountless_reconnect_pending = True
    connection._reconnect_after_accountless_bind = AsyncMock()

    connection.disconnected()
    await connection._reconnect_task

    connection._reconnect_after_accountless_bind.assert_awaited_once_with()
    assert connection._state is not ConnectionState.DISCONNECTED


async def test_empty_gatt_cache_is_cleared_and_retried_once(mocker, caplog) -> None:
    connection = _connection()
    services = Mock(services={}, characteristics={})
    clients = [
        Mock(is_connected=True, services=services),
        Mock(is_connected=True, services=services),
    ]
    establish = mocker.patch(
        "custom_components.ef_ble.eflib.connection.establish_connection",
        new=AsyncMock(side_effect=clients),
    )
    mocker.patch(
        "custom_components.ef_ble.eflib.connection.close_stale_connections_by_address",
        new=AsyncMock(),
    )
    mocker.patch(
        "custom_components.ef_ble.eflib.connection.asyncio.sleep", new=AsyncMock()
    )
    connection._validate_characteristics = Mock(
        side_effect=[UnsupportedBluetoothProtocol("notify", []), None]
    )
    connection._clear_gatt_cache = AsyncMock()
    connection._disconnect_client = AsyncMock()
    connection._start_notify = AsyncMock()
    connection._run_auth = AsyncMock()

    await connection.connect(max_attempts=3)
    await connection._auth_task

    assert establish.await_count == 2
    assert establish.await_args_list[0].kwargs["use_services_cache"] is True
    assert establish.await_args_list[1].kwargs["use_services_cache"] is False
    connection._clear_gatt_cache.assert_awaited_once_with()
    assert connection._state is ConnectionState.CONNECTED
    assert connection._gatt_cache_recovery_attempted is False
    assert "GATT discovery snapshot" in caplog.text
    assert "services=0 characteristics=0" in caplog.text


async def test_gatt_cache_clear_uses_retry_connector(mocker) -> None:
    connection = _connection()
    clear_cache = mocker.patch(
        "custom_components.ef_ble.eflib.connection.clear_cache",
        new=AsyncMock(return_value=True),
    )

    await connection._clear_gatt_cache()

    clear_cache.assert_awaited_once_with(connection._address)


@pytest.mark.parametrize(
    ("payload", "error"),
    [
        (b"\x03", AuthErrors.DeviceAlreadyBound),
        (b"\x06", AuthErrors.WrongKey),
    ],
)
async def test_accountless_does_not_overwrite_terminal_auth_errors(
    payload: bytes, error: type[Exception]
) -> None:
    connection = _connection()
    connection._client = Mock()
    connection.send_packet = AsyncMock()
    connection._disconnect_client = AsyncMock()
    reply = Packet(0x35, 0x21, 0x35, 0x86, payload, 0x01, 0x01, 0x03)

    with pytest.raises(error):
        await connection._check_auth(reply)

    connection.send_packet.assert_not_awaited()
