from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
from collections.abc import Callable
from typing import Any

from uvicorn import Config, Server

from .endpoint import Endpoint
from .listener import AdoptedSocket, ListenerClosedError, PHXPListener

logger = logging.getLogger("uvicorn.error")


class PHXPUvicornServer(Server):
    """Uvicorn server that feeds PHXP sockets into its configured HTTP protocol."""

    def __init__(
        self,
        config: Config,
        endpoint: Endpoint,
        *,
        handoff_queue_size: int = 128,
        handoff_backlog: int = 128,
        control_timeout: float = 2.0,
    ) -> None:
        super().__init__(config)
        self.endpoint = endpoint
        self.handoff_queue_size = handoff_queue_size
        self.handoff_backlog = handoff_backlog
        self.control_timeout = control_timeout
        self.handoff_listener: PHXPListener | None = None
        self._handoff_task: asyncio.Task[None] | None = None

    @property
    def direct_addresses(self) -> list[tuple[Any, ...] | str]:
        addresses: list[tuple[Any, ...] | str] = []
        for server in getattr(self, "servers", []):
            for listening_socket in server.sockets or ():
                addresses.append(listening_socket.getsockname())
        return addresses

    async def startup(self, sockets: list[socket.socket] | None = None) -> None:
        if sockets is not None:
            raise RuntimeError("PHXPUvicornServer owns its ordinary listener")
        await self.lifespan.startup()
        if self.lifespan.should_exit:
            self.should_exit = True
            return

        config = self.config
        loop = asyncio.get_running_loop()

        def create_protocol(
            _loop: asyncio.AbstractEventLoop | None = None,
        ) -> asyncio.Protocol:
            return config.http_protocol_class(  # type: ignore[call-arg,no-any-return]
                config=config,
                server_state=self.server_state,
                app_state=self.lifespan.state,
                _loop=_loop,
            )

        try:
            handoff = PHXPListener(
                self.endpoint,
                queue_size=self.handoff_queue_size,
                backlog=self.handoff_backlog,
                control_timeout=self.control_timeout,
                logger=logging.getLogger("phxp"),
            )
        except Exception:
            await self.lifespan.shutdown()
            raise
        try:
            direct = await loop.create_server(
                create_protocol,
                host=config.host,
                port=config.port,
                ssl=config.ssl,
                backlog=config.backlog,
            )
        except BaseException:
            handoff.close()
            await self.lifespan.shutdown()
            raise

        self.handoff_listener = handoff
        self.servers = [direct]
        self._handoff_task = asyncio.create_task(
            self._pump_handoffs(create_protocol),
            name="phxp-uvicorn-adoption",
        )
        assert direct.sockets is not None
        self._log_started_message(direct.sockets)
        logger.info("PHXP endpoint: %s", self.endpoint.path)
        self.started = True

    async def shutdown(self, sockets: list[socket.socket] | None = None) -> None:
        handoff = self.handoff_listener
        if handoff is not None:
            await asyncio.to_thread(handoff.close)
            self.handoff_listener = None
        task = self._handoff_task
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            self._handoff_task = None
        await super().shutdown(sockets=sockets)

    async def _pump_handoffs(
        self,
        create_protocol: Callable[
            [asyncio.AbstractEventLoop | None],
            asyncio.Protocol,
        ],
    ) -> None:
        assert self.handoff_listener is not None
        listener = self.handoff_listener
        loop = asyncio.get_running_loop()
        while True:
            try:
                adopted = await asyncio.to_thread(listener.accept, 0.2)
            except TimeoutError:
                continue
            except ListenerClosedError:
                return
            connection = adopted.transfer()

            def tracked_protocol(
                _loop: asyncio.AbstractEventLoop | None = None,
                *,
                item: AdoptedSocket = adopted,
            ) -> asyncio.Protocol:
                protocol = create_protocol(_loop)
                original_connection_lost = protocol.connection_lost

                def connection_lost(error: Exception | None) -> None:
                    try:
                        original_connection_lost(error)
                    finally:
                        item.release()

                protocol.connection_lost = connection_lost  # type: ignore[method-assign]
                return protocol

            try:
                # Ownership becomes irreversible before the TLS transport can consume
                # bytes; later protocol or handshake failures must never trigger relay.
                adopted.adopt()
                await loop.connect_accepted_socket(
                    tracked_protocol,
                    connection,
                    ssl=self.config.ssl,
                )
            except asyncio.CancelledError:
                connection.close()
                adopted.release()
                raise
            except Exception:
                connection.close()
                adopted.release()
                logger.exception("Uvicorn could not adopt PHXP connection")
