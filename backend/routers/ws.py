"""
WebSocket router: /ws/feed — real-time detection broadcast.

ConnectionManager handles all active WebSocket connections.
It is imported by the alerts router to broadcast new detections as they arrive.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(tags=["websocket"])


class ConnectionManager:
    """Manage active WebSocket connections and broadcast messages."""

    def __init__(self) -> None:
        self.active: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active:
            self.active.remove(websocket)

    async def broadcast(self, data: dict[str, Any]) -> None:
        """Send a JSON payload to every connected client."""
        disconnected: list[WebSocket] = []
        for ws in list(self.active):
            try:
                await ws.send_json(data)
            except Exception:
                disconnected.append(ws)
        for ws in disconnected:
            self.disconnect(ws)


# Singleton manager — import this from other routers to broadcast events
manager = ConnectionManager()


@router.websocket("/ws/feed")
async def websocket_feed(websocket: WebSocket) -> None:
    """
    Live detection feed WebSocket endpoint.
    Clients connect here and receive JSON payloads whenever a new detection is stored.
    A heartbeat ping is sent every 25 seconds to keep the connection alive.
    """
    await manager.connect(websocket)
    try:
        while True:
            # Keep-alive ping every 25 s; actual data is pushed via manager.broadcast()
            await asyncio.sleep(25)
            await websocket.send_json({"ping": True})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)
