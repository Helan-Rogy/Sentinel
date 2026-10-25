"""Sentinel API: ingest, query, approve, and live-stream."""
from __future__ import annotations

import hmac
from collections import Counter
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from contracts import (
    ActionResult,
    ActionStatus,
    FileEvent,
    Incident,
    IncidentStatus,
)

from .bus import Bus
from .config import Settings
from .db import Store


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    cfg = settings or Settings()
    store = Store(cfg.db_path)
    bus = Bus()
    app = FastAPI(title="Sentinel", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.state.store, app.state.bus, app.state.cfg = store, bus, cfg

    def check_token(tok: Optional[str]) -> bool:
        return bool(tok) and hmac.compare_digest(tok, cfg.token)

    def auth(authorization: Optional[str] = Header(None)) -> str:
        tok = authorization[7:] if authorization and authorization.startswith("Bearer ") else None
        if not check_token(tok):
            raise HTTPException(401, "invalid or missing token")
        return "admin"

    @app.get("/api/health")
    def health():
        return {"status": "ok", "suspend_enabled": cfg.allow_suspend,
                "auto_contain_enabled": cfg.allow_auto_contain}

    @app.post("/api/events")
    def post_event(e: FileEvent, who: str = Depends(auth)):
        store.add_event(e)
        bus.publish("event", e.model_dump(mode="json"))
        return {"ok": True, "id": e.id}

    @app.get("/api/events")
    def get_events(limit: int = 200, who: str = Depends(auth)):
        return [e.model_dump(mode="json") for e in store.list_events(min(limit, 1000))]

    @app.post("/api/incidents")
    def upsert_incident(inc: Incident, who: str = Depends(auth)):
        old = store.get_incident(inc.id)
        if old:  # evidence may be refreshed; decisions and outcomes are server-owned
            inc.created, inc.actions = old.created, old.actions
            inc.results, inc.status = old.results, old.status
        store.save_incident(inc)
        store.audit(who, "incident.upsert", inc.id, inc.title)
        bus.publish("incident", inc.model_dump(mode="json"))
        return {"ok": True, "id": inc.id}

    @app.get("/api/incidents")
    def list_incidents(who: str = Depends(auth)):
        return [i.model_dump(mode="json") for i in store.list_incidents()]

    @app.get("/api/incidents/{inc_id}")
    def get_incident(inc_id: str, who: str = Depends(auth)):
        inc = store.get_incident(inc_id)
        if not inc:
            raise HTTPException(404, "incident not found")
        return inc.model_dump(mode="json")

    def _decide(inc_id: str, act_id: str, approve: bool, who: str):
        inc = store.get_incident(inc_id)
        if not inc:
            raise HTTPException(404, "incident not found")
        act = next((a for a in inc.actions if a.id == act_id), None)
        if not act:
            raise HTTPException(404, "action not found")
        if act.status != ActionStatus.PROPOSED:
            raise HTTPException(409, f"action already {act.status.value}")
        act.status = ActionStatus.APPROVED if approve else ActionStatus.REJECTED
        if not approve and not any(a.status == ActionStatus.PROPOSED for a in inc.actions):
            inc.status = IncidentStatus.OPEN
        store.save_incident(inc)
        store.audit(who, "action.approve" if approve else "action.reject", act_id, inc_id)
        bus.publish("incident", inc.model_dump(mode="json"))
        return inc.model_dump(mode="json")

    @app.post("/api/incidents/{inc_id}/actions/{act_id}/approve")
    def approve(inc_id: str, act_id: str, who: str = Depends(auth)):
        return _decide(inc_id, act_id, True, who)

    @app.post("/api/incidents/{inc_id}/actions/{act_id}/reject")
    def reject(inc_id: str, act_id: str, who: str = Depends(auth)):
        return _decide(inc_id, act_id, False, who)

    @app.post("/api/incidents/{inc_id}/results")
    def post_result(inc_id: str, r: ActionResult, who: str = Depends(auth)):
        inc = store.get_incident(inc_id)
        if not inc:
            raise HTTPException(404, "incident not found")
        act = next((a for a in inc.actions if a.id == r.action_id), None)
        if not act:
            raise HTTPException(404, "action not found")
        inc.results.append(r)
        act.status = (ActionStatus.VERIFIED if r.verified
                      else ActionStatus.EXECUTED if r.success else ActionStatus.FAILED)
        if r.success and r.verified:
            inc.status = IncidentStatus.CONTAINED
        store.save_incident(inc)
        store.audit(who, "action.result", r.action_id, f"success={r.success} verified={r.verified}")
        bus.publish("incident", inc.model_dump(mode="json"))
        return {"ok": True}

    @app.post("/api/incidents/{inc_id}/status")
    def set_status(inc_id: str, body: dict, who: str = Depends(auth)):
        try:
            status = IncidentStatus(body.get("status"))
        except ValueError:
            raise HTTPException(422, "invalid status")
        if status not in (IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE, IncidentStatus.OPEN):
            raise HTTPException(422, "status can only be set to closed, false_positive or open")
        inc = store.get_incident(inc_id)
        if not inc:
            raise HTTPException(404, "incident not found")
        inc.status = status
        store.save_incident(inc)
        store.audit(who, f"incident.{status.value}", inc_id)
        bus.publish("incident", inc.model_dump(mode="json"))
        return inc.model_dump(mode="json")

    @app.get("/api/stats")
    def stats(who: str = Depends(auth)):
        incs = store.list_incidents(1000)
        by_level = Counter(i.assessment.level.value for i in incs if i.assessment)
        by_status = Counter(i.status.value for i in incs)
        pending = sum(1 for i in incs for a in i.actions if a.status == ActionStatus.PROPOSED)
        return {"events": store.count_events(), "incidents": len(incs),
                "by_level": dict(by_level), "by_status": dict(by_status),
                "pending_approvals": pending}

    @app.get("/api/audit")
    def audit_log(limit: int = 200, who: str = Depends(auth)):
        return store.list_audit(min(limit, 1000))

    @app.websocket("/ws")
    async def ws(sock: WebSocket, token: str = ""):
        if not check_token(token):
            await sock.close(code=4401)
            return
        await sock.accept()
        q = bus.subscribe()
        try:
            while True:
                await sock.send_text(await q.get())
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            bus.unsubscribe(q)

    return app
