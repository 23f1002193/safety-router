"""GA5 Q4 - Harness safety router (deterministic policy rules in rules.py)."""
import os, json, time, pathlib
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from rules import classify

DEBUG_KEY = os.environ.get("DEBUG_KEY", "")
LOG = pathlib.Path("/tmp/batches"); LOG.mkdir(exist_ok=True)
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.get("/")
def root(): return {"ok": True, "service": "safety-router", "version": 2}

@app.post("/classify")
async def route(req: Request):
    env = await req.json()
    out = []
    for c in env.get("cases", []) or []:
        try: out.append(classify(c))
        except Exception as e:
            print("case error", repr(e))
            out.append({"caseId": c.get("caseId"), "requestDecision": "review",
                        "toolDecision": "review" if c.get("proposedTool") else "none",
                        "route": "primary", "trajectory": "watch"})
    try: (LOG / f"{int(time.time()*1000)}.json").write_text(json.dumps({"in": env, "out": out}))
    except Exception: pass
    return JSONResponse({"profile": env.get("profile"), "batchId": env.get("batchId"), "results": out})

@app.get("/debug/batches")
def batches(key: str = ""):
    if not DEBUG_KEY or key != DEBUG_KEY: return JSONResponse({"error": "not found"}, 404)
    return [json.loads(p.read_text()) for p in sorted(LOG.glob("*.json"))[-8:]]
