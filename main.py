from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import hmac, hashlib, time, asyncio, json
from collections import defaultdict

app = FastAPI()
SEED = "SEED-2563-PH-405E"
HEADER = "x-pinhire-hmac-2563"
LIMIT = 455
store = {}
locks = defaultdict(asyncio.Lock)

def check_hmac(raw_body: bytes, sig: str):
    expected = hmac.new(SEED.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig or "")

@app.post("/api/guard")
async def guard(request: Request):
    raw = await request.body()
    sig = request.headers.get(HEADER, "")
    if not check_hmac(raw, sig):
        return JSONResponse({"error":"bad sig"}, status_code=401)
    
    data = json.loads(raw)
    event = data.get("event")
    payload = data.get("payload", {})
    tx = payload.get("tx_ref_2563") or "default"

    if event == "faq.query":
        return JSONResponse({"status":"answered", "answer":"This is cached FAQ answer"}, status_code=200)

    if event == "refund.requested":
        async with locks[tx]:
            now = time.time()
            if tx in store and now - store[tx] < 300:
                return JSONResponse({"status":"duplicate"}, status_code=409)
            amt = float(payload.get("refund_amt", 0) or 0)
            if amt > LIMIT:
                return JSONResponse({"error":"limit exceeded"}, status_code=403)
            store[tx] = now
            return JSONResponse({"status":"processed"}, status_code=200)
    
    return JSONResponse({"status":"processed"}, status_code=200)
