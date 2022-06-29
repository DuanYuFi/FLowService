import asyncio

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from Analyzer import FlowAnalyzer, get_ngrams
from config.sniffer import LISTENING_PORT, LISTENING_HOST, PACKAGE_GROUP_NUM
from utils.hids import get_hids_warings
from utils.honey import get_honey_warnings

app = FastAPI()

flowAnalyzer = FlowAnalyzer(LISTENING_HOST, LISTENING_PORT, threshold=PACKAGE_GROUP_NUM)
flowAnalyzer.start()

@app.websocket("/ws/v1/flow/")
async def flow_analyzer(websocket: WebSocket):
    
    await flowAnalyzer.connect(websocket)
    
    try:
        while True:
            data = await websocket.receive_text()
            print(data)
    
    except WebSocketDisconnect:
        flowAnalyzer.disconnect()

@app.websocket("/ws/v1/hid/")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    while True:
        try:
            data = get_hids_warings()
            await websocket.send_text(data)
            await asyncio.sleep(5)
        except WebSocketDisconnect:
            await websocket.close()
        except Exception as e:
            print(e)
            await websocket.close()

@app.websocket("/ws/v1/honey/")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    while True:
        try:
            data = get_honey_warnings()
            await websocket.send_text(data)
            await asyncio.sleep(5)
        except Exception as e:
            print(e)
            await websocket.close()

if __name__ == "__main__":
    import uvicorn
    from config.common import SERVICE_HOST, SERVICE_PORT

    uvicorn.run(app, host=SERVICE_HOST, port=SERVICE_PORT)
