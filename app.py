from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from Analyzer import FlowAnalyzer, get_ngrams
from config.sniffer import LISTENING_PORT, LISTENING_HOST, PACKAGE_GROUP_NUM

app = FastAPI()

flowAnalyzer = FlowAnalyzer(LISTENING_HOST, LISTENING_PORT, threshold=PACKAGE_GROUP_NUM)

@app.websocket("/ws/v1/flow")
async def flow_analyzer(websocket: WebSocket):
    
    await flowAnalyzer.connect(websocket)
    
    try:
        await flowAnalyzer.run()
    
    except WebSocketDisconnect:
        flowAnalyzer.ws = None


if __name__ == "__main__":
    import uvicorn
    from config.common import SERVICE_HOST, SERVICE_PORT

    uvicorn.run(app, host=SERVICE_HOST, port=SERVICE_PORT)

