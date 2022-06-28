from os import path

TMP_PATH = "tmp"
TMP_TLS_PATH = path.join(TMP_PATH,"TLS")
TMP_TLS_INPUT_PATH = path.join(TMP_TLS_PATH,"input")
TMP_TLS_OUTPUT_PATH = path.join(TMP_TLS_PATH,"output")

TMP_PATH = "tmp"
TMP_HTTP_PATH = path.join(TMP_PATH,"HTTP")
TMP_HTTP_INPUT_PATH = path.join(TMP_HTTP_PATH,"input")
TMP_HTTP_OUTPUT_PATH = path.join(TMP_HTTP_PATH,"output")


TLS_PATH = path.join("utils","TLS")
TLS_MODEL_PATH = path.join(TLS_PATH,"model")

HTTP_PATH = path.join("utils","HTTP")
HTTP_MODEL_PATH = path.join(HTTP_PATH,"model")

SERVICE_HOST = "0.0.0.0"
SERVICE_PORT = 11110