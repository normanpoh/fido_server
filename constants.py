NGROK_UUID = "afaadfaa985b"  # replace with your ngrok uuid

# Server configuration
RP_ID = f"{NGROK_UUID}.ngrok-free.app"  # can be "localhost"
RP_NAME = "FIDO Demo Server"
ORIGIN = f"https://{NGROK_UUID}.ngrok-free.app"  # can be "http://localhost:8000" but must use https for testing

H5_FILE = "fido_server_data.h5"
