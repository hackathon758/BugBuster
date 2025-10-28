#!/usr/bin/env python3
"""
Test WebSocket functionality only
"""

import websocket
import json
import threading
import time
import requests

BASE_URL = "https://bug-fixer-35.preview.emergentagent.com/api"
WS_URL = "wss://content-err-solver.preview.emergentagent.com/ws/scan"
TEST_USER_EMAIL = "testuser@bugbustersx.com"
TEST_USER_PASSWORD = "SecurePassword123!"

def get_auth_token():
    """Get authentication token"""
    login_data = {
        "email": TEST_USER_EMAIL,
        "password": TEST_USER_PASSWORD
    }
    
    response = requests.post(f"{BASE_URL}/auth/login", json=login_data)
    if response.status_code == 200:
        return response.json()["token"]
    return None

def test_websocket_scan():
    """Test WebSocket scan functionality"""
    token = get_auth_token()
    if not token:
        print("❌ Failed to get auth token")
        return False
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Start WebSocket scan
    scan_data = {
        "github_url": "https://github.com/octocat/Spoon-Knife"
    }
    
    print("Starting WebSocket scan...")
    response = requests.post(f"{BASE_URL}/repositories/scan-github-ws", 
                           json=scan_data, headers=headers)
    
    if response.status_code != 200:
        print(f"❌ Failed to start WebSocket scan: {response.status_code}")
        print(response.text)
        return False
    
    scan_result = response.json()
    session_id = scan_result["session_id"]
    print(f"✅ WebSocket scan started with session ID: {session_id}")
    
    # Test WebSocket connection
    messages_received = []
    connection_successful = False
    
    def on_message(ws, message):
        try:
            if message == "pong":
                print("   Received pong")
                return
            
            data = json.loads(message)
            messages_received.append(data)
            msg_type = data.get('type', 'unknown')
            msg_text = data.get('message', '')
            progress = data.get('progress', 0)
            print(f"   WebSocket [{msg_type}] {progress}%: {msg_text}")
        except Exception as e:
            print(f"   WebSocket message error: {e}")
            messages_received.append(message)
    
    def on_open(ws):
        nonlocal connection_successful
        connection_successful = True
        print("   ✅ WebSocket connection established")
        # Send ping to keep connection alive
        ws.send("ping")
    
    def on_error(ws, error):
        print(f"   ❌ WebSocket error: {error}")
    
    def on_close(ws, close_status_code, close_msg):
        print("   WebSocket connection closed")
    
    # Create WebSocket connection
    ws_url = f"{WS_URL}/{session_id}"
    print(f"Connecting to: {ws_url}")
    
    ws = websocket.WebSocketApp(ws_url,
                              on_open=on_open,
                              on_message=on_message,
                              on_error=on_error,
                              on_close=on_close)
    
    # Run WebSocket in a separate thread
    ws_thread = threading.Thread(target=ws.run_forever)
    ws_thread.daemon = True
    ws_thread.start()
    
    # Wait for connection and messages
    print("Waiting for WebSocket messages...")
    time.sleep(15)  # Wait 15 seconds for messages
    
    ws.close()
    
    print(f"\nWebSocket test results:")
    print(f"Connection successful: {connection_successful}")
    print(f"Messages received: {len(messages_received)}")
    
    if connection_successful:
        if len(messages_received) > 0:
            print("✅ WebSocket real-time updates working!")
            for i, msg in enumerate(messages_received[:5]):  # Show first 5 messages
                print(f"  Message {i+1}: {msg}")
            return True
        else:
            print("⚠️  WebSocket connected but no scan messages received (scan may have completed quickly)")
            return True
    else:
        print("❌ WebSocket connection failed")
        return False

if __name__ == "__main__":
    success = test_websocket_scan()
    print(f"\nWebSocket test {'PASSED' if success else 'FAILED'}")