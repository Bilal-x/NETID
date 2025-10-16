import dash
from dash import html
import threading
from src.realtime.packet_capture import start_live_capture

capture_thread = None

def layout():
    return html.Div([
        html.H2("Live Packet Monitor"),
        html.Button("Start Detection", id="start-btn"),
        html.Button("Stop Detection", id="stop-btn"),
        html.Div(id="live-monitor-output")
    ])

def register_callbacks(app):
    global capture_thread

    @app.callback(
        dash.dependencies.Output("live-monitor-output", "children"),
        [dash.dependencies.Input("start-btn", "n_clicks"),
         dash.dependencies.Input("stop-btn", "n_clicks")],
    )
    def control_capture(start_clicks, stop_clicks):
        global capture_thread
        changed_id = [p['prop_id'] for p in dash.callback_context.triggered][0]
        if "start-btn" in changed_id and not capture_thread:
            capture_thread = threading.Thread(target=start_live_capture, daemon=True)
            capture_thread.start()
            return "Packet capture started."
        if "stop-btn" in changed_id and capture_thread:
            # Stopping Scapy thread gracefully is non-trivial, user can Ctrl+C manually in fallback
            capture_thread = None
            return "Packet capture stopped. (May require manual Ctrl+C to fully halt sniffing)"
        return ""
