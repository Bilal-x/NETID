import dash
from dash import dcc, html, Input, Output, State
import pandas as pd
import joblib

# Load saved objects once
scaler = joblib.load('../models/scaler.joblib')
encoder = joblib.load('../models/encoder.joblib')
model = joblib.load('../models/model.joblib')

app = dash.Dash(__name__)

# Helper icons for output
CHECK_ICON = '✅'
WARNING_ICON = '⚠️'

dark_green_text = '#009900'
darker_green_bg = '#006600'
dark_background = '#0f0f0f'

# Define feature names in order
FEATURE_NAMES = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes','land',
    'wrong_fragment','urgent','hot','num_failed_logins','logged_in','num_compromised',
    'root_shell','su_attempted','num_root','num_file_creations','num_shells',
    'num_access_files','num_outbound_cmds','is_host_login','is_guest_login','count',
    'srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate',
    'same_srv_rate','diff_srv_rate','srv_diff_host_rate','dst_host_count',
    'dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate',
    'dst_host_srv_serror_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate',
]

app.layout = html.Div([
    html.H2("NITD Real-Time Intrusion Detection",
            style={'color': dark_green_text, 'font-family': 'Courier New, monospace', 'text-align': 'center', 'margin-bottom': '25px'}),
    
    # Input section with header and tooltip
    html.Div([
        html.Label("Enter network data record as CSV line:",
                   style={'color': dark_green_text, 'font-family': 'Courier New, monospace', 'font-size': '18px'}),
        html.Span(" (Format: duration,protocol_type,service,flag,src_bytes,dst_bytes,land,...)", 
                  title="Enter raw network traffic features as a single comma-separated CSV line. See project docs for full field list.",
                  style={'color': dark_green_text, 'font-family': 'Courier New, monospace', 'font-size': '12px', 'margin-left': '10px', 'cursor': 'help'}),
        dcc.Textarea(
            id='input-data',
            placeholder='e.g. 0,tcp,http,SF,54540,8314,0,0,0,2,0,1,1,0,0,0,0,0,0,0,0,0,2,2,0.00,0.00,0.00,0.00,1.00,0.00,0.00,176,176,1.00,0.00,0.01,0.00,0.00,0.00,0.01,0.01',
            style={
                'width': '100%',
                'height': 120,
                'backgroundColor': dark_background,
                'color': dark_green_text,
                'font-family': 'Courier New, monospace',
                'font-size': '16px',
                'border': f'2px solid {dark_green_text}',
                'border-radius': '5px',
                'padding': '10px',
                'resize': 'none'
            }
        ),
    ], style={'margin-bottom': '20px'}),
    
    # Buttons for detect and reset
    html.Div([
        html.Button('Detect Anomaly', id='detect-btn',
                    style={
                        'width': '48%',
                        'padding': '15px',
                        'backgroundColor': dark_green_text,
                        'color': dark_background,
                        'font-family': 'Courier New, monospace',
                        'font-weight': 'bold',
                        'font-size': '18px',
                        'border': 'none',
                        'border-radius': '5px',
                        'cursor': 'pointer',
                        'margin-right': '4%'
                    }),
        html.Button('Clear Input & Output', id='clear-btn',
                    style={
                        'width': '48%',
                        'padding': '15px',
                        'backgroundColor': '#550000',
                        'color': '#FF4444',
                        'font-family': 'Courier New, monospace',
                        'font-weight': 'bold',
                        'font-size': '18px',
                        'border': 'none',
                        'border-radius': '5px',
                        'cursor': 'pointer',
                    }),
    ], style={'margin-bottom': '30px', 'display': 'flex', 'justify-content': 'space-between'}),
    
    # Output area with icon and text
    html.Div(id='output-prediction', style={
        'font-family': 'Courier New, monospace',
        'font-size': '22px',
        'font-weight': 'bold',
        'text-align': 'center',
        'min-height': '40px',
        'height': '60px',
        'width': '100%',
        'overflow-wrap': 'break-word',
        'white-space': 'pre-wrap',
        'resize': 'none',
        'margin-top': '10px',
    }),
    
    # Anomaly reason container (hidden unless anomaly)
    html.Div(id='anomaly-reason', style={
        'font-family': 'Courier New, monospace',
        'font-size': '16px',
        'color': '#FF3333',
        'margin-top': '10px',
        'display': 'none',
    }),
    
    # Detailed input breakdown container
    html.Div(id='input-breakdown', style={
        'font-family': 'Courier New, monospace',
        'font-size': '14px',
        'color': dark_green_text,
        'backgroundColor': '#011400',
        'padding': '15px',
        'border-radius': '5px',
        'margin-top': '20px',
        'white-space': 'pre-wrap',
        'maxHeight': '300px',
        'overflowY': 'auto',
        'border': f'1px solid {dark_green_text}',
        'display': 'none'  # hidden initially
    }),
    
    # Loading spinner on detection
    dcc.Loading(
        id="loading-spinner",
        type="circle",
        fullscreen=False,
        children=html.Div(id="loading-output")
    ),
    
    # Background animation area (simple green matrix rain effect)
    html.Div(id='matrix-rain', style={
        'position': 'fixed', 'top': 0, 'left': 0, 'width': '100%', 'height': '100%', 
        'zIndex': '-1', 'pointerEvents': 'none'
    }),
], style={
    'backgroundColor': dark_background,
    'color': dark_green_text,
    'font-family': 'Courier New, monospace',
    'maxWidth': '800px',
    'margin': '40px auto',
    'padding': '30px',
    'border-radius': '10px',
    'box-shadow': f'0 0 20px {dark_green_text}'
})

@app.callback(
    [
        Output('input-data', 'value'),
        Output('output-prediction', 'children'),
        Output('output-prediction', 'style'),
        Output('anomaly-reason', 'children'),
        Output('anomaly-reason', 'style'),
        Output('input-breakdown', 'children'),
        Output('input-breakdown', 'style'),
    ],
    [
        Input('detect-btn', 'n_clicks'),
        Input('clear-btn', 'n_clicks')
    ],
    State('input-data', 'value')
)
def handle_buttons(detect_clicks, clear_clicks, input_value):
    ctx = dash.callback_context

    if not ctx.triggered:
        return dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update

    button_id = ctx.triggered[0]['prop_id'].split('.')[0]

    if button_id == 'clear-btn':
        # Clear all outputs
        return '', '', {}, '', {'display': 'none'}, '', {'display': 'none'}

    if button_id == 'detect-btn':

        if not input_value or input_value.strip() == '':

            alert_msg = "⚠️ Please enter valid network data values before detecting anomaly."
            return dash.no_update, alert_msg, {'color': '#FF3333', 'font-family': 'Courier New, monospace', 'font-weight': 'bold'}, '', {'display': 'none'}, '', {'display': 'none'}


        try:
            # Parse and validate input values count
            input_values = input_value.split(',')
            if len(input_values) != len(FEATURE_NAMES):
                error_msg = f"⚠️ Error: Expected {len(FEATURE_NAMES)} features but got {len(input_values)}."
                return dash.no_update, error_msg, {'color': '#FF3333'}, '', {'display': 'none'}, '', {'display': 'none'}

            # Prepare DataFrame for model input
            raw_df = pd.DataFrame([input_values], columns=FEATURE_NAMES)

            cat_cols = ['protocol_type', 'service', 'flag']
            raw_df[cat_cols] = encoder.transform(raw_df[cat_cols])

            numeric_cols = [col for col in raw_df.columns if col not in cat_cols + ['difficulty']]
            raw_df[numeric_cols] = scaler.transform(raw_df[numeric_cols])

            pred = model.predict(raw_df)

            # Prediction output styling and icon
            if pred[0] == 'normal':
                pred_style = {
                    'color': '#006600',
                    'font-family': 'Courier New, monospace',
                    'font-weight': 'bold',
                    'text-shadow': '0 0 4px #006600'
                }
                icon = CHECK_ICON
                anomaly_reason = ''
                anomaly_style = {'display': 'none'}
            else:
                pred_style = {
                    'color': '#FF3333',
                    'font-family': 'Courier New, monospace',
                    'font-weight': 'bold',
                    'text-shadow': '0 0 10px #FF0000'
                }
                icon = WARNING_ICON
                anomaly_reason = "Anomaly detected: Network behavior deviates from normal patterns."
                anomaly_style = {'color': '#FF3333', 'marginTop': '10px', 'font-family': 'Courier New, monospace', 'font-weight': 'bold', 'display': 'block'}

            # Build detailed input breakdown message
            breakdown_lines = [f"{name}: {value}" for name, value in zip(FEATURE_NAMES, input_values)]
            breakdown_text = "\n".join(breakdown_lines)
            breakdown_style = {
                'font-family': 'Courier New, monospace',
                'font-size': '14px',
                'color': dark_green_text,
                'backgroundColor': '#011400',
                'padding': '15px',
                'border-radius': '5px',
                'margin-top': '20px',
                'white-space': 'pre-wrap',
                'maxHeight': '300px',
                'overflowY': 'auto',
                'border': f'1px solid {dark_green_text}',
                'display': 'block'
            }

            return dash.no_update, f"{icon} Prediction: {pred[0]}", pred_style, anomaly_reason, anomaly_style, breakdown_text, breakdown_style

        except Exception as e:
            error_msg = f"⚠️ Error processing input: {str(e)}"
            return dash.no_update, error_msg, {'color': '#FF3333', 'font-family': 'Courier New, monospace'}, '', {'display': 'none'}, '', {'display': 'none'}

    return dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update

# Matrix rain effect via clientside callback
app.clientside_callback(
    """
    function(n) {
        if (!window.matrixStarted) {
            window.matrixStarted = true;
            let canvas = document.createElement('canvas');
            canvas.style.position = 'fixed';
            canvas.style.top = '0';
            canvas.style.left = '0';
            canvas.style.width = '100%';
            canvas.style.height = '100%';
            canvas.style.zIndex = '-1';
            canvas.style.pointerEvents = 'none';
            document.body.appendChild(canvas);
            let ctx = canvas.getContext('2d');
            let width, height;
            let columns;
            let drops = [];

            function resize() {
                width = window.innerWidth;
                height = window.innerHeight;
                canvas.width = width;
                canvas.height = height;
                columns = Math.floor(width / 20);
                drops = new Array(columns).fill(1);
            }

            function draw() {
                ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
                ctx.fillRect(0, 0, width, height);
                ctx.fillStyle = '#004400';
                ctx.font = '20px Courier New';
                for (let i = 0; i < drops.length; i++) {
                    let text = String.fromCharCode(33 + Math.random() * 94);
                    ctx.fillText(text, i * 20, drops[i] * 20);
                    if (drops[i] * 20 > height && Math.random() > 0.975) {
                        drops[i] = 0;
                    }
                    drops[i]++;
                }
            }

            window.addEventListener('resize', resize);
            resize();
            setInterval(draw, 45);
        }
        return '';
    }
    """,
    Output('matrix-rain', 'children'),
    Input('input-data', 'value')
)

if __name__ == '__main__':
    app.run(debug=True)
