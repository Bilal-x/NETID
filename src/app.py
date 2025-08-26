import dash
from dash import dcc, html, Input, Output, State
import pandas as pd
import joblib

# Load saved objects once
scaler = joblib.load('../models/scaler.joblib')
encoder = joblib.load('../models/encoder.joblib')
model = joblib.load('../models/model.joblib')

app = dash.Dash(__name__)

app.layout = html.Div([
    html.H2("NITD Real-Time Intrusion Detection"),
    
    dcc.Textarea(
        id='input-data',
        placeholder='Enter new network data record as CSV line...',
        style={'width': '100%', 'height': 100}
    ),
    
    html.Button('Detect Anomaly', id='detect-btn'),
    
    html.Div(id='output-prediction')
])

@app.callback(
    Output('output-prediction', 'children'),
    Input('detect-btn', 'n_clicks'),
    State('input-data', 'value')
)
def detect_intrusion(n_clicks, input_value):
    if not n_clicks or not input_value:
        return ''
    try:
        # Parse input CSV line into DataFrame
        raw_df = pd.DataFrame([input_value.split(',')], columns=[
            'duration','protocol_type','service','flag','src_bytes','dst_bytes','land',
            'wrong_fragment','urgent','hot','num_failed_logins','logged_in','num_compromised',
            'root_shell','su_attempted','num_root','num_file_creations','num_shells',
            'num_access_files','num_outbound_cmds','is_host_login','is_guest_login','count',
            'srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate',
            'same_srv_rate','diff_srv_rate','srv_diff_host_rate','dst_host_count',
            'dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
            'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate',
            'dst_host_srv_serror_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate',
        ])
        
        cat_cols = ['protocol_type', 'service', 'flag']
        raw_df[cat_cols] = encoder.transform(raw_df[cat_cols])
        
        numeric_cols = [col for col in raw_df.columns if col not in cat_cols + ['difficulty']]
        raw_df[numeric_cols] = scaler.transform(raw_df[numeric_cols])
        
        pred = model.predict(raw_df)
        
        return f"Prediction: {pred[0]}"
    except Exception as e:
        return f"Error processing input: {str(e)}"

if __name__ == '__main__':
    app.run(debug=True)
