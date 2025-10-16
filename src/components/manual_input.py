import dash
from dash import html, dcc
import joblib
from src.preprocessing import preprocess_features

model = joblib.load('models/model.joblib')
scaler = joblib.load('models/scaler.joblib')

def layout(feature_names):
    return html.Div([
        html.H2("Manual Network Feature Entry"),
        html.Div([
            html.Div([
                html.Label(name),
                dcc.Input(id=f'input-{name}', type='number', required=True)
            ]) for name in feature_names
        ]),
        html.Button("Predict", id="predict-btn"),
        html.Div(id="prediction-output")
    ])

def register_callbacks(app, feature_names):
    @app.callback(
        dash.dependencies.Output("prediction-output", "children"),
        [dash.dependencies.Input("predict-btn", "n_clicks")],
        [dash.dependencies.State(f"input-{name}", "value") for name in feature_names]
    )
    def predict_features(n_clicks, *values):
        if n_clicks:
            try:
                features = list(values)
                processed = preprocess_features(features, scaler)
                prediction = model.predict([processed])[0]
                msg = "Intrusion Detected" if prediction == 1 else "Normal Traffic"
                return html.Div(f"Prediction: {msg}")
            except Exception as e:
                return html.Div(f"Prediction error: {str(e)}")
        return ""
