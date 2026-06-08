import json
import os
import joblib
import pandas as pd
import shap

def test_shap_shapes():
    features_path = os.path.join(os.getcwd(), 'data', 'processed', 'selected_features.json')
    with open(features_path, 'r') as f:
        selected_features = json.load(f)
        
    test_path = os.path.join(os.getcwd(), 'data', 'processed', 'test_processed.csv')
    test_df = pd.read_csv(test_path).head(10) # solo 10 muestras
    X_test = test_df[selected_features]
    
    model = joblib.load('models/lightgbm_ids_model.pkl')
    explainer = shap.TreeExplainer(model)
    
    shap_values = explainer.shap_values(X_test)
    
    print("Type of shap_values:", type(shap_values))
    if isinstance(shap_values, list):
        print("Length of list:", len(shap_values))
        print("Shape of first element:", shap_values[0].shape)
    else:
        print("Shape of array:", shap_values.shape)
        
    expected = explainer.expected_value
    print("Type of expected_value:", type(expected))
    if isinstance(expected, list):
        print("Length of expected list:", len(expected))
        print("First expected value:", expected[0])
    else:
        print("Shape of expected array:", getattr(expected, 'shape', 'No shape'))
        print("Expected value:", expected)

if __name__ == '__main__':
    test_shap_shapes()
