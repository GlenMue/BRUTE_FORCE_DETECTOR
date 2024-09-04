from fastapi import FastAPI
import pandas as pd
from sklearn.ensemble import IsolationForest
from fastapi.middleware.cors import CORSMiddleware

# Load and preprocess the data
def load_and_preprocess():
    df = pd.read_csv("train.csv")
    df = df.drop(['No.'], axis=1)
    df = df[df['Protocol'] == 'HTTP']

    df1 = pd.read_csv("test.csv")
    df1 = df1.drop(['No.'], axis=1)
    df1 = df1[df1['Protocol'] == 'HTTP']

    def assign_numbers(ip_addresses):
        prev_ip = None
        prev_num = 0
        output = []
        for ip in ip_addresses:
            if prev_ip is None:
                prev_ip = ip
                output.append(prev_num)
            elif prev_ip != ip:
                prev_ip = ip
                prev_num = 1 - prev_num  # Toggle between 0 and 1
                output.append(prev_num)
            else:
                output.append(prev_num)
        return output

    # Apply the function to relevant columns
    list_a = df['Source'].tolist()
    list_b = df['Destination'].tolist()
    list_c = df['Length'].tolist()
    info1 = df['Info'].tolist()
    df['SLabel'] = assign_numbers(list_a)
    df['DLabel'] = assign_numbers(list_b)
    df['LLabel'] = assign_numbers(list_c)
    df['Infoo'] = assign_numbers(info1)
    df = df.drop(['Source', 'Destination', 'Protocol', 'Info', 'Length'], axis=1)

    list_a1 = df1['Source'].tolist()
    list_b1 = df1['Destination'].tolist()
    list_c1 = df1['Length'].tolist()
    info11 = df1['Info'].tolist()
    df2=df1
    df1['SLabel'] = assign_numbers(list_a1)
    df1['DLabel'] = assign_numbers(list_b1)
    df1['LLabel'] = assign_numbers(list_c1)
    df1['Infoo'] = assign_numbers(info11)
    df1 = df1.drop(['Source', 'Destination', 'Protocol', 'Info', 'Length'], axis=1)

    return df, df1, df2

# Create and train the model
def train_model(df):
    model = IsolationForest(n_estimators=100, contamination=float(0.2), random_state=42)
    model.fit(df)
    return model

# Check for anomalies and count them
def check_negatives(lst):
    count = 0
    # list all the anomalies
    df1= pd.read_csv("test.csv")
    anomalies = df1[lst == -1]
    for i, num in enumerate(lst):
        if num == -1:
            count += 1
    return count, anomalies

# Generate the dashboard data dynamically
def generate_dashboard_data(model, df1, df2):
    
    # anomalies = df1[pred == -1]


    pred = model.predict(df1)
    brute_force_attacks, anomalies = check_negatives(pred)
    brute_force_increase = None
    blocked_ips = anomalies['Source'].nunique()  # Number of unique IP addresses blocked
    blocked_ips_increase = None

    recent_attacks = []

    # Calculate recent attacks from the test data
    source_ips = df2['Source'].tolist()
    dest_ips = df2['Destination'].tolist()
    lengths = df2['Length'].tolist()
    times = df2['Time'].tolist()
    
    for i, (src, dst, length, time) in enumerate(zip(source_ips, dest_ips, lengths, times)):
        if pred[i] == -1:  # If this is an anomaly
            recent_attacks.append({
                "ip_address":src,  # Assuming Source is included in original test.csv
                "attempts": length,  # Number of attempts can be represented by length here
                "timestamp": time,  # Assuming Time is included in original test.csv
                "status": "Blocked"  # Status could be blocked if detected as anomaly
            })

    # If any of the metrics have calculated values, include them in the dashboard
    dashboard={}
    dashboard["dashboard"] ={
                "brute_force_attacks": brute_force_attacks,
                "brute_force_increase": brute_force_increase,
                "blocked_ips": blocked_ips,
                "blocked_ips_increase": blocked_ips_increase,
            }
    
    if recent_attacks:
        dashboard["recent_attacks"] = recent_attacks

    return {"dashboard": dashboard}

# FastAPI app
app = FastAPI()

# add cors
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/network-security-dashboard")
async def network_security_dashboard():
    df, df1, df2 = load_and_preprocess()
    model = train_model(df)
    dashboard_data = generate_dashboard_data(model, df1, df2)
    return dashboard_data

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
