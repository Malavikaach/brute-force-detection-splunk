
import streamlit as st
import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).parent
LOG_FILE = BASE_DIR / "login_logs.csv"

THRESHOLD = 5
WINDOW_MINUTES = 5

st.set_page_config(
    page_title="Security Monitoring Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Security Monitoring Dashboard")
st.caption("Brute-Force Detection | Mini SOC Project")

if st.button("Refresh login data"):
    st.rerun()

if not LOG_FILE.exists():
    st.error("login_logs.csv was not found.")
    st.stop()

df = pd.read_csv(LOG_FILE)
required = {"timestamp", "ip_address", "username", "status"}

if not required.issubset(df.columns):
    st.error("CSV is missing required columns.")
    st.stop()

df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
df["ip_address"] = df["ip_address"].astype(str).str.strip()
df["username"] = df["username"].astype(str).str.strip()
df["status"] = df["status"].astype(str).str.strip().str.upper()

df = df.dropna(subset=["timestamp"])
df = df.sort_values("timestamp").reset_index(drop=True)

failed = df[df["status"] == "FAILED"].copy()
successful = df[df["status"] == "SUCCESS"].copy()

# Apply the same five-minute rule as the detection engine
alerts = []

for ip, group in failed.groupby("ip_address"):
    times = group["timestamp"].sort_values().tolist()
    left = 0

    for right, current_time in enumerate(times):
        while (current_time - times[left]).total_seconds() > WINDOW_MINUTES * 60:
            left += 1

        count = right - left + 1

        if count >= THRESHOLD:
            alerts.append({
                "IP Address": ip,
                "Failed Attempts": count,
                "Window Start": times[left],
                "Window End": current_time,
                "Risk": "HIGH"
            })
            break

alerts_df = pd.DataFrame(alerts)

st.subheader("Overview")
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Login Events", len(df))
c2.metric("Successful Logins", len(successful))
c3.metric("Failed Logins", len(failed))
c4.metric("High-Risk IPs", len(alerts_df))

st.divider()

st.subheader("Failed Login Attempts by IP")
if failed.empty:
    st.info("No failed login events found.")
else:
    chart = (
        failed.groupby("ip_address")
        .size()
        .reset_index(name="Failed Attempts")
        .sort_values("Failed Attempts", ascending=False)
        .set_index("ip_address")
    )
    st.bar_chart(chart)

st.subheader("Five-Minute Detection Alerts")
if alerts_df.empty:
    st.success("No five-minute threshold breaches detected.")
else:
    st.dataframe(alerts_df, use_container_width=True)

    for _, alert in alerts_df.iterrows():
        st.error(
            f"HIGH RISK: {alert['IP Address']} recorded "
            f"{alert['Failed Attempts']} failures within "
            f"{WINDOW_MINUTES} minutes."
        )

st.subheader("Filter Login Events")
ip_options = ["All"] + sorted(df["ip_address"].unique().tolist())
status_options = ["All"] + sorted(df["status"].unique().tolist())

f1, f2 = st.columns(2)
selected_ip = f1.selectbox("Filter by IP address", ip_options)
selected_status = f2.selectbox("Filter by status", status_options)

filtered = df.copy()

if selected_ip != "All":
    filtered = filtered[filtered["ip_address"] == selected_ip]

if selected_status != "All":
    filtered = filtered[filtered["status"] == selected_status]

st.dataframe(
    filtered.sort_values("timestamp", ascending=False),
    use_container_width=True
)

st.caption(
    "Demo uses simulated login events. Alerts are based on five or more "
    "failed attempts from one IP within a five-minute window."
)

# Previous Alert History
st.divider()
st.subheader("Alert History")

HISTORY_FILE = BASE_DIR / "alert_history.csv"

if HISTORY_FILE.exists():
    try:
        history = pd.read_csv(HISTORY_FILE)

        if history.empty:
            st.info("No previous alerts recorded yet.")
        else:
            st.dataframe(
                history.sort_values(
                    "detected_at", ascending=False
                ),
                use_container_width=True
            )

            st.download_button(
                label="Download Alert History",
                data=history.to_csv(index=False),
                file_name="alert_history.csv",
                mime="text/csv"
            )
    except (pd.errors.EmptyDataError, pd.errors.ParserError):
        st.warning("The alert history file could not be read.")
else:
    st.info("Alert history file has not been created yet.")

