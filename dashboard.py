
import os
from pathlib import Path
from datetime import datetime, timedelta, timezone

import boto3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from botocore.exceptions import BotoCoreError, ClientError

# -------------------------------------------------------
# CloudGuard Command Center
# -------------------------------------------------------
REGION = "ap-southeast-2"
NAMESPACE = "CloudGuard"
TABLE_NAME = "CloudGuardIncidents"
REPORT_DIR = Path("/opt/cloudguard/reports")
HEALTH_FILE = REPORT_DIR / "health_checks.csv"
INCIDENT_FILE = REPORT_DIR / "incidents.csv"

SITES = ["store", "restaurant", "clinic"]
COLORS = {
    "HEALTHY": "#16a34a",
    "DOWN": "#dc2626",
    "RECOVERED": "#0891b2",
    "UNKNOWN": "#64748b",
}

st.set_page_config(
    page_title="CloudGuard | Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .stApp {
        background: linear-gradient(145deg, #08111f 0%, #0c1728 60%, #101c30 100%);
        color: #e5edf8;
    }
    [data-testid="stSidebar"] {
        background: #0a1322;
        border-right: 1px solid #24334a;
    }
    [data-testid="stMetric"] {
        background: rgba(21, 36, 57, 0.82);
        border: 1px solid #2b3e59;
        border-radius: 14px;
        padding: 16px 18px;
    }
    [data-testid="stMetricLabel"] {
        color: #a8bad2;
    }
    [data-testid="stMetricValue"] {
        color: #f3f7fc;
    }
    .hero {
        padding: 24px 26px;
        border-radius: 18px;
        border: 1px solid #2c4563;
        background: linear-gradient(115deg, #132b46, #142239 70%, #1c2440);
        margin-bottom: 20px;
    }
    .hero h1 { margin: 0; color: #f8fbff; }
    .hero p { color: #b7c8df; margin-bottom: 0; }
    .section-title {
        font-size: 1.15rem;
        font-weight: 700;
        margin: 12px 0 8px 0;
    }
    .site-card {
        background: rgba(20, 35, 55, .92);
        border: 1px solid #2b3e59;
        border-radius: 14px;
        padding: 18px;
        min-height: 145px;
    }
    .muted { color: #a8bad2; font-size: .88rem; }
    .status { font-weight: 750; font-size: 1.35rem; }
    div[data-testid="stDataFrame"] {
        border: 1px solid #293d57;
        border-radius: 10px;
        overflow: hidden;
    }
    .stButton button {
        border-radius: 9px;
        border: 1px solid #355477;
    }
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def get_aws_clients():
    session = boto3.Session(region_name=REGION)
    return (
        session.client("cloudwatch"),
        session.client("dynamodb"),
        session.resource("dynamodb").Table(TABLE_NAME),
    )


def empty_health():
    return pd.DataFrame(columns=[
        "timestamp_utc", "website", "url", "status_code",
        "response_ms", "healthy", "error"
    ])


def read_csv(path, required_columns):
    try:
        if not path.exists() or path.stat().st_size == 0:
            return pd.DataFrame(columns=required_columns)
        frame = pd.read_csv(path)
        for col in required_columns:
            if col not in frame.columns:
                frame[col] = None
        return frame
    except (OSError, pd.errors.ParserError, UnicodeDecodeError):
        return pd.DataFrame(columns=required_columns)


@st.cache_data(ttl=15)
def load_health():
    df = read_csv(HEALTH_FILE, list(empty_health().columns))
    if df.empty:
        return empty_health()

    df["timestamp_utc"] = pd.to_datetime(
        df["timestamp_utc"], utc=True, errors="coerce"
    )
    df["website"] = df["website"].astype(str).str.lower()
    df["response_ms"] = pd.to_numeric(df["response_ms"], errors="coerce")
    df["healthy"] = (
        df["healthy"].astype(str).str.lower().isin(["true", "1", "yes"])
    )
    df["status_code"] = df["status_code"].astype(str)
    return df.dropna(subset=["timestamp_utc"]).sort_values("timestamp_utc")


@st.cache_data(ttl=30)
def load_incidents():
    """Prefer DynamoDB; fall back to the local incident CSV."""
    try:
        _, _, table = get_aws_clients()
        items = []
        response = table.scan()
        items.extend(response.get("Items", []))

        while response.get("LastEvaluatedKey"):
            response = table.scan(
                ExclusiveStartKey=response["LastEvaluatedKey"]
            )
            items.extend(response.get("Items", []))

        df = pd.DataFrame(items)
        if not df.empty:
            df = df[~df["event"].astype(str).str.upper().eq("TEST")]
            for col in [
                "timestamp_utc", "website", "event",
                "status_code", "response_ms", "error"
            ]:
                if col not in df.columns:
                    df[col] = ""
            df["timestamp_utc"] = pd.to_datetime(
                df["timestamp_utc"], utc=True, errors="coerce"
            )
            df["website"] = df["website"].astype(str).str.lower()
            df["event"] = df["event"].astype(str).str.upper()
            df["response_ms"] = pd.to_numeric(
                df["response_ms"], errors="coerce"
            )
            return df.dropna(subset=["timestamp_utc"]).sort_values(
                "timestamp_utc", ascending=False
            ), "DynamoDB"

    except (BotoCoreError, ClientError, KeyError, ValueError) as exc:
        error_message = str(exc)
    else:
        error_message = "DynamoDB has no incident records yet."

    df = read_csv(
        INCIDENT_FILE,
        ["timestamp_utc", "website", "event", "status_code",
         "response_ms", "error"]
    )
    if not df.empty:
        df["timestamp_utc"] = pd.to_datetime(
            df["timestamp_utc"], utc=True, errors="coerce"
        )
        df["website"] = df["website"].astype(str).str.lower()
        df["event"] = df["event"].astype(str).str.upper()
        df["response_ms"] = pd.to_numeric(
            df["response_ms"], errors="coerce"
        )
        df = df.dropna(subset=["timestamp_utc"]).sort_values(
            "timestamp_utc", ascending=False
        )
    return df, f"CSV fallback — {error_message}"


def latest_status(df, site):
    site_df = df[df["website"] == site]
    if site_df.empty:
        return "UNKNOWN", None, None

    latest = site_df.iloc[-1]
    checked_at = latest["timestamp_utc"]
    age = (pd.Timestamp.now(tz="UTC") - checked_at).total_seconds()

    # Don't present old health checks as live status.
    if age > 180:
        return "STALE", latest["response_ms"], checked_at

    return (
        "HEALTHY" if bool(latest["healthy"]) else "DOWN",
        latest["response_ms"],
        checked_at,
    )


def get_alarm_data():
    try:
        cw, _, _ = get_aws_clients()
        alarms = []
        response = cw.describe_alarms(MaxRecords=100)
        alarms.extend(response.get("MetricAlarms", []))
        while response.get("NextToken"):
            response = cw.describe_alarms(
                MaxRecords=100, NextToken=response["NextToken"]
            )
            alarms.extend(response.get("MetricAlarms", []))
        alarms = [
            a for a in alarms
            if a.get("AlarmName", "").startswith("CloudGuard-")
        ]
        return alarms, None
    except (BotoCoreError, ClientError) as exc:
        return [], str(exc)


def get_metric(site, metric_name, hours=24):
    try:
        cw, _, _ = get_aws_clients()
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=hours)
        response = cw.get_metric_statistics(
            Namespace=NAMESPACE,
            MetricName=metric_name,
            Dimensions=[{"Name": "Website", "Value": site}],
            StartTime=start,
            EndTime=end,
            Period=300 if hours <= 24 else 3600,
            Statistics=["Average", "Minimum", "Maximum"],
        )
        points = response.get("Datapoints", [])
        if not points:
            return pd.DataFrame(columns=["time", "value"])
        return pd.DataFrame([
            {"time": p["Timestamp"], "value": p["Average"]}
            for p in points
        ]).sort_values("time")
    except (BotoCoreError, ClientError):
        return pd.DataFrame(columns=["time", "value"])


# -------------------------------------------------------
# Sidebar and data
# -------------------------------------------------------
with st.sidebar:
    st.markdown("## 🛡️ CloudGuard")
    st.caption("COMMAND CENTER")
    page = st.radio(
        "NAVIGATION",
        ["Overview", "Analytics", "Incident Explorer", "AWS Alarms"],
        index=0,
    )
    st.divider()
    refresh_seconds = st.selectbox(
        "Auto-refresh interval",
        [15, 30, 60, 120],
        index=1,
        format_func=lambda x: f"{x} seconds",
    )
    if st.button("↻ Refresh data", use_container_width=True):
        st.cache_data.clear()
        st.rerun()
    st.caption(f"AWS region: `{REGION}`")
    st.caption("Read-only monitoring dashboard")

st.markdown("""
<div class="hero">
  <h1>🛡️ CloudGuard Command Center</h1>
  <p>Website reliability · Incident intelligence · AWS observability</p>
</div>
""", unsafe_allow_html=True)

health = load_health()
incidents, incident_source = load_incidents()
alarms, alarm_error = get_alarm_data()

if health.empty:
    st.warning(
        "No health-check history was found yet. Confirm that "
        "/opt/cloudguard/reports/health_checks.csv exists and contains data."
    )

# Time range and site filters
with st.container():
    f1, f2 = st.columns([2, 2])
    with f1:
        selected_sites = st.multiselect(
            "Websites",
            SITES,
            default=SITES,
            help="Filter charts and incident records by website.",
        )
    with f2:
        range_label = st.selectbox(
            "Time range",
            ["Last 1 hour", "Last 6 hours", "Last 24 hours", "Last 7 days"],
            index=2,
        )

hours_map = {
    "Last 1 hour": 1,
    "Last 6 hours": 6,
    "Last 24 hours": 24,
    "Last 7 days": 168,
}
selected_hours = hours_map[range_label]
cutoff = pd.Timestamp.now(tz="UTC") - pd.Timedelta(hours=selected_hours)

filtered_health = health[
    health["website"].isin(selected_sites)
    & (health["timestamp_utc"] >= cutoff)
].copy()

filtered_incidents = incidents[
    incidents["website"].isin(selected_sites)
    & (incidents["timestamp_utc"] >= cutoff)
].copy() if not incidents.empty else incidents.copy()

# Global KPI values
if not filtered_health.empty:
    uptime_pct = filtered_health["healthy"].mean() * 100
    avg_response = filtered_health["response_ms"].mean()
    checks = len(filtered_health)
    failed_checks = int((~filtered_health["healthy"]).sum())
else:
    uptime_pct, avg_response, checks, failed_checks = 0, None, 0, 0

down_count = (
    int((filtered_incidents["event"] == "DOWN").sum())
    if not filtered_incidents.empty else 0
)
recovered_count = (
    int((filtered_incidents["event"] == "RECOVERED").sum())
    if not filtered_incidents.empty else 0
)

if page == "Overview":
    st.markdown("### System overview")
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Observed availability", f"{uptime_pct:.2f}%",
              help="Healthy checks divided by checks in the selected range.")
    k2.metric("Average response", 
              f"{avg_response:.1f} ms" if pd.notna(avg_response) else "—")
    k3.metric("Health checks", f"{checks:,}")
    k4.metric("DOWN events", f"{down_count:,}")

    st.markdown("### Website status")
    cols = st.columns(3)
    for col, site in zip(cols, SITES):
        with col:
            status, response_ms, checked_at = latest_status(health, site)
            color = COLORS.get(status, "#d97706")
            response_text = (
                f"{response_ms:.1f} ms"
                if response_ms is not None and pd.notna(response_ms)
                else "No data"
            )
            time_text = (
                checked_at.strftime("%d %b %H:%M:%S UTC")
                if checked_at is not None else "No check recorded"
            )
            st.markdown(f"""
            <div class="site-card">
              <div class="muted">MONITORED ENDPOINT</div>
              <h3>{site.title()}</h3>
              <div class="status" style="color:{color}">● {status}</div>
              <p>Response: <b>{response_text}</b></p>
              <div class="muted">Last check: {time_text}</div>
            </div>
            """, unsafe_allow_html=True)

    left, right = st.columns([1.6, 1])
    with left:
        st.markdown("### Response-time trend")
        if not filtered_health.empty:
            fig = px.line(
                filtered_health,
                x="timestamp_utc",
                y="response_ms",
                color="website",
                markers=False,
                labels={
                    "timestamp_utc": "Time (UTC)",
                    "response_ms": "Response (ms)",
                    "website": "Website",
                },
                template="plotly_dark",
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                legend_title_text="",
                margin=dict(l=10, r=10, t=15, b=10),
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No checks match these filters.")

    with right:
        st.markdown("### Check outcomes")
        if not filtered_health.empty:
            outcomes = (
                filtered_health.assign(
                    outcome=filtered_health["healthy"].map(
                        {True: "Healthy", False: "Failed"}
                    )
                ).groupby(["website", "outcome"]).size()
                .reset_index(name="checks")
            )
            fig = px.bar(
                outcomes,
                x="website",
                y="checks",
                color="outcome",
                barmode="stack",
                template="plotly_dark",
                color_discrete_map={"Healthy": "#16a34a", "Failed": "#dc2626"},
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                margin=dict(l=5, r=5, t=15, b=5),
                legend_title_text="",
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No check data available.")

    st.markdown("### Recent incidents")
    if filtered_incidents.empty:
        st.info("No incidents in this time range.")
    else:
        show_cols = [
            c for c in [
                "timestamp_utc", "website", "event",
                "status_code", "response_ms", "error"
            ] if c in filtered_incidents.columns
        ]
        st.dataframe(
            filtered_incidents[show_cols].head(10),
            use_container_width=True,
            hide_index=True,
        )

elif page == "Analytics":
    st.markdown("### Reliability analytics")
    st.caption(
        "Metrics are based on observed checks; missing checks are not "
        "automatically counted as downtime."
    )
    if not filtered_health.empty:
        a, b = st.columns(2)
        with a:
            fig = px.line(
                filtered_health,
                x="timestamp_utc",
                y="response_ms",
                color="website",
                title="Response time",
                template="plotly_dark",
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
            )
            st.plotly_chart(fig, use_container_width=True)
        with b:
            availability = (
                filtered_health.groupby("website")["healthy"]
                .mean().mul(100).reset_index(name="availability_pct")
            )
            fig = px.bar(
                availability,
                x="website",
                y="availability_pct",
                color="website",
                range_y=[0, 100],
                title="Observed availability by website",
                template="plotly_dark",
                text_auto=".2f",
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                showlegend=False,
            )
            st.plotly_chart(fig, use_container_width=True)

        st.markdown("### Website comparison")
        summary = filtered_health.groupby("website").agg(
            total_checks=("healthy", "size"),
            healthy_checks=("healthy", "sum"),
            avg_response_ms=("response_ms", "mean"),
            max_response_ms=("response_ms", "max"),
        ).reset_index()
        summary["observed_availability_pct"] = (
            summary["healthy_checks"] / summary["total_checks"] * 100
        ).round(2)
        st.dataframe(summary, use_container_width=True, hide_index=True)
    else:
        st.info("No health-check data matches the selected filters.")

    st.markdown("### CloudWatch response-time metrics")
    site_choice = st.selectbox(
        "CloudWatch website",
        selected_sites if selected_sites else SITES,
    )
    cw_hours = st.selectbox("CloudWatch window", [1, 6, 24, 168], index=2,
                            format_func=lambda x: f"Last {x} hour(s)")
    metric_df = get_metric(site_choice, "ResponseTime", cw_hours)
    if not metric_df.empty:
        fig = px.line(
            metric_df, x="time", y="value", markers=True,
            labels={"time": "Time", "value": "Response (ms)"},
            title=f"CloudWatch — {site_choice.title()}",
            template="plotly_dark",
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No CloudWatch datapoints available for this window yet.")

elif page == "Incident Explorer":
    st.markdown("### Incident explorer")
    st.caption(f"Incident source: {incident_source}")

    if not filtered_incidents.empty:
        f1, f2 = st.columns(2)
        with f1:
            event_options = sorted(
                filtered_incidents["event"].dropna().unique().tolist()
            )
            selected_events = st.multiselect(
                "Incident event",
                event_options,
                default=event_options,
            )
        with f2:
            search = st.text_input(
                "Search incidents",
                placeholder="Search website, event or error text...",
            )

        view = filtered_incidents[
            filtered_incidents["event"].isin(selected_events)
        ].copy()
        if search:
            text_columns = [
                c for c in ["website", "event", "error", "status_code"]
                if c in view.columns
            ]
            mask = view[text_columns].fillna("").astype(str).apply(
                lambda col: col.str.contains(search, case=False, regex=False)
            ).any(axis=1)
            view = view[mask]

        display_columns = [
            c for c in [
                "timestamp_utc", "website", "event",
                "status_code", "response_ms", "error"
            ] if c in view.columns
        ]
        st.dataframe(
            view[display_columns],
            use_container_width=True,
            hide_index=True,
        )
        st.download_button(
            "⬇ Download filtered incidents as CSV",
            data=view[display_columns].to_csv(index=False).encode("utf-8"),
            file_name="cloudguard_incidents.csv",
            mime="text/csv",
        )
        st.metric("Incidents in view", len(view))
    else:
        st.info("No incidents in this time range. Test records marked TEST are hidden.")

elif page == "AWS Alarms":
    st.markdown("### AWS CloudWatch alarms")
    if alarm_error:
        st.error(f"Could not retrieve CloudWatch alarms: {alarm_error}")
    elif not alarms:
        st.info("No CloudGuard alarms returned by CloudWatch.")
    else:
        alarm_frame = pd.DataFrame([
            {
                "Alarm": a.get("AlarmName", ""),
                "State": a.get("StateValue", "UNKNOWN"),
                "Reason": a.get("StateReason", ""),
                "Updated (UTC)": a.get("StateUpdatedTimestamp"),
                "Actions enabled": a.get("ActionsEnabled", False),
            }
            for a in alarms
        ])
        st.dataframe(alarm_frame, use_container_width=True, hide_index=True)

        state_counts = alarm_frame["State"].value_counts().reset_index()
        state_counts.columns = ["State", "Count"]
        fig = px.pie(
            state_counts,
            names="State",
            values="Count",
            hole=0.55,
            title="Alarm state distribution",
            template="plotly_dark",
        )
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("### Data source status")
    st.write(f"**Incident history:** {incident_source}")
    st.write(
        "**Local health CSV:** "
        + ("Available" if HEALTH_FILE.exists() else "Missing")
    )
    st.write(
        "**Local incident CSV:** "
        + ("Available" if INCIDENT_FILE.exists() else "Missing")
    )
    if alarm_error:
        st.warning("CloudWatch alarm data could not be loaded; check IAM permissions.")

st.divider()
st.caption(
    f"CloudGuard Command Center · Region {REGION} · "
    f"Dashboard refreshes data on rerun · "
    f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
)

# Optional automatic rerun; data caches expire independently.
st.markdown(
    f'<meta http-equiv="refresh" content="{refresh_seconds}">',
    unsafe_allow_html=True,
)
