import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st


DATA_DIR = Path(__file__).resolve().parent / "data"

st.set_page_config(
    page_title="AWS DriftWatch",
    page_icon="☁️",
    layout="wide",
)

st.title("☁️ AWS DriftWatch")
st.caption("AWS configuration monitoring • Read-only security-group snapshots")


def load_reports():
    reports = []
    errors = []

    for path in sorted(DATA_DIR.glob("security-groups-*.json"), reverse=True):
        try:
            report = json.loads(path.read_text(encoding="utf-8"))

            if report.get("schema_version") != 1:
                raise ValueError("Unsupported report version")
            if report.get("status") != "COMPLETE":
                raise ValueError("Report is not complete")

            for key in ("account_id", "region", "scanned_at", "inventory", "findings"):
                if key not in report:
                    raise ValueError(f"Missing field: {key}")

            if not isinstance(report["inventory"], list):
                raise ValueError("Inventory must be a list")
            if not isinstance(report["findings"], list):
                raise ValueError("Findings must be a list")

            scanned_at = datetime.fromisoformat(report["scanned_at"])
            if scanned_at.tzinfo is None:
                raise ValueError("Scan timestamp must include a timezone")

            for item in report["inventory"]:
                if not isinstance(item.get("configuration"), dict):
                    raise ValueError("Invalid security-group configuration")
                if "GroupId" not in item["configuration"]:
                    raise ValueError("Security-group ID is missing")

            reports.append((path, report))
        except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
            errors.append(f"{path.name}: {error}")

    reports.sort(
        key=lambda item: datetime.fromisoformat(item[1]["scanned_at"]),
        reverse=True,
    )
    return reports, errors


if st.sidebar.button("Reload saved reports"):
    st.rerun()

reports, errors = load_reports()

if errors:
    st.warning(
        f"{len(errors)} report(s) could not be loaded. "
        "The displayed results exclude these files."
    )
    with st.expander("Report loading errors"):
        for error in errors:
            st.text(error)

if not reports:
    st.info("No valid reports found. Run the scanner first.")
    st.code(
        r".\.venv\Scripts\python.exe .\src\security_group_scan.py",
        language="powershell",
    )
    st.stop()

scopes = sorted({
    (report["account_id"], report["region"])
    for _, report in reports
})

scope = st.sidebar.selectbox(
    "Account / region",
    scopes,
    format_func=lambda value: f"…{value[0][-4:]} / {value[1]}",
)

scoped_reports = [
    item for item in reports
    if (item[1]["account_id"], item[1]["region"]) == scope
]

selected = st.sidebar.selectbox(
    "Saved snapshot — newest first",
    range(len(scoped_reports)),
    format_func=lambda index: scoped_reports[index][1]["scanned_at"],
)

path, report = scoped_reports[selected]
inventory = report["inventory"]
findings = report["findings"]

scanned_at = datetime.fromisoformat(report["scanned_at"])
age_hours = (
    datetime.now(timezone.utc) - scanned_at
).total_seconds() / 3600

st.caption(f"Region: {report['region']} | Scan time: {report['scanned_at']}")

if selected != 0:
    st.warning("You are viewing a historical snapshot.")
elif age_hours > 24:
    st.warning("The latest saved scan is over 24 hours old.")

st.info(
    "Saved configuration snapshot, not live monitoring. "
    "This check covers unrestricted inbound TCP SSH/RDP only. "
    "Network-interface association does not prove internet reachability."
)

associated = sum(bool(item.get("interface_ids")) for item in inventory)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Security groups", len(inventory))
col2.metric("Associated groups", associated)
col3.metric("Findings", len(findings))
col4.metric("Saved scans in this scope", len(scoped_reports))

inventory_tab, findings_tab, history_tab, evidence_tab = st.tabs(
    ["Inventory", "Findings", "Scan history", "Evidence"]
)

with inventory_tab:
    rows = []
    for item in inventory:
        group = item["configuration"]
        rows.append({
            "Group ID": group["GroupId"],
            "Name": group.get("GroupName", ""),
            "VPC": group.get("VpcId", ""),
            "Associated interfaces": len(item.get("interface_ids", [])),
            "Inbound rule blocks": len(group.get("IpPermissions", [])),
        })

    if rows:
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    else:
        st.info("No security groups were returned for this scope.")

with findings_tab:
    if findings:
        st.error(f"{len(findings)} unrestricted administrative-access finding(s).")
        st.dataframe(
            pd.DataFrame(findings),
            hide_index=True,
            width="stretch",
        )
        st.download_button(
            "Download findings CSV",
            data=pd.DataFrame(findings).to_csv(index=False).encode("utf-8"),
            file_name=f"{path.stem}-findings.csv",
            mime="text/csv",
        )
    else:
        st.success("No unrestricted SSH/RDP rules found in this snapshot.")

with history_tab:
    history = [
        {
            "Scan time": saved["scanned_at"],
            "Security groups": len(saved["inventory"]),
            "Findings": len(saved["findings"]),
        }
        for _, saved in scoped_reports
    ]
    st.dataframe(pd.DataFrame(history), hide_index=True, width="stretch")
    st.caption(
        "History includes successfully saved scans. "
        "Failed scan attempts are not yet persisted."
    )

with evidence_tab:
    st.write("Original report")
    st.json(report)
    st.download_button(
        "Download snapshot JSON",
        data=json.dumps(report, indent=2),
        file_name=path.name,
        mime="application/json",
    )

st.sidebar.caption(
    "Reloading reads local files only. Run the scanner separately "
    "to collect a new AWS snapshot."
)