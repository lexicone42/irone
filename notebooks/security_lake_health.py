"""Security Lake Health Check

Simple notebook to confirm Security Lake connectivity and data freshness.

Run with: marimo edit notebooks/security_lake_health.py
"""

import marimo

__generated_with = "0.19.9"
app = marimo.App(width="full")


@app.cell
def _():
    import marimo as mo

    mo.md(
        """
        # Security Lake Health Check

        Quick verification that Security Lake tables are accessible and contain recent data.
        """
    )
    return (mo,)


@app.cell
def _(mo):
    region_input = mo.ui.dropdown(
        options=[
            "us-west-2",
            "us-west-1",
            "us-east-1",
            "us-east-2",
            "eu-west-1",
            "eu-central-1",
        ],
        value="us-west-2",
        label="AWS Region",
    )
    region_input
    return (region_input,)


@app.cell
def _(mo):
    workgroup_input = mo.ui.text(
        value="primary",
        label="Athena Workgroup",
    )
    workgroup_input
    return (workgroup_input,)


@app.cell
def _(region_input):
    region = region_input.value
    region_underscore = region.replace("-", "_")

    # Standard Security Lake OCSF 2.0 tables
    security_lake_tables = {
        "CloudTrail": f"amazon_security_lake_table_{region_underscore}_cloud_trail_mgmt_2_0",
        "VPC Flow Logs": f"amazon_security_lake_table_{region_underscore}_vpc_flow_2_0",
        "Route53 DNS": f"amazon_security_lake_table_{region_underscore}_route53_2_0",
        "Security Hub": f"amazon_security_lake_table_{region_underscore}_sh_findings_2_0",
        "Lambda Exec": f"amazon_security_lake_table_{region_underscore}_lambda_execution_2_0",
        "S3 Data Events": f"amazon_security_lake_table_{region_underscore}_s3_data_2_0",
    }

    database = f"amazon_security_lake_glue_db_{region_underscore}"
    return database, region, security_lake_tables


@app.cell
def _(mo):
    run_btn = mo.ui.run_button(label="Run Health Checks")
    run_btn
    return (run_btn,)


@app.cell
def _(database, mo, region, run_btn, security_lake_tables, workgroup_input):
    import time
    from datetime import UTC, datetime

    import boto3
    import polars as pl

    health_output = mo.md("_Click 'Run Health Checks' to verify Security Lake connectivity_")

    if run_btn.value:
        athena = boto3.client("athena", region_name=region)
        workgroup = workgroup_input.value

        results = []
        for label, table in security_lake_tables.items():
            row = {"Source": label, "Table": table}
            start = time.time()
            try:
                sql = f"""
                SELECT COUNT(*) as cnt, MAX(time) as latest_time
                FROM "{database}"."{table}"
                WHERE time >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
                """

                resp = athena.start_query_execution(
                    QueryString=sql,
                    WorkGroup=workgroup,
                )
                qid = resp["QueryExecutionId"]

                # Wait for query to complete (max 30s)
                for _ in range(60):
                    status = athena.get_query_execution(QueryExecutionId=qid)
                    state = status["QueryExecution"]["Status"]["State"]
                    if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
                        break
                    time.sleep(0.5)

                latency = time.time() - start

                if state == "SUCCEEDED":
                    result_resp = athena.get_query_results(QueryExecutionId=qid)
                    data_rows = result_resp["ResultSet"]["Rows"]
                    if len(data_rows) > 1:
                        cnt = data_rows[1]["Data"][0].get("VarCharValue", "0")
                        latest = data_rows[1]["Data"][1].get("VarCharValue", "")
                        row["Records (24h)"] = int(cnt)
                        row["Latest Event"] = latest or "-"
                        if latest:
                            latest_dt = datetime.fromisoformat(latest.replace("Z", "+00:00"))
                            age = (datetime.now(UTC) - latest_dt).total_seconds() / 60
                            row["Age (min)"] = round(age, 1)
                            row["Status"] = "Healthy" if age < 120 else "Stale"
                        else:
                            row["Age (min)"] = None
                            row["Status"] = "No Data"
                    else:
                        row["Records (24h)"] = 0
                        row["Latest Event"] = "-"
                        row["Age (min)"] = None
                        row["Status"] = "Empty"
                else:
                    reason = status["QueryExecution"]["Status"].get("StateChangeReason", state)
                    row["Records (24h)"] = 0
                    row["Latest Event"] = "-"
                    row["Age (min)"] = None
                    row["Status"] = f"Error: {reason[:60]}"
                    latency = time.time() - start

                row["Latency (s)"] = round(latency, 1)

            except Exception as e:
                row["Records (24h)"] = 0
                row["Latest Event"] = "-"
                row["Age (min)"] = None
                row["Status"] = f"Error: {str(e)[:60]}"
                row["Latency (s)"] = round(time.time() - start, 1)

            results.append(row)

        df = pl.DataFrame(results)

        healthy = sum(1 for r in results if r["Status"] == "Healthy")
        total = len(results)
        overall = "All Healthy" if healthy == total else f"{healthy}/{total} Healthy"

        health_output = mo.vstack(
            [
                mo.md(
                    f"**Overall: {overall}** | Region: `{region}` | Checked: {datetime.now(UTC):%Y-%m-%d %H:%M UTC}"
                ),
                mo.ui.table(df.to_pandas()),
            ]
        )

    health_output
    return


if __name__ == "__main__":
    app.run()
