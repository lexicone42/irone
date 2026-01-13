"""Security Data Lake Analytics - Navigation Hub

Central dashboard for accessing security notebooks.

Run with: marimo edit notebooks/main.py

Individual notebooks:
- Detection Engineering: marimo edit notebooks/detection_engineering.py
- Investigation: marimo edit notebooks/investigation.py
- Monitoring: marimo edit notebooks/monitoring.py
- Deployment: marimo edit notebooks/deployment.py
"""

import marimo

__generated_with = "0.19.2"
app = marimo.App(width="full")


@app.cell
def _():
    import marimo as mo

    mo.md(
        """
        # Security Data Lake Analytics

        A Marimo notebook-based security analytics platform for AWS Security Lake.

        ## Notebooks

        Choose a focused notebook based on your task:
        """
    )
    return (mo,)


@app.cell
def _(mo):
    notebooks = [
        {
            "name": "Detection Engineering",
            "file": "detection_engineering.py",
            "description": "Create, test, and manage SQL-based detection rules. Includes AI-assisted rule generation.",
            "roles": ["Detection Engineer", "Security Analyst"],
            "icon": "🔍",
        },
        {
            "name": "Investigation",
            "file": "investigation.py",
            "description": "Build and visualize investigation graphs from security events. AI-assisted analysis.",
            "roles": ["SOC Analyst", "Incident Responder"],
            "icon": "🔎",
        },
        {
            "name": "Monitoring",
            "file": "monitoring.py",
            "description": "Health monitoring for data sources and security infrastructure.",
            "roles": ["SOC Analyst", "Security Engineer"],
            "icon": "📊",
        },
        {
            "name": "Deployment",
            "file": "deployment.py",
            "description": "Deploy detection rules to Lambda and manage infrastructure. (Admin only)",
            "roles": ["Security Engineer", "DevOps"],
            "icon": "🚀",
            "sensitive": True,
        },
    ]

    cards = []
    for nb in notebooks:
        sensitive_badge = " ⚠️" if nb.get("sensitive") else ""
        roles_str = ", ".join(nb["roles"])
        card = mo.md(
            f"""
            ### {nb["icon"]} {nb["name"]}{sensitive_badge}

            {nb["description"]}

            **Roles:** {roles_str}

            ```bash
            marimo edit notebooks/{nb["file"]}
            ```
            """
        )
        cards.append(card)

    mo.vstack(cards)
    return cards, nb, notebooks, roles_str, sensitive_badge


@app.cell
def _(mo):
    mo.md(
        """
        ---

        ## Quick Start

        ### Local Development

        ```bash
        # Install dependencies
        uv sync

        # Run any notebook
        uv run marimo edit notebooks/detection_engineering.py
        ```

        ### AWS Deployment

        ```bash
        # Build container
        docker build -f Dockerfile.marimo -t secdash-marimo .

        # Deploy to App Runner (VPC-only access)
        aws cloudformation deploy \\
          --template-file infrastructure/marimo-apprunner.yaml \\
          --stack-name secdash-marimo-dev \\
          --parameter-overrides VpcId=vpc-xxx ...
        ```

        ---

        ## Features

        | Feature | Description |
        |---------|-------------|
        | **Security Lake Integration** | Query OCSF-formatted security events |
        | **Detection Rules** | SQL-based rules with threshold alerts |
        | **Investigation Graphs** | Visual entity relationship mapping |
        | **AI Assistance** | Bedrock Claude for analysis & generation |
        | **AWS Deployment** | Lambda, App Runner, Neptune infrastructure |
        """
    )
    return


@app.cell
def _(mo):
    mo.md("## Configuration")
    return


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
def _(mo, region_input):
    region = region_input.value

    mo.md(
        f"""
        ## AWS Console Links

        - [Security Lake](<https://{region}.console.aws.amazon.com/securitylake/home?region={region}>)
        - [Athena Query Editor](<https://{region}.console.aws.amazon.com/athena/home?region={region}#/query-editor>)
        - [Security Hub](<https://{region}.console.aws.amazon.com/securityhub/home?region={region}>)
        - [CloudWatch](<https://{region}.console.aws.amazon.com/cloudwatch/home?region={region}>)
        - [Lambda Functions](<https://{region}.console.aws.amazon.com/lambda/home?region={region}#/functions>)
        """
    )
    return (region,)


@app.cell
def _(mo):
    mo.md(
        """
        ## About

        **secdashboards** is an Apache 2.0 licensed security analytics platform.

        - GitHub: [secdashboards](https://github.com/your-org/secdashboards)
        - Documentation: See README.md
        - License: Apache License 2.0
        """
    )
    return


if __name__ == "__main__":
    app.run()
