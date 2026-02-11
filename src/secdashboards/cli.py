"""Command-line interface for secdashboards."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    name="secdash",
    help="Security Data Lake Analytics CLI",
)

console = Console()


@app.command()
def serve(
    host: Annotated[str, typer.Option(help="Bind address")] = "0.0.0.0",
    port: Annotated[int, typer.Option(help="Port to listen on")] = 8000,
    catalog: Annotated[
        Path | None, typer.Option("--catalog", "-c", help="Path to catalog YAML")
    ] = None,
    rules_dir: Annotated[
        Path | None, typer.Option("--rules", "-r", help="Path to rules directory")
    ] = None,
    duckdb_path: Annotated[str, typer.Option("--db", help="DuckDB database path")] = ":memory:",
    reload: Annotated[bool, typer.Option(help="Enable auto-reload for development")] = False,
) -> None:
    """Start the FastAPI web server."""
    import uvicorn

    from secdashboards.web.app import create_app
    from secdashboards.web.config import WebConfig

    config = WebConfig(
        host=host,
        port=port,
        catalog_path=str(catalog) if catalog else "",
        rules_dir=str(rules_dir) if rules_dir else "",
        duckdb_path=duckdb_path,
        debug=reload,
    )

    if reload:
        # Use factory string for uvicorn reload support
        console.print(
            f"[green]Starting dev server at http://{host}:{port} (reload enabled)[/green]"
        )
        uvicorn.run(
            "secdashboards.web.app:create_app",
            host=host,
            port=port,
            reload=True,
            factory=True,
        )
    else:
        console.print(f"[green]Starting server at http://{host}:{port}[/green]")
        web_app = create_app(config)
        uvicorn.run(web_app, host=host, port=port)


@app.command()
def notebook(
    port: Annotated[int, typer.Option(help="Port to run marimo on")] = 2718,
) -> None:
    """Launch the Marimo notebook for interactive analysis."""
    import subprocess

    notebook_path = Path(__file__).parent.parent.parent.parent / "notebooks" / "main.py"

    if not notebook_path.exists():
        console.print(f"[red]Notebook not found at {notebook_path}[/red]")
        raise typer.Exit(1)

    console.print(f"[green]Starting Marimo notebook at http://localhost:{port}[/green]")
    subprocess.run(["marimo", "edit", str(notebook_path), "--port", str(port)])


@app.command()
def health(
    catalog_path: Annotated[
        Path | None, typer.Option("--catalog", "-c", help="Path to catalog YAML")
    ] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Output as JSON")] = False,
) -> None:
    """Check health of all data sources."""
    import json as json_module

    from secdashboards.catalog.registry import DataCatalog
    from secdashboards.health.monitor import HealthMonitor

    catalog = DataCatalog(catalog_path)
    monitor = HealthMonitor(catalog)
    report = monitor.generate_report()

    if json_output:
        console.print(json_module.dumps(report.to_dict(), indent=2))
    else:
        # Print summary table
        table = Table(title="Data Source Health")
        table.add_column("Source")
        table.add_column("Healthy")
        table.add_column("Last Data")
        table.add_column("Age (min)")
        table.add_column("Records/hr")

        for h in report.source_health:
            status = "[green]Yes[/green]" if h.healthy else "[red]No[/red]"
            last_data = h.last_data_time.strftime("%H:%M:%S") if h.last_data_time else "N/A"
            age = f"{h.data_age_minutes:.0f}" if h.data_age_minutes else "N/A"

            table.add_row(h.source_name, status, last_data, age, str(h.record_count))

        console.print(table)

        if report.issues:
            console.print("\n[red]Issues:[/red]")
            for issue in report.issues:
                console.print(f"  - {issue}")


@app.command()
def run_detections(
    catalog_path: Annotated[
        Path | None, typer.Option("--catalog", "-c", help="Path to catalog YAML")
    ] = None,
    rules_dir: Annotated[
        Path | None, typer.Option("--rules", "-r", help="Path to rules directory")
    ] = None,
    source: Annotated[str, typer.Option("--source", "-s", help="Data source to query")] = "",
    lookback: Annotated[int, typer.Option("--lookback", "-l", help="Lookback in minutes")] = 15,
) -> None:
    """Run all detection rules."""
    from secdashboards.catalog.registry import DataCatalog
    from secdashboards.detections.runner import DetectionRunner

    if not source:
        console.print("[red]Must specify --source[/red]")
        raise typer.Exit(1)

    catalog = DataCatalog(catalog_path)
    runner = DetectionRunner(catalog)

    if rules_dir and rules_dir.exists():
        loaded = runner.load_rules_from_directory(rules_dir)
        console.print(f"Loaded {loaded} detection rules")

    connector = catalog.get_connector(source)
    results = runner.run_all(connector, lookback_minutes=lookback)

    # Print results
    table = Table(title="Detection Results")
    table.add_column("Rule")
    table.add_column("Triggered")
    table.add_column("Severity")
    table.add_column("Matches")
    table.add_column("Time (ms)")

    for result in results:
        triggered = "[red]YES[/red]" if result.triggered else "[green]No[/green]"
        table.add_row(
            result.rule_name,
            triggered,
            result.severity,
            str(result.match_count),
            f"{result.execution_time_ms:.0f}",
        )

    console.print(table)

    # Print alerts
    alerts = [r for r in results if r.triggered]
    if alerts:
        console.print(f"\n[red]{len(alerts)} alert(s) triggered![/red]")


@app.command()
def deploy(
    rules_dir: Annotated[Path, typer.Option("--rules", "-r", help="Path to rules directory")],
    output_dir: Annotated[
        Path, typer.Option("--output", "-o", help="Output directory for packages")
    ] = Path("./deploy_output"),
    source: Annotated[str, typer.Option("--source", "-s", help="Data source name")] = "",
) -> None:
    """Build detection rule packages for CDK deployment."""
    from secdashboards.catalog.registry import DataCatalog
    from secdashboards.deploy.lambda_builder import LambdaBuilder
    from secdashboards.detections.runner import DetectionRunner

    catalog = DataCatalog()
    runner = DetectionRunner(catalog)

    if rules_dir.exists():
        loaded = runner.load_rules_from_directory(rules_dir)
        console.print(f"Loaded {loaded} detection rules")
    else:
        console.print(f"[red]Rules directory not found: {rules_dir}[/red]")
        raise typer.Exit(1)

    builder = LambdaBuilder(output_dir)
    rules = runner.list_rules(enabled_only=True)

    for rule in rules:
        console.print(f"Building package for: {rule.name}")
        package_path = builder.build_package(rule, source)
        console.print(f"  -> {package_path}")

    # Build notifications layer for CDK deployment
    layer_path = builder.build_notifications_layer()
    console.print(f"\n[green]Notifications layer built: {layer_path}[/green]")
    console.print("\nDeploy with CDK:")
    console.print("  cd infrastructure/cdk && cdk deploy secdash-detections")


@app.command()
def init_catalog(
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Output path for catalog YAML")
    ] = Path("catalog.yaml"),
    region: Annotated[str, typer.Option("--region", "-r", help="AWS region")] = "us-west-2",
) -> None:
    """Initialize a sample data catalog configuration."""
    from secdashboards.catalog.models import DataSource, DataSourceType
    from secdashboards.catalog.registry import DataCatalog

    catalog = DataCatalog()

    # Add Security Lake sources
    catalog.create_security_lake_source(
        name="cloudtrail",
        database=f"amazon_security_lake_glue_db_{region.replace('-', '_')}",
        table=f"amazon_security_lake_table_{region.replace('-', '_')}_cloud_trail_mgmt_2_0",
        region=region,
        description="CloudTrail management events from Security Lake",
    )

    catalog.add_source(
        DataSource(
            name="vpc-flow",
            type=DataSourceType.SECURITY_LAKE,
            database=f"amazon_security_lake_glue_db_{region.replace('-', '_')}",
            table=f"amazon_security_lake_table_{region.replace('-', '_')}_vpc_flow_2_0",
            region=region,
            description="VPC Flow Logs from Security Lake",
            tags=["security-lake", "network", "ocsf"],
        )
    )

    catalog.save_to_file(output)
    console.print(f"[green]Catalog initialized at: {output}[/green]")


# Adversary testing commands
adversary_app = typer.Typer(help="Red team and adversary emulation commands")
app.add_typer(adversary_app, name="adversary")


@adversary_app.command("list-scenarios")
def list_scenarios() -> None:
    """List available attack scenarios."""
    from secdashboards.adversary.scenarios import get_mitre_scenarios

    scenarios = get_mitre_scenarios()

    table = Table(title="Available Attack Scenarios")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Techniques")
    table.add_column("Expected Detections")

    for scenario_id, scenario in scenarios.items():
        techniques = ", ".join(scenario.get_technique_ids())
        detections = ", ".join(scenario.expected_detections) or "None defined"
        table.add_row(scenario_id, scenario.name, techniques, detections)

    console.print(table)


@adversary_app.command("run-scenario")
def run_scenario(
    scenario_id: Annotated[str, typer.Argument(help="Scenario ID to run")],
    output_file: Annotated[
        Path | None, typer.Option("--output", "-o", help="Output file for events JSON")
    ] = None,
    generate_network: Annotated[
        bool, typer.Option("--network", "-n", help="Generate real network traffic")
    ] = False,
) -> None:
    """Run an attack scenario and generate synthetic events."""
    import json as json_module

    from secdashboards.adversary.events import OCSFEventGenerator
    from secdashboards.adversary.network import NetworkEmulator
    from secdashboards.adversary.scenarios import ScenarioRunner, get_mitre_scenarios

    scenarios = get_mitre_scenarios()

    if scenario_id not in scenarios:
        console.print(f"[red]Unknown scenario: {scenario_id}[/red]")
        console.print(f"Available: {', '.join(scenarios.keys())}")
        raise typer.Exit(1)

    scenario = scenarios[scenario_id]
    console.print(f"[bold]Running scenario: {scenario.name}[/bold]")
    console.print(f"Description: {scenario.description}")
    console.print(f"MITRE Techniques: {', '.join(scenario.get_technique_ids())}")

    # Setup runner
    gen = OCSFEventGenerator()
    network = NetworkEmulator() if generate_network else None
    runner = ScenarioRunner(event_generator=gen, network_emulator=network)

    # Run scenario
    result = runner.run_scenario(scenario, generate_network_traffic=generate_network)

    # Display results
    table = Table(title="Scenario Results")
    table.add_column("Metric")
    table.add_column("Value")

    table.add_row("Events Generated", str(result["total_events"]))
    table.add_row("Network Packets", str(result["total_network_packets"]))
    table.add_row("Duration", f"{result['duration_seconds']:.2f}s")
    table.add_row("Expected Detections", ", ".join(result["expected_detections"]))

    console.print(table)

    # Show step results
    console.print("\n[bold]Step Details:[/bold]")
    for step in result["step_results"]:
        console.print(
            f"  - {step['step_name']}: {step['events_generated']} events, {step['technique_id']}"
        )

    # Save events if requested
    if output_file:
        events_data = [e.to_ocsf_dict() for e in result["events"]]
        output_file.write_text(json_module.dumps(events_data, indent=2, default=str))
        console.print(f"\n[green]Events saved to: {output_file}[/green]")


@adversary_app.command("test-detections")
def test_detections(
    rules_dir: Annotated[
        Path, typer.Option("--rules", "-r", help="Path to rules directory")
    ] = Path("./detections"),
    scenario_id: Annotated[
        str | None, typer.Option("--scenario", "-s", help="Specific scenario to test")
    ] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Output as JSON")] = False,
) -> None:
    """Test detection rules against adversary scenarios."""
    import json as json_module

    from secdashboards.adversary.runner import AdversaryTestRunner
    from secdashboards.adversary.scenarios import get_mitre_scenarios
    from secdashboards.catalog.registry import DataCatalog
    from secdashboards.detections.runner import DetectionRunner

    # Load detection rules
    catalog = DataCatalog()
    det_runner = DetectionRunner(catalog)

    if rules_dir.exists():
        loaded = det_runner.load_rules_from_directory(rules_dir)
        console.print(f"Loaded {loaded} detection rules")
    else:
        console.print(f"[yellow]Rules directory not found: {rules_dir}[/yellow]")

    rules = det_runner.list_rules(enabled_only=True)
    if not rules:
        console.print("[red]No detection rules loaded[/red]")
        raise typer.Exit(1)

    # Get scenarios
    scenarios = get_mitre_scenarios()
    if scenario_id:
        if scenario_id not in scenarios:
            console.print(f"[red]Unknown scenario: {scenario_id}[/red]")
            raise typer.Exit(1)
        scenarios = {scenario_id: scenarios[scenario_id]}

    # Run tests
    test_runner = AdversaryTestRunner()
    suite = test_runner.run_test_suite(
        rules=rules,
        scenarios=list(scenarios.values()),
    )

    if json_output:
        console.print(json_module.dumps(suite.summary(), indent=2))
    else:
        # Print summary
        summary = suite.summary()
        console.print("\n[bold]Test Suite Results[/bold]")

        table = Table()
        table.add_column("Metric")
        table.add_column("Value")

        table.add_row("Total Tests", str(summary["total_tests"]))
        table.add_row("Passed", f"[green]{summary['passed']}[/green]")
        table.add_row("Failed", f"[red]{summary['failed']}[/red]" if summary["failed"] else "0")
        table.add_row(
            "Errors", f"[yellow]{summary['errors']}[/yellow]" if summary["errors"] else "0"
        )
        table.add_row("Pass Rate", summary["pass_rate"])

        console.print(table)

        # Show failed tests
        failed = [r for r in suite.results if r["outcome"] == "fail"]
        if failed:
            console.print("\n[red]Failed Tests:[/red]")
            for f in failed:
                console.print(f"  - {f['rule_name']} ({f['scenario_id']})")


@adversary_app.command("network-test")
def network_test(
    target_ip: Annotated[str, typer.Option("--target", "-t", help="Target IP")] = "127.0.0.1",
    test_type: Annotated[str, typer.Option("--type", help="Test type: scan, dns, beacon")] = "scan",
    ports: Annotated[
        str, typer.Option("--ports", "-p", help="Comma-separated ports")
    ] = "22,80,443",
) -> None:
    """Run network-based tests locally (for VPC Flow/DNS log triggers)."""
    from secdashboards.adversary.network import NetworkEmulator

    emulator = NetworkEmulator(verbose=True)

    console.print(f"[bold]Running network test: {test_type}[/bold]")
    console.print(f"Target: {target_ip}")

    if test_type == "scan":
        port_list = [int(p.strip()) for p in ports.split(",")]
        console.print(f"Ports: {port_list}")
        results = emulator.tcp_connect_scan(target_ip, port_list)

    elif test_type == "dns":
        hostnames = ["test.example.com", "beacon.test.com", "c2.test.com"]
        results = emulator.dns_queries(hostnames)

    elif test_type == "beacon":
        results = emulator.simulate_beacon(target_ip, port=443, count=5, interval_seconds=2.0)

    else:
        console.print(f"[red]Unknown test type: {test_type}[/red]")
        raise typer.Exit(1)

    # Show results
    summary = emulator.results_summary(results)

    table = Table(title="Network Test Results")
    table.add_column("Metric")
    table.add_column("Value")

    table.add_row("Total Packets", str(summary["total_packets"]))
    table.add_row("Successful Sends", str(summary["successful_sends"]))
    table.add_row("Responses Received", str(summary["responses_received"]))
    table.add_row("Avg Response Time", f"{summary['average_response_time_ms']:.2f}ms")

    console.print(table)


@adversary_app.command("deploy-lambda")
def deploy_adversary_lambda(
    output_dir: Annotated[Path, typer.Option("--output", "-o", help="Output directory")] = Path(
        "./build"
    ),
    generate_template: Annotated[
        bool, typer.Option("--template", help="Generate CloudFormation template")
    ] = True,
) -> None:
    """Build and prepare adversary Lambda for deployment."""
    from secdashboards.adversary.deploy import AdversaryLambdaBuilder

    builder = AdversaryLambdaBuilder(output_dir)

    # Build package
    console.print("[bold]Building adversary Lambda package...[/bold]")
    package_path = builder.build_package()
    console.print(f"[green]Package created: {package_path}[/green]")

    if generate_template:
        template = builder.generate_cloudformation_template()
        template_path = output_dir / "adversary-template.yaml"
        builder.write_template(template, template_path)
        console.print(f"[green]CloudFormation template created: {template_path}[/green]")

        console.print("\n[bold]Deploy with CDK or CloudFormation:[/bold]")
        console.print(f"  aws cloudformation deploy --template-file {template_path} \\")
        console.print("    --stack-name secdash-adversary --capabilities CAPABILITY_NAMED_IAM")


@adversary_app.command("invoke-lambda")
def invoke_adversary_lambda(
    function_name: Annotated[
        str, typer.Option("--function", "-f", help="Lambda function name")
    ] = "secdash-adversary-network-tester",
    scenario: Annotated[
        str, typer.Option("--scenario", "-s", help="Scenario to run")
    ] = "basic_connectivity",
    target_ip: Annotated[
        str | None, typer.Option("--target", "-t", help="Override target IP")
    ] = None,
) -> None:
    """Invoke the deployed adversary Lambda function."""
    import json as json_module

    from secdashboards.adversary.deploy import AdversaryLambdaBuilder

    builder = AdversaryLambdaBuilder("./build")

    console.print(f"[bold]Invoking {function_name}...[/bold]")
    console.print(f"Scenario: {scenario}")

    try:
        result = builder.invoke_test(
            function_name=function_name,
            scenario=scenario,
            target_ip=target_ip,
        )

        if result.get("statusCode") == 200:
            body = json_module.loads(result["body"])
            console.print("[green]Test completed successfully[/green]")
            console.print(f"Tests run: {body.get('tests_run', 'N/A')}")
            console.print(f"Successful: {body.get('successful', 'N/A')}")
        else:
            console.print(f"[red]Test failed: {result}[/red]")

    except Exception as e:
        console.print(f"[red]Failed to invoke Lambda: {e}[/red]")
        raise typer.Exit(1) from e


if __name__ == "__main__":
    app()
