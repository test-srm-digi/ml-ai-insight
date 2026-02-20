#!/usr/bin/env python3
"""CLI: Ingest vulnerability data from JSON, CSV, MariaDB, or generate sample data."""
import json
import sys
from pathlib import Path

import click
import pandas as pd

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from vuln_insight.data.csv_loader import load_csv
from vuln_insight.data.json_ingester import ingest_json, ingest_json_batch
from vuln_insight.data.sample_data import generate_sample_data, save_sample_csv
from vuln_insight.data.transformers import to_canonical


@click.group()
def cli():
    """Ingest vulnerability data from various sources."""
    pass


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--output", "-o", default="data/ingested.csv", help="Output CSV path.")
@click.option("--sheet", default=None, help="Excel sheet name (for .xlsx files).")
def csv(path, output, sheet):
    """Ingest data from a CSV or Excel file."""
    click.echo(f"Loading data from {path}...")
    df = load_csv(path, sheet_name=sheet)
    df = to_canonical(df)

    Path(output).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output, index=False)

    click.echo(f"Ingested {len(df)} records.")
    click.echo(f"Columns: {list(df.columns)}")
    click.echo(f"Severity distribution:\n{df['severity'].value_counts().to_string()}")
    click.echo(f"Saved to {output}")


@cli.command("json")
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
@click.option("--output", "-o", default="data/ingested.csv", help="Output CSV path.")
def json_cmd(paths, output):
    """Ingest data from one or more JSON API response files."""
    if not paths:
        click.echo("Error: provide at least one JSON file path.", err=True)
        raise SystemExit(1)

    click.echo(f"Loading data from {len(paths)} JSON file(s)...")

    if len(paths) == 1:
        df = ingest_json(paths[0])
    else:
        df = ingest_json_batch(list(paths))

    df = to_canonical(df)

    Path(output).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output, index=False)

    click.echo(f"Ingested {len(df)} records.")
    click.echo(f"Saved to {output}")


@cli.command()
@click.option("--config", "-c", default="config/db_config.yaml", help="DB config path.")
@click.option("--query", "-q", default=None, help="SQL query override.")
@click.option("--output", "-o", default="data/ingested.csv", help="Output CSV path.")
def db(config, query, output):
    """Ingest data from MariaDB."""
    from vuln_insight.data.db_loader import load_mariadb

    click.echo(f"Connecting to MariaDB (config: {config})...")
    df = load_mariadb(config_path=config, query=query)
    df = to_canonical(df)

    Path(output).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output, index=False)

    click.echo(f"Ingested {len(df)} records from MariaDB.")
    click.echo(f"Saved to {output}")


@cli.command()
@click.option("--records", "-n", default=1000, help="Number of sample records.")
@click.option("--output", "-o", default="data/sample_data.csv", help="Output CSV path.")
@click.option("--seed", default=42, help="Random seed.")
def sample(records, output, seed):
    """Generate synthetic sample data for testing."""
    click.echo(f"Generating {records} synthetic vulnerability records (seed={seed})...")
    df = generate_sample_data(n_records=records, seed=seed)

    Path(output).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output, index=False)

    click.echo(f"Generated {len(df)} records.")
    click.echo(f"Severity distribution:\n{df['severity'].value_counts().to_string()}")
    click.echo(f"User action distribution:\n{df['user_action'].value_counts().to_string()}")
    click.echo(f"Saved to {output}")


@cli.command()
@click.argument("path", type=click.Path(exists=True))
def info(path):
    """Show summary info about an ingested dataset."""
    df = pd.read_csv(path)
    click.echo(f"File: {path}")
    click.echo(f"Records: {len(df)}")
    click.echo(f"Columns ({len(df.columns)}): {list(df.columns)}")

    if "severity" in df.columns:
        click.echo(f"\nSeverity distribution:\n{df['severity'].value_counts().to_string()}")
    if "user_action" in df.columns:
        click.echo(f"\nUser action distribution:\n{df['user_action'].value_counts().to_string()}")
    if "ecosystem" in df.columns:
        click.echo(f"\nEcosystem distribution:\n{df['ecosystem'].value_counts().to_string()}")
    if "repo" in df.columns:
        click.echo(f"\nRepos: {df['repo'].nunique()} unique")


if __name__ == "__main__":
    cli()
