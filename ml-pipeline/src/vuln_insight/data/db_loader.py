"""MariaDB / MySQL loader via SQLAlchemy.

Loads vulnerability data directly from MariaDB using configurable queries.
"""
from pathlib import Path
from typing import Optional, Union

import pandas as pd
import yaml
from sqlalchemy import create_engine, text


def load_mariadb(
    config_path: Union[str, Path] = "config/db_config.yaml",
    query: Optional[str] = None,
) -> pd.DataFrame:
    """Load vulnerability data from MariaDB.

    Args:
        config_path: Path to YAML config with connection details.
        query: Optional SQL query override. If None, uses query from config.

    Returns:
        DataFrame with query results.
    """
    config_path = Path(config_path)
    with open(config_path) as f:
        config = yaml.safe_load(f)

    db = config.get("mariadb", config)

    host = db.get("host", "localhost")
    port = db.get("port", 3306)
    database = db.get("database", "vuln_db")
    user = db.get("user", "root")
    password = db.get("password", "")

    connection_string = (
        f"mysql+pymysql://{user}:{password}@{host}:{port}/{database}"
    )

    engine = create_engine(connection_string)

    sql = query or db.get("query", "SELECT * FROM vulnerability_data")

    with engine.connect() as conn:
        df = pd.read_sql(text(sql), conn)

    # Normalize column names
    from vuln_insight.data.csv_loader import normalize_columns
    return normalize_columns(df)


def test_connection(config_path: Union[str, Path] = "config/db_config.yaml") -> bool:
    """Test MariaDB connection.

    Returns:
        True if connection succeeds, False otherwise.
    """
    config_path = Path(config_path)
    with open(config_path) as f:
        config = yaml.safe_load(f)

    db = config.get("mariadb", config)

    connection_string = (
        f"mysql+pymysql://{db['user']}:{db['password']}"
        f"@{db['host']}:{db['port']}/{db['database']}"
    )

    try:
        engine = create_engine(connection_string)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as e:
        print(f"Connection failed: {e}")
        return False
