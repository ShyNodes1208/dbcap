"""Database type → default port mapping. Port is always configurable via CLI."""

DB_PORTS: dict[str, int] = {
    "mysql": 3306,
    "postgresql": 5432,
    "oracle": 1521,
    "mssql": 1433,
    "dameng": 5236,
    "redis": 6379,
    "mongodb": 27017,
}


def get_db_name(port: int) -> str:
    for name, p in DB_PORTS.items():
        if p == port:
            return name
    return str(port)
