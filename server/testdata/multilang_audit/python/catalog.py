"""Source-only audit fixture; no listener or executable entry point."""


def lookup_unchecked(connection, requested_name):
    # requested_name is untrusted text; the connection is trusted SQLite context.
    query = "SELECT name FROM items WHERE name = '" + requested_name + "'"  # PY-SQL-BUILD
    return connection.execute(query).fetchall()  # PY-SQL-EXECUTE


def lookup_bound(connection, requested_name):
    return connection.execute(
        "SELECT name FROM items WHERE name = ?", (requested_name,)  # PY-SQL-CONTROL
    ).fetchall()
