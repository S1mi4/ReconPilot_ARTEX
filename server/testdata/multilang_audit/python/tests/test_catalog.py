"""Context only; the Go inventory regression never imports this module."""

import sqlite3

from catalog import lookup_bound


def test_bound_value_stays_data():
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("CREATE TABLE items (name TEXT)")
        connection.execute("INSERT INTO items VALUES (?)", ("example",))
        assert lookup_bound(connection, "example") == [("example",)]
        assert lookup_bound(connection, "' OR 1=1 --") == []
    finally:
        connection.close()
