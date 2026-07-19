"""A service class whose method is reached only via a type-annotated receiver."""
import sqlite3


class Service:
    def query(self, q):
        conn = sqlite3.connect("x.db")
        return conn.execute("SELECT * FROM t WHERE k = '%s'" % q)   # sink inside the method
