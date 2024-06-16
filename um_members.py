# import my own files
import db
import console

import sys

if __name__ == "__main__":
    db.setup_database()
    # always seed except if specified otherwise
    if not sys.argv.__contains__("--no-seed"):
        db.seed_database()
    if db.database_connection.cursor().execute("SELECT * FROM users WHERE isadmin=0").fetchone() == None:
        db.create_test_admin()
    console.home_screen()
