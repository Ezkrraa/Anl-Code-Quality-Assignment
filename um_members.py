# import my own files
import db
import console

import sys

if __name__ == "__main__":
    db.setup_database()
    # only seed if not specified --no-seed param AND no consultants in DB
    if not sys.argv.__contains__("--no-seed") and db.database_connection.cursor().execute("SELECT * FROM users WHERE isadmin=0").fetchone() == None:
        db.seed_database()
    if db.database_connection.cursor().execute("SELECT * FROM users WHERE isadmin=1").fetchone() == None:
        db.create_test_admin()
    console.home_screen()
