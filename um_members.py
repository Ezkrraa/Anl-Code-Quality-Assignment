# import my own files
import db
import console

import sys

if __name__ == "__main__":
    db.setup_database()
    # only seed if not specified --no-seed param AND no consultants in DB
    if db.database_connection.cursor().execute("SELECT * FROM users").fetchone() == None:
        db.create_test_admin()
    if sys.argv.__contains__("--seed"):
        db.seed_database()
    console.home_screen()
