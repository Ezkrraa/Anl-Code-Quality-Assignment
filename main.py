# import my own files
import db
import console

# for closing the db connection on exit
import atexit


def unlock_account(uname):
    cur = db.database_connection.cursor()
    cur.execute("UPDATE users SET failedlogins = 0 WHERE username=?", (uname,))
    db.database_connection.commit()
    print(f"unlocked account {uname}")


def create_test_user(
    uname="test", testpw="password123", failedattempts=0, isadmin=True
):
    import bcrypt

    "creates a default test user"
    bcryptpass = bcrypt.hashpw(testpw.encode("utf-8"), bcrypt.gensalt())
    cur = db.database_connection.cursor()
    cur.execute(
        "INSERT INTO users VALUES(?, ?, ?, ?)",
        (uname, bcryptpass, failedattempts, isadmin),
    )
    db.database_connection.commit()


def exit_handler():
    """Runs on close, closes the database connection"""
    if db.database_connection:
        db.database_connection.close()


if __name__ == "__main__":
    atexit.register(exit_handler)
    db.setup_database()
    if db.database_connection.cursor().execute("SELECT 1 FROM users") == None:
        db.seed_database()
        print("seeded DB, was empty")
    # create_test_user()
    # unlock_account("test")
    console.login_screen()


# SQL Tables Rows:

## Users
# Username (String)
#   - Unique
#   - len <= 10
#   - starts with a-z, A-Z or _
#   - may contain any of: a-z 0-9 _ ' .
#   - case-insensitive
# Password (Bcrypt hash)
#   - Unhashed len: 12 >= len >= 30
#   - may contain any of: a-z A-Z 0-9 ~!@#$%&_-+=`|\(){}[]:;'<>,.?/
#   - at least contains 1 lower- and uppercase letter, a digit and a special character
# failedLogins (int)
#   - increments up to 3 to prevent brute forcing
#   - must be reset by an admin if >= 3
# IsAdmin (Bool)

## members
# id, in the format AABBBBBBBC, where AA is the last 2 numbers of the year, B is a random numeric 0-9, and C is the sum of all preceding digits % 10.
# Firstname (String)
# Lastname (String)
# Age (Integer)
# Gender (Char, either 'M', 'F' or 'O')
# Weight (Integer)
# Address (String)
# Email (String)
# Phonenumber (String)
# Registrationdate (Timestamp, format YYYY-MM-DD HH:mm:SS)


## logs
# ID, UUIDv4
# Timestamp, format YYYY-MM-DD HH:mm:SS (ex. 2023-09-14 22:26:47)
# Severity, integer (0-7), ACCORDING TO CCNA specifications. Will not use 0 or 6-7
#    0: emerg    emergency      system is unstable (should not be used by applications)
#    1: alert    alert          should be corrected immediately
#    2: crit     critical       critical conditions
#    3: err      error          error conditions
#    4: warning  warning        may indicate that an error will occur if action is not taken
#    5: notice   notice         events that are unusual, but not error conditions
#    6: info     informational  normal operational messages that require no action
#    7: debug    debug          information that is useful for debugging the application
# Description
