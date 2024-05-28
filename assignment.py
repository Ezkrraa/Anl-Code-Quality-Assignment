import bcrypt, sqlite3, atexit, datetime, random
from faker import Faker
from random import Random
from getpass import getpass

rand = Random()
fake = Faker()
database_connection: sqlite3.Connection = None

def setup_database() -> None:
    """connects to the database, makes one if none exists. returns nothing."""
    global database_connection
    try:
        database_connection = sqlite3.connect("database.db")
        print("Found database, version: " + sqlite3.sqlite_version)
    except sqlite3.Error as e:
        print("couldn't connect, got error: ")
        print(e)
    finally:
        if database_connection:
            create_tables()
            return


def create_tables():
    statements = [
        """CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS members (
        id CHAR(10) PRIMARY KEY,
        firstname TEXT NOT NULL,
        lastname TEXT NOT NULL,
        age INT,
        gender CHARACTER(1),
        weight INT,
        address TEXT,
        email TEXT,
        phonenumber TEXT,
        registrationdate CHAR(10)
        )"""
    ]
    try:
        with sqlite3.connect("database.db") as conn:
            cursor = conn.cursor()
            for statement in statements:
                cursor.execute(statement)
            conn.commit()
    except sqlite3.Error as e:
        print(e)


def seed_database():
    cursor = database_connection.cursor()
    seed_members = []
    for i in range(50):
        seed_members.append((
            gen_userid(),
            fake.first_name(),
            fake.last_name(),
            rand.randint(20, 80),
            rand.choice(["M", "M", "F", "F", "O"]),
            rand.randint(50, 110),
            fake.address(),
            fake.email(),
            rand.randint(10000000, 99999999), # not using numbers that start with zeroes to prevent errors, I'm lazy
            str(datetime.datetime.now().date().today()),
        ))
    print(seed_members[0])
    cursor.executemany("INSERT INTO members VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", seed_members)
    database_connection.commit()


def gen_userid()-> str:
    id = str(datetime.date.today().year)[2:]
    for i in range(7):
        id += str(random.randint(0, 9))
    total = 0
    for i in range(len(id)):
        total += int(id[i])
    id += str(total % 10)
    return id

def attempt_login(uname: str, pw: str) -> bool:
    cursor = database_connection.cursor()
    usr = cursor.execute("SELECT TOP FROM users WHERE username = ?", uname).fetchone()
    bcrypt.checkpw(pw, usr[0])


def exit_handler():
    """will run if the program is closed, closes the database connection"""
    if database_connection:
        database_connection.close()


def login_screen():
    print("Login to the application, enter your username:\n> ")
    uname = input()
    print("enter password:")
    unhashed_pw = getpass("> ")



if __name__ == "__main__":
    atexit.register(exit_handler)
    setup_database()
    if(database_connection.cursor().fetchone() == None):
        seed_database()
    login_screen()




# SQL Table Rows:


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

# IsAdmin (Bool)