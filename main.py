import platform
from pydantic import BaseModel
import bcrypt, sqlite3, atexit, datetime, random, os
from faker import Faker
from random import Random
from getpass import getpass

rand = Random()
fake = Faker()
database_connection: sqlite3.Connection = None

class User:
    username: str
    password: str
    failedattempts: int
    isadmin: bool

    def __init__(self, uname, pw, fails = 0, isadmin = False) -> None:
        self.username = uname
        self.password = pw
        self.failedattempts = fails
        self.isadmin = isadmin

    @classmethod
    def fromtuple(cls, data: tuple[str, str, int]):
        return cls(data[0], data[1], data[2])


    def toTuple(self) -> tuple[str, str, int, bool]:
        return (self.username, self.password, self.failedattempts, self.isadmin)

class Member:
    id: str
    firstname: str
    lastname: str
    age: int
    gender: str #python does not have a char data type
    weight: int
    address: str
    email: str
    phonenumber: str
    registrationdate: str

    def __init__(self, fname, lname, age, gender, weight, addr, email, phone, regdate) -> None:
        self.id = gen_memberid()
        self.firstname = fname
        self.lastname = lname
        self.age = age
        self.gender = gender
        self.weight = weight
        self.address = addr
        self.email = email
        self.phonenumber = phone
        self.registrationdate = regdate
    
    @classmethod
    def fromtuple(self, data: tuple[str, str, str, int, str, str, str, str]) -> None:
        self.__init__(self, data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7])

    @classmethod
    def genrandom(self) -> User:
        self.id = gen_memberid()
        self.firstname = fake.first_name()
        self.lastname = fake.last_name()
        self.age = rand.randint(20, 80)
        self.gender = rand.choice(["F", "F", "M", "M", "O"])
        self.weight = rand.randint(50, 110)
        self.address = fake.address()
        self.email = fake.email()
        self.phonenumber = rand.randint(10000000, 99999999)
        self.registrationdate = str(datetime.datetime.now().date().today())
        return self

    def toTuple(self) -> tuple[str, str, str, int, str, str, str, str]:
        return (self.id, self.firstname, self.lastname, self.age, self.gender, self.weight, self.address, self.email, self.phonenumber, self.registrationdate)

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
            print("creating tables")
            create_tables()
            return


def create_tables():
    statements = [
        """CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password BLOB,
        failedlogins INT,
        isadmin BOOL
        )""",
        """CREATE TABLE IF NOT EXISTS members (
        id CHAR(10) PRIMARY KEY,
        firstname TEXT NOT NULL,
        lastname TEXT NOT NULL,
        age INT,
        gender CHAR(1),
        weight INT,
        address TEXT,
        email TEXT,
        phonenumber TEXT,
        registrationdate CHAR(10)
        )"""
    ]
    try:
        cursor = database_connection.cursor()
        for statement in statements:
            cursor.execute(statement)
        database_connection.commit()
    except sqlite3.Error as e:
        print(e)
    finally:
        print("created tables successfully")


def seed_database():
    cursor = database_connection.cursor()
    seed_members = [Member.toTuple(Member.genrandom()) for _ in range(50) ]
    # [print(member) for member in seed_members]
    cursor.executemany("INSERT INTO members VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", seed_members)
    database_connection.commit()


def gen_memberid()-> str:
    "generates new ID's until there isn't a collision"
    while True:
        new_id = str(datetime.date.today().year)[2:]
        for i in range(7):
            new_id += str(random.randint(0, 9))
        total = 0
        for i in range(len(new_id)):
            total += int(new_id[i])
        new_id += str(total % 10)
        cur = database_connection.cursor()
        anymembers = cur.execute("SELECT * FROM members WHERE id=?", (new_id,)).fetchone()
        if (anymembers is None):
            return new_id


def attempt_login(uname: str, attemptPassword: str) -> Exception | User:
    "Returns an exception or a user, depending on success"
    cursor = database_connection.cursor()
    output = cursor.execute("SELECT * FROM users WHERE username = ?", (uname,)).fetchone()

    if(output == None):
        return Exception("UserNotFound")
    
    usr: User = User.fromtuple(data=output)
    print(type(usr))
    if (usr.failedattempts >= 3):
        return Exception("TooManyFailedAttempts")
    elif (not bcrypt.checkpw(attemptPassword.encode('utf-8'), usr.password)):
        cursor.execute("UPDATE users SET failedlogins = (failedlogins + 1) WHERE username=?", (uname,))
        database_connection.commit()
        return Exception("WrongPassword")
    else:
        return usr
    

def clear_console():
    match (platform.system()):
        case "Windows":
            os.system("cls")
        case _:
            os.system("clear")


def main_menu(usr: User):
    while(True):
        selection: str = input("Welcome to the main menu!\nSelect an option to continue:\n\t0: Logout\n").lower()
        match(selection):
            case "0":
                show_error("Logging out now.")
                break
            case _:
                show_error("Invalid option.")
                continue


def login_screen():
    while True:
        clear_console()
        print("To login to the application, enter your username:\n> ", end="")
        uname = input()
        print("enter password:")
        unhashed_pw = getpass("> ")
        attempt = attempt_login(uname=uname, attemptPassword=unhashed_pw)
        print(attempt, User.toTuple(attempt))
        if(isinstance(attempt, User)):
            print(f"It's a user, and the name is {attempt.username}")
        elif type(attempt) == User:
            print(f"It's a user, and the name is {attempt.username}")
        else:
            print("not a user??? it's a: " + str(type(attempt)))
        match (attempt):
            case e if isinstance(e, User):
                main_menu(attempt)

            case e if isinstance(e, Exception) and (str(attempt) == "UserNotFound" or str(attempt) == "WrongPassword"):
                show_error("No user found with that username and password.")
            case e if isinstance(e, Exception) and str(attempt) == "TooManyFailedAttempts":
                show_error("This user has had too many failed attempts. Ask an admin to unlock your account.")
            case e if isinstance(e, Exception):
                show_error(str(attempt))


def unlock_account(uname):
    cur = database_connection.cursor()
    cur.execute("UPDATE users SET failedlogins = 0 WHERE username=?", (uname,))
    database_connection.commit()
    print(f"unlocked account {uname}")

def show_error(err: str):
    clear_console()
    print(err, end="")
    input(" Press enter to continue.")

def create_test_user(uname = "test", testpw = "password123", failedattempts = 0, isadmin = True):
    "creates a default test user "
    bcryptpass = bcrypt.hashpw(testpw.encode('utf-8'), bcrypt.gensalt())
    cur = database_connection.cursor()
    cur.execute("INSERT INTO users VALUES(?, ?, ?, ?)", (uname, bcryptpass, failedattempts, isadmin))
    database_connection.commit()

def exit_handler():
    """Runs on close, closes the database connection"""
    if database_connection:
        database_connection.close()

if __name__ == "__main__":
    atexit.register(exit_handler)
    setup_database()
    if(database_connection.cursor().execute("SELECT 1 FROM users") == None):
        seed_database()
        print("seeded DB, was empty")
    else:
        print("did not seed DB, wasn't empty")
    # create_test_user()
    # unlock_account("test")
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