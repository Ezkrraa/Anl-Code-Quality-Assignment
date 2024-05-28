# uuid v4, since it's unique and random
from uuid import uuid4

# to have strict type checking
from pydantic import BaseModel

# for database, hashing, logging and random data
import bcrypt, sqlite3, datetime

# for seeding, testing purposes
from faker import Faker

# random, duhh
from random import Random

rand = Random()
fake = Faker()
database_connection: sqlite3.Connection = None


class User:
    username: str
    password: str
    failedattempts: int
    isadmin: bool

    def __init__(self, uname, pw, fails=0, isadmin=False) -> None:
        self.username = uname
        self.password = pw
        self.failedattempts = fails
        self.isadmin = isadmin

    @classmethod
    def fromtuple(cls, data: tuple[str, str, int, bool]):
        return cls(data[0], data[1], data[2], bool(data[3]))

    def toTuple(self) -> tuple[str, str, int, bool]:
        return (self.username, self.password, self.failedattempts, self.isadmin)


class Member:
    id: str
    firstname: str
    lastname: str
    age: int
    gender: str  # python does not have a char data type
    weight: int
    address: str
    email: str
    phonenumber: str
    registrationdate: str

    def __init__(
        self, fname, lname, age, gender, weight, addr, email, phone, regdate
    ) -> None:
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
        self.__init__(
            self, data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]
        )

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
        return (
            self.id,
            self.firstname,
            self.lastname,
            self.age,
            self.gender,
            self.weight,
            self.address,
            self.email,
            self.phonenumber,
            self.registrationdate,
        )


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
        )""",
        """CREATE TABLE IF NOT EXISTS logs (
        id UUID PRIMARY KEY,
        timestamp TEXT,
        severity INT,
        desc TEXT
        )""",
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
    seed_members = [Member.toTuple(Member.genrandom()) for _ in range(50)]
    cursor.executemany(
        "INSERT INTO members VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", seed_members
    )
    database_connection.commit()


def gen_memberid() -> str:
    "generates new ID's until there isn't a collision"
    while True:
        new_id = str(datetime.date.today().year)[2:]
        for i in range(7):
            new_id += str(rand.randint(0, 9))
        total = 0
        for i in range(len(new_id)):
            total += int(new_id[i])
        new_id += str(total % 10)
        cur = database_connection.cursor()
        anymembers = cur.execute(
            "SELECT * FROM members WHERE id=?", (new_id,)
        ).fetchone()
        if anymembers is None:
            return new_id


def attempt_login(uname: str, attemptPassword: str) -> Exception | User:
    "Returns an exception or a User, depending on success"
    cursor = database_connection.cursor()
    output = cursor.execute(
        "SELECT * FROM Users WHERE Username = ?", (uname,)
    ).fetchone()

    if output == None:
        return Exception("UserNotFound")

    print(output)
    usr: User = User.fromtuple(data=output)
    if usr.failedattempts >= 3:
        return Exception("TooManyFailedAttempts")
    elif not bcrypt.checkpw(attemptPassword.encode("utf-8"), usr.password):
        cursor.execute(
            "UPDATE Users SET failedlogins = (failedlogins + 1) WHERE Username=?",
            (uname,),
        )
        database_connection.commit()
        return Exception("WrongPassword")
    else:
        return usr
