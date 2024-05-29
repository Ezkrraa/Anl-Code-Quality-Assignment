# uuid v4, since it's unique and random
from uuid import uuid4, UUID

from typing import cast

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
database_connection: sqlite3.Connection


class LogPoint:
    id: UUID
    timestamp: datetime.datetime
    severity: int
    description: str

    def __init__(self, severity, desc):
        self.id = uuid4()
        self.timestamp = datetime.datetime.now()
        self.severity = severity
        self.description = desc

    def toTuple(self) -> tuple[bytes, str, int, str]:
        return (
            self.id.bytes,
            self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            self.severity,
            self.description,
        )


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

    @classmethod
    def genRandom(cls):
        username = fake.catch_phrase()
        password = str(bcrypt.hashpw("password123".encode("utf-8"), bcrypt.gensalt()))
        failedattempts = 0
        isadmin = False
        return cls(username, password, failedattempts, isadmin)

    def toTuple(self) -> tuple[str, str, int, bool]:
        return (self.username, self.password, self.failedattempts, self.isadmin)

    def __str__(self) -> str:
        return f"Name: {self.username}\nIs admin: {self.isadmin}\nFailed login attempts: {self.failedattempts}"


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
        self, fname, lname, age, gender, weight, addr, email, phone, regdate, id="0"
    ) -> None:
        # input(id + ' ' + fname + ' ' + lname + ' ' + str(age) + ' ' + gender + ' ' + str(weight) + ' ' + addr + ' ' + email + ' ' + phone + ' ' + regdate)
        if id == "0":
            self.id = gen_memberid()
        else:
            self.id = id
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
    # format: id(str), fname(str), lname(str), age(int), gender(char), weight(int), address(str), email(str), phone(str), regdate(str)
    def fromtuple(cls, data: tuple[str, str, str, int, str, int, str, str, str, str]):
        return cls(
            data[1],
            data[2],
            data[3],
            data[4],
            data[5],
            data[6],
            data[7],
            data[8],
            data[9],
            id=data[0],
        )

    @classmethod
    def genrandom(cls):
        id = gen_memberid()
        firstname = fake.first_name()
        lastname = fake.last_name()
        age = rand.randint(20, 80)
        gender = rand.choice(["F", "F", "M", "M", "O"])
        weight = rand.randint(50, 110)
        address = fake.address().replace("\n", " ")
        email = fake.email()
        phonenumber = str(rand.randint(10000000, 99999999))
        registrationdate = str(datetime.datetime.now().date().today())
        return cls(
            id,
            firstname,
            lastname,
            age,
            gender,
            weight,
            address,
            email,
            phonenumber,
            registrationdate,
        )

    def toTuple(self) -> tuple[str, str, str, int, str, int, str, str, str, str]:
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

    def __str__(self) -> str:
        return f"ID: {self.id}\nName: {self.firstname} {self.lastname}\nAge: {self.age}\nGender: {self.gender}\nWeight: {self.weight}\nAddress: {self.address}\nEmail: {self.email}\nPhone number: {self.phonenumber}\nRegistration Date: {self.registrationdate}"


def setup_database() -> None:
    """connects to the database, makes one if none exists. returns nothing."""
    global database_connection
    try:
        database_connection = sqlite3.connect("database.db")
        write_log_short(6, f"starting up using sqlite v{sqlite3.sqlite_version}")
    except sqlite3.Error as e:
        write_log_short(2, f"Failed to connect to database, got error {e}")
    finally:
        if database_connection:
            create_tables()
            return


def create_tables():
    statements = [
        """CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password BLOB(60),
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
        id BLOB(16) PRIMARY KEY,
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
        write_log_short(5, f"Tried to seed database, but ran into error {e}")
    finally:
        write_log_short(6, "Successfully seeded database (this happens at any startup)")
    database_connection.commit()


def create_test_admin(
    uname="test", testpw="password123", failedattempts=0, isadmin=True
):
    "creates a default test user"

    bcryptpass = bcrypt.hashpw(testpw.encode("utf-8"), bcrypt.gensalt())
    cur = database_connection.cursor()
    if cur.execute("SELECT 1 FROM users WHERE isadmin = 1").fetchone() != None:
        write_log_short(
            6, "Was told to make a new user for testing, but users table wasn't empty"
        )
        return
    try:
        cur.execute(
            "INSERT INTO users VALUES(?, ?, ?, ?)",
            (uname, bcryptpass, failedattempts, isadmin),
        )
        database_connection.commit()
    except sqlite3.Error as e:
        write_log_short(
            4, f"Tried to add a new user for testing, but ran into error {e}"
        )
    finally:
        write_log_short(6, "Added a new user for testing, with default credentials")


def seed_database():
    cursor = database_connection.cursor()
    seed_members = [Member.toTuple(Member.genrandom()) for _ in range(50)]
    cursor.executemany(
        "INSERT INTO members VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", seed_members
    )
    seed_users = [User.genRandom().toTuple() for _ in range(20)]
    cursor.executemany("INSERT INTO users VALUES(?, ?, ?, ?)", seed_users)
    database_connection.commit()
    write_log_short(6, "Successfully seeded members table")
    create_test_admin()


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


def unlock_account(adminname: User, usr: User):
    cur = database_connection.cursor()
    result = cur.execute(
        "SELECT * FROM users WHERE username = ?", (usr.username,)
    ).fetchone()
    if result == None:
        return
    admin: User = User.fromtuple(result)
    if not admin.isadmin:
        write_log_short(
            3,
            f"user {admin.username} tried to unlock {usr}'s account, but is not an admin.",
        )  # should not be possible to do, since I shouldn't be calling this function with a non-admin at all
        return
    cur.execute("UPDATE users SET failedlogins = 0 WHERE username=?", (usr.username,))
    database_connection.commit()
    write_log_short(6, f"{admin.username} unlocked {usr.username}'s account.")


def edit_member(member: Member):
    cur = database_connection.cursor()
    cur.execute("REPLACE INTO members VALUES(?,?,?,?,?,?,?,?,?,?)", member.toTuple())
    database_connection.commit()


def edit_user(usr: User):
    cur = database_connection.cursor()
    cur.execute("REPLACE INTO users VALUES(?,?,?,?)", usr.toTuple())
    database_connection.commit()


def get_all_members() -> list[Member]:
    cur = database_connection.cursor()
    members = cur.execute("SELECT * FROM members").fetchall()
    return [Member.fromtuple(row) for row in members]


def get_all_users(include_admins=False) -> list[User]:
    cur = database_connection.cursor()
    if include_admins:
        users = cur.execute("SELECT * FROM users").fetchall()
    else:
        users = cur.execute(
            "SELECT * FROM users WHERE isadmin = 0 ORDER BY username"
        ).fetchall()
    return [User.fromtuple(row) for row in users]


def attempt_login(uname: str, attemptPassword: str) -> Exception | User:
    "Returns an exception or a User, depending on success"

    uname = uname.lower()
    if uname == "super_admin" and attemptPassword == "Admin_123?":
        return Exception("SuperAdmin")
    cursor = database_connection.cursor()
    output = cursor.execute(
        "SELECT * FROM Users WHERE Username = ?", (uname,)
    ).fetchone()

    if output == None:
        return Exception("UserNotFound")

    usr: User = User.fromtuple(data=output)
    if usr.failedattempts >= 3:
        write_log_short(
            6, f"Attempted to log into account {uname}, but already failed thrice."
        )
        return Exception("TooManyFailedAttempts")
    elif not bcrypt.checkpw(attemptPassword.encode("utf-8"), usr.password):  # type: ignore
        cursor.execute(
            "UPDATE Users SET failedlogins = (failedlogins + 1) WHERE Username=?",
            (uname,),
        )
        database_connection.commit()
        write_log_short(6, f"Failed attempt to log into account {uname}")
        return Exception("WrongPassword")
    else:
        return usr


def write_log_short(severity: int, desc: str):
    newlog = LogPoint(severity=severity, desc=desc)
    write_log(newlog)


def write_log(logpoint: LogPoint):
    cursor = database_connection.cursor()
    # input(logpoint.toTuple())
    cursor.execute("INSERT INTO logs VALUES(?, ?, ?, ?)", logpoint.toTuple())
    database_connection.commit()
