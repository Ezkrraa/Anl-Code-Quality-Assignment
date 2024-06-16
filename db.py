# uuid v4, since it's unique and random, use UUID class for type hints
from uuid import uuid4, UUID

# typing is in python STD lib
from typing import Union

# for hashing, database, timestamps
import bcrypt, sqlite3, datetime

# for seeding and testing purposes
from faker import Faker

# random for seeding and stuff
from random import Random

# used for encrypting assymmetrically
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend

# for parsing b64 encrypted items
import base64

# for allowing hard copies
import copy

# for backups
import os, shutil


rand = Random()
fake = Faker()
database_connection: sqlite3.Connection


class LogPoint:
    id: UUID
    timestamp: datetime.datetime
    username: str
    severity: int
    description: str
    info: str
    suspicious: bool

    def __init__(self, username, severity, desc, info, suspicious=False):
        self.id = uuid4()
        self.timestamp = datetime.datetime.now()
        self.username = username
        self.severity = severity
        self.description = desc
        self.info = info
        self.suspicious = suspicious

    @classmethod
    def fromtuple(cls, data: tuple[bytes, str, str, int, str, str, bool]):
        return cls(data[2], data[3], data[4], data[5], data[6])

    def toTuple(self) -> tuple[bytes, str, str, int, str, str, bool]:
        return (
            self.id.bytes,
            self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            self.username,
            self.severity,
            self.description,
            self.info,
            self.suspicious,
        )

    def encrypt(self, key):
        new_log = copy.deepcopy(self)
        new_log.description = encrypt_data(key, self.description.encode())
        new_log.info = encrypt_data(key, self.info.encode())
        return new_log

    def decrypt(self, key):
        new_log = copy.deepcopy(self)
        new_log.description = decrypt_data(key, self.description)
        new_log.info = decrypt_data(key, self.info)
        return new_log


class User:
    id: UUID
    username: str
    password: bytes  # updated to bytes (stored as BLOB(16))
    role: str
    firstname: str
    lastname: str
    registrationdate: str
    isadmin: bool

    def __init__(
        self,
        uname,
        pw,
        role,
        fname,
        lname,
        regdate,
        isadmin=False,
        uid: bytes = uuid4().bytes,
    ) -> None:
        self.id: UUID = UUID(bytes=uid)
        self.username: str = uname
        self.password: bytes = pw
        self.role: str = role
        self.firstname: str = fname
        self.lastname: str = lname
        self.registrationdate: str = regdate
        self.isadmin: bool = isadmin

    @classmethod
    def fromtuple(cls, data: tuple[bytes, str, bytes, str, str, str, str, bool]):
        return cls(data[1], data[2], data[3], data[4], data[5], data[6], bool(data[7]), data[0])

    @classmethod
    def genRandom(cls):
        username = (fake.first_name() + str(rand.randint(1000, 9999))).lower()
        password = bcrypt.hashpw("password123".encode("utf-8"), bcrypt.gensalt())
        role = "Consultant"
        firstname = fake.first_name()
        lastname = fake.last_name()
        registrationdate = datetime.datetime.now().strftime("%Y-%m-%d")
        isadmin = False
        return cls(
            username,
            password,
            role,
            firstname,
            lastname,
            registrationdate,
            isadmin,
            uuid4().bytes,
        )

    def toTuple(self) -> tuple[bytes, str, bytes, str, str, str, str, bool]:
        return (
            self.id.bytes,
            self.username,
            self.password,
            self.role,
            self.firstname,
            self.lastname,
            self.registrationdate,
            self.isadmin,
        )

    def __str__(self) -> str:
        return f"Name: {self.username}\n\
            Role: {self.role}\n\
            Is {'' if self.isadmin else 'not '}an admin\n\
            Full name: {self.firstname} {self.lastname}\n\
            Registration Date: {self.registrationdate}"

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, User):
            return False
        return (
            self.id == value.id
            and self.username == value.username
            and self.password == value.password
            and self.role == value.role
            and self.firstname == value.firstname
            and self.lastname == value.lastname
            and self.registrationdate == value.registrationdate
            and self.isadmin == value.isadmin
        )

    def encrypt(self, key):
        new_user = User.fromtuple(self.toTuple())
        new_user.username = encrypt_data(key, self.username.encode())
        new_user.firstname = encrypt_data(key, self.firstname.encode())
        new_user.lastname = encrypt_data(key, self.lastname.encode())
        return new_user

    def decrypt(self, key):
        new_user = User.fromtuple(self.toTuple())
        new_user.username = decrypt_data(key, self.username)
        new_user.firstname = decrypt_data(key, self.firstname)
        new_user.lastname = decrypt_data(key, self.lastname)
        return new_user


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

    def __init__(self, fname, lname, age, gender, weight, addr, email, phone, regdate, id="0") -> None:
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
            data[0],
        )

    @classmethod
    def genrandom(cls):
        id = gen_memberid()
        firstname = fake.first_name()
        lastname = fake.last_name()
        age = rand.randint(20, 80)
        gender = rand.choice(["F", "F", "M", "M", "O"])
        weight = rand.randint(50, 110)
        cities = ["New York", "Los Angeles", "Chicago", "Houston", "Phoenix", "Philadelphia", "San Antonio", "San Diego", "Dallas", "San Jose"]
        city = rand.choice(cities)
        zip_code = f"{rand.randint(1000, 9999)}{rand.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ')}{rand.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ')}"
        address = f"{fake.street_address()}, {zip_code}, {city}"
        email = fake.email()
        phonenumber = "+31-6" + str(rand.randint(10000000, 99999999))
        registrationdate = str(datetime.datetime.now().date().today())
        return cls(
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
        return f"\
            ID: {self.id}\n\
            Name: {self.firstname} {self.lastname}\n\
            Age: {self.age}\n\
            Gender: {self.gender}\n\
            Weight: {self.weight}\n\
            Address: {self.address}\n\
            Email: {self.email}\n\
            Phone number: {self.phonenumber}\n\
            Registration Date: {self.registrationdate}"

    def fullname(self) -> str:
        return f"{self.firstname} {self.lastname}"

    def encrypt(self, key):
        new_member = copy.deepcopy(self)
        new_member.firstname = encrypt_data(key, self.firstname.encode())
        new_member.lastname = encrypt_data(key, self.lastname.encode())
        new_member.gender = encrypt_data(key, self.gender.encode())
        new_member.address = encrypt_data(key, self.address.encode())
        new_member.email = encrypt_data(key, self.email.encode())
        new_member.phonenumber = encrypt_data(key, self.phonenumber.encode())
        return new_member

    def decrypt(self, key):
        new_member = copy.deepcopy(self)
        new_member.firstname = decrypt_data(key, self.firstname)
        new_member.lastname = decrypt_data(key, self.lastname)
        new_member.gender = decrypt_data(key, self.gender)
        new_member.address = decrypt_data(key, self.address)
        new_member.email = decrypt_data(key, self.email)
        new_member.phonenumber = decrypt_data(key, self.phonenumber)
        return new_member


def setup_database() -> None:
    """connects to the database, makes one if none exists. returns nothing."""
    global database_connection
    try:
        database_connection = sqlite3.connect("database.db")
    except sqlite3.Error as e:
        raise Exception(f"Failed to connect to database, got error {e}")
    finally:
        if database_connection:
            create_tables()
            write_log_short(
                "",
                6,
                "Startup successful",
                f"starting up using sqlite v{sqlite3.sqlite_version}",
            )
            return
        else:
            raise Exception("Failed to connect to database, no connection was found")


def create_tables():
    statements = [
        """CREATE TABLE IF NOT EXISTS users (
        id BLOB(16) PRIMARY KEY,
        username TEXT UNIQUE,
        password BLOB(60),
        role TEXT,
        firstname TEXT,
        lastname TEXT,
        registrationdate TEXT,
        isadmin BOOLEAN
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
        registrationdate TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS logs (
        id BLOB(16) PRIMARY KEY,
        timestamp TEXT,
        username TEXT,
        severity INT,
        description TEXT,
        additional_info TEXT,
        suspicious BOOLEAN
        )""",
    ]
    try:
        cursor = database_connection.cursor()
        for statement in statements:
            cursor.execute(statement)
        cursor.close()
        database_connection.commit()
    except sqlite3.Error as e:
        write_log_short("", 4, "Seeding error", f"Tried to seed database, but ran into error {e}")


def load_public_key():
    if not os.path.exists("public_key.pem"):
        generate_keys()

    with open("public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
    return public_key


def encrypt_data(public_key, data: bytes):
    encrypted_data = public_key.encrypt(data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return base64.b64encode(encrypted_data).decode()


def load_private_key():
    if not os.path.exists("private_key.pem"):
        generate_keys()

    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())  # Assuming no password protection
    return private_key


def generate_keys() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    with open("private_key.pem", "wb") as private_key_file:
        private_key_file.write(
            private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
        )
    public_key = private_key.public_key()

    with open("public_key.pem", "wb") as public_key_file:
        public_key_file.write(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))

    write_log_short("", 6, "Generated keys", "Generated a new pair of RSA keys")


def decrypt_data(private_key, encrypted_data):
    decrypted_data = private_key.decrypt(base64.b64decode(encrypted_data), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return decrypted_data.decode()


def create_test_admin():
    "creates a default test user"
    testpw = "Admin_123?"
    bcryptpass = bcrypt.hashpw(testpw.encode("utf-8"), bcrypt.gensalt())
    cur = database_connection.cursor()
    if cur.execute("SELECT 1 FROM users WHERE isadmin = 1").fetchone() != None:
        write_log_short(
            "",
            5,
            "Seeding error",
            "Was told to make a new user for testing, but users table wasn't empty",
        )
        return
    try:
        cur.execute(
            "INSERT INTO users VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
            (User("admin", bcryptpass, "Admin", "mister admin", "a user", datetime.date.today(), True, uuid4().bytes).encrypt(load_public_key()).toTuple()),
        )
        cur.execute(
            "INSERT INTO users VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
            (User("user", bcryptpass, "Consultant", "mister user", "a user", datetime.date.today(), False, uuid4().bytes).encrypt(load_public_key()).toTuple()),
        )
        database_connection.commit()
        cur.close()
    except sqlite3.Error as e:
        write_log_short(
            "",
            4,
            "Seeding error",
            f"Tried to add a new user for testing, but ran into error {e}",
        )
    finally:
        write_log_short(
            "",
            6,
            "Seeded successfully",
            "Added a new user for testing, with default credentials",
        )


def seed_database():
    cursor = database_connection.cursor()
    seed_members = [Member.genrandom().encrypt(load_public_key()).toTuple() for _ in range(50)]
    cursor.executemany("INSERT INTO members VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", seed_members)
    seed_users = [User.genRandom().encrypt(load_public_key()).toTuple() for _ in range(20)]
    cursor.executemany("INSERT INTO users VALUES(?, ?, ?, ?, ?, ?, ?, ?)", seed_users)
    cursor.close()
    database_connection.commit()
    write_log_short("", 6, "Seeded successfully", "Successfully seeded members and users tables")
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
        anymembers = cur.execute("SELECT * FROM members WHERE id=?", (new_id,)).fetchone()
        if anymembers is None:
            return new_id


# any user can edit members
def edit_member(user: User, member: Member):
    if not is_valid_user(user):
        write_log_short(
            user.username,
            4,
            "Someone tried to edit a member without privileges",
            f"Someone attempted to edit a member without being a valid user.",
            True,
        )
        return
    cur = database_connection.cursor()
    cur.execute("REPLACE INTO members VALUES(?,?,?,?,?,?,?,?,?,?)", member.encrypt(load_public_key()).toTuple())
    cur.close()
    database_connection.commit()
    write_log_short(user.username, 3, "Edited member info", f"Changed {member.firstname} {member.lastname} info")


# only admins and above can delete members
def delete_member(admin: User, member: Member) -> bool:
    if not (is_valid_user(admin) and admin.isadmin):
        write_log_short(
            admin.username,
            4,
            "Someone tried to delete a member without privileges",
            f"Someone attempted to delete a member without being a valid admin.",
            True,
        )
        return False
    try:
        cur = database_connection.cursor()
        cur.execute("DELETE FROM members WHERE id=?", (member.id,))
        database_connection.commit()
        cur.close()
        write_log_short(
            admin.username,
            6,
            "Deleted account",
            f"Admin deleted the account of {member.firstname} {member.lastname}.",
        )
        return True
    except Exception as e:
        write_log_short(
            admin.username,
            4,
            "Deletion failure",
            f"Failed to delete member {member.firstname} {member.lastname} due to error {e}",
        )
        return False


# only admins and above may edit users
def edit_user(admin: User, new_user: User, old_user: User):
    if not is_valid_user(old_user) or new_user.id != old_user.id:
        write_log_short(
            admin.username,
            5,
            "Someone tried to edit a user that doesn't exist",
            f"Someone attempted to edit a user that does not exist. Invalid User: {old_user.username}",
            True,
        )
        return
    # bypass admin check if 'admin' isn't an admin but a user is only editing password, firstname or lastname (for changing passwords)
    if (
        is_valid_user(admin)
        and admin.id == new_user.id
        and admin.username == new_user.username
        and admin.isadmin == new_user.isadmin
        and admin.role == new_user.role
        and admin.registrationdate == new_user.registrationdate
    ):
        pass
    elif is_valid_user(admin) and admin.isadmin:
        pass
    else:
        write_log_short(
            admin.username,
            4,
            "Someone tried to edit a user without privileges",
            f"Someone attempted to edit a user without being both a valid user and an admin.",
            True,
        )
        return
    cur = database_connection.cursor()
    cur.execute("REPLACE INTO users VALUES(?,?,?,?,?,?,?,?)", new_user.encrypt(load_public_key()).toTuple())
    cur.close()
    database_connection.commit()
    write_log_short(admin.username, 5, "User edited", f"Admin edited a user. Old user: {old_user.username} => New user: {new_user.username}", True)
    return


# any user can create a member (consultant or above)
def create_member(user: User, member: Member):
    if not (is_valid_user(user)):
        write_log_short(
            user.username,
            4,
            "Someone tried to create a member without privileges",
            f"Someone attempted to create a member without being a valid user.",
            True,
        )
    cur = database_connection.cursor()
    cur.execute("INSERT INTO members VALUES(?,?,?,?,?,?,?,?,?,?)", member.encrypt(load_public_key()).toTuple())
    database_connection.commit()
    write_log_short(user.username, 4, "Member created", f"Someone created a member. New member: {member.fullname()}")


# admin and above can create a user
def create_user(admin: User, new_user: User):
    if not (is_valid_user(admin) and admin.isadmin):
        write_log_short(
            admin.username,
            4,
            "Someone tried to create a user without privileges",
            f"Someone attempted to create a user without being a valid user. Admin: {admin.username}",
            True,
        )
        return
    if new_user.isadmin and admin.username != "super_admin":
        write_log_short(
            admin.username,
            4,
            "Someone tried to create an admin without privileges",
            f"Someone attempted to create an admin without being super admin. User: {new_user.username}",
            True,
        )
        return
    cur = database_connection.cursor()
    cur.execute("INSERT INTO users VALUES(?,?,?,?,?,?,?,?)", new_user.encrypt(load_public_key()).toTuple())
    database_connection.commit()


def delete_user(admin: User, user: User) -> bool:
    # if admin or user are invalid, log and leave
    if not (is_valid_user(user) and is_valid_user(admin)):
        write_log_short(
            admin.username,
            4,
            "Someone tried to delete a user but messed with the inputs",
            f"Someone attempted to delete a user but the admin or user account was different from their version in the database.",
            True,
        )
        return False
    # if either admin isn't actually an admin, log and leave
    elif not admin.isadmin:
        write_log_short(
            admin.username,
            4,
            "Someone tried to delete a user without privileges",
            f"Someone attempted to delete a user without being a valid admin. User: {admin.username}",
            True,
        )
        return False
    # if trying to delete an admin without being super admin, log and leave
    elif user.isadmin and admin.username != "super_admin":
        write_log_short(
            admin.username,
            4,
            "Someone tried to delete an admin without privileges",
            f"Someone attempted to delete an admin without being super admin.",
            True,
        )
        return False

    try:
        cur = database_connection.cursor()
        cur.execute("DELETE FROM users WHERE id=?", (user.id.bytes,))
        database_connection.commit()
        cur.close()
        write_log_short(
            admin.username,
            6,
            "Deletion success",
            f"Admin deleted the account of {user.username}.",
        )
        return True
    except Exception as e:
        write_log_short(
            admin.username,
            4,
            "Deletion failure",
            f"Failed to delete user {user.username} due to error {e}",
        )
        return False


# any user can get all members (Consultant or above)
def get_all_members(user: User) -> list[Member]:
    if not is_valid_user(user):
        write_log_short(
            user.username,
            4,
            "Someone tried to get members without being a valid user",
            f"Someone attempted to get all members but wasn't a valid user.",
            True,
        )
    cur = database_connection.cursor()
    members = cur.execute("SELECT * FROM members").fetchall()
    write_log_short(user.username, 5, "User fetched members", f"User fetched all members.")
    return [Member.fromtuple(row).decrypt(load_private_key()) for row in members]


def get_all_users(user: User) -> list[User]:
    if not is_valid_user(user):
        write_log_short(
            user.username,
            4,
            "Someone tried to get users without being a valid user",
            f"Someone attempted to get all users but wasn't a valid user.",
            True,
        )
    cur = database_connection.cursor()
    if user.username == "super_admin":
        users = cur.execute("SELECT * FROM users").fetchall()
    else:
        users = cur.execute("SELECT * FROM users WHERE isadmin = 0 ORDER BY username").fetchall()
        write_log_short(user.username, 5, "Admin fetched users", f"Admin fetched all users.")
    return [User.fromtuple(row).decrypt(load_private_key()) for row in users]


def attempt_login(uname: str, attemptPassword: str) -> Exception | User:
    "Returns an exception or a User, depending on success"

    uname = uname.lower()
    if uname == "super_admin" and attemptPassword == "Admin_123?":
        write_log_short(uname, 5, "Super admin login", "Someone logged in as super admin")
        return Exception("SuperAdmin")

    cursor = database_connection.cursor()

    encrypted_users = cursor.execute("SELECT * FROM users").fetchall()
    output: Union[User, None] = None
    for i in range(len(encrypted_users)):
        curr_user = User.fromtuple(encrypted_users[i]).decrypt(load_private_key())
        if curr_user.username == uname:
            output = curr_user
            break

    if output is None:
        write_log_short("", 4, "Failed login", f"Failed attempt to log into account {uname}, which doesn't exist")
        return Exception("UserNotFound")

    usr: User = output
    if not bcrypt.checkpw(attemptPassword.encode("utf-8"), usr.password):
        write_log_short("", 6, "Failed login", f"Failed attempt to log into account {uname}")
        return Exception("WrongPassword")
    else:
        write_log_short(uname, 5, "Successful login", f"{uname} logged in successfully")
        return usr


def is_valid_user(user: User) -> bool:
    "checks whether there is either an exact copy of User in the database or its username is 'super_admin'."
    if user.username == "super_admin":
        return True
    cursor = database_connection.cursor()
    check_user = User.fromtuple(cursor.execute("SELECT * FROM users WHERE id=?", (user.id.bytes,)).fetchone()).decrypt(load_private_key())
    if check_user == None:
        return False
    return user.__eq__(check_user)


def search_members_and_users(user: User, search_key: str) -> list[Union[User, Member]]:
    if not is_valid_user(user):
        write_log_short(
            user.username,
            4,
            "Someone tried to search without privileges",
            f"Someone attempted to search users without being super admin. , Search query: {search_key}",
            True,
        )
        return []

    members = get_all_members(user)
    users = get_all_users(user)
    raw_search_key = search_key.lower()

    search_results = []
    for member in members:  # Search among all members
        if (
            any(raw_search_key in getattr(member, attr).lower() for attr in ["firstname", "lastname", "email", "phonenumber", "address", "registrationdate"])
            or raw_search_key == str(member.age)
            or raw_search_key in str(member.id)
        ):
            search_results.append(member)

    if user.isadmin:  # Admins and super_admin can see members and normal users
        for current_user in users:
            if not current_user.isadmin and (
                raw_search_key in current_user.username.lower()
                or raw_search_key in current_user.firstname.lower()
                or raw_search_key in current_user.lastname.lower()
                or raw_search_key in current_user.registrationdate.lower()
                or raw_search_key in current_user.role.lower()
            ):
                search_results.append(current_user)

    if user.username == "super_admin":  # Additional check if the current user is the super_admin
        for admin_user in users:  # Use a different variable name to avoid conflict
            # Check if search_key is in any of the admin_user's fields
            if any(raw_search_key.lower() in str(getattr(admin_user, field, "")).lower() for field in vars(admin_user)):
                # For super_admin, add other admins to the search results if the search key is in their fields
                if admin_user.isadmin and admin_user not in search_results:
                    search_results.append(admin_user)

    return search_results


def write_log_short(username: str, severity: int, desc: str, info: str, suspicious=False):
    newlog = LogPoint(username=username, severity=severity, desc=desc, info=info, suspicious=suspicious)
    write_log(newlog)


def write_log(logpoint: LogPoint):
    cursor = database_connection.cursor()
    cursor.execute("INSERT INTO logs VALUES(?, ?, ?, ?, ?, ?, ?)", logpoint.encrypt(load_public_key()).toTuple())
    cursor.close()
    database_connection.commit()


def get_all_logs(user: User) -> list[LogPoint]:
    if not is_valid_user(user):
        write_log_short(
            user.username,
            4,
            "Someone tried to get logs without being a valid user",
            f"Someone attempted to get all logs but wasn't a valid user. ",
            True,
        )
    cur = database_connection.cursor()
    logs = cur.execute("SELECT * FROM logs").fetchall()
    return [LogPoint.fromtuple(row).decrypt(load_private_key()) for row in logs]


def create_backup(admin: User):
    # Updated to include hours and minutes for multiple backups per day
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M")
    backups_dir = os.path.join(os.getcwd(), "backups")
    if not os.path.exists(backups_dir):
        os.makedirs(backups_dir)
    backup_filename = os.path.join(backups_dir, f"backup_{timestamp}.db")  # Include .db extension for clarity
    try:
        shutil.copyfile("database.db", backup_filename)
        write_log_short(admin.username, 6, "Backup successful", f"Created backup at {backup_filename}")
    except Exception as e:
        write_log_short(admin.username, 4, "Backup failed", f"Failed to create backup at {backup_filename} due to error {e}")


def restore_backup(admin: User, backup_date):
    backup_filename = f"{os.getcwd()}/backups/{backup_date}"  # Adjusted to current working directory
    if os.path.exists(backup_filename):
        try:
            shutil.copyfile(backup_filename, "database.db")
            write_log_short(admin.username, 6, "Backup restored", f"Restored backup from {backup_filename}")
        except Exception as e:
            write_log_short(admin.username, 4, "Backup restore failed", f"Failed to restore backup from {backup_filename} due to error {e}")
    else:
        write_log_short(admin.username, 4, "Backup restore failed", f"Failed to restore backup from {backup_filename}")


def show_backups():
    backups_dir = os.path.join(os.getcwd(), "backups")  # Define the backups directory path
    backups = [file for file in os.listdir(backups_dir) if file.startswith("backup_")]  # List only backup files from the /backups directory
    return backups
