# for masking password input, from STD lib
from getpass import getpass

# for casting and Union types
from typing import cast, Union

# for clearing the console
import platform, os

# for selection in a list of options
from pick import pick

# for hashing and salting passwords
import bcrypt

import datetime
import re
import random
import copy

from uuid import uuid4

# for database access
import db

rand = random
noclear: bool = False


logo = """
 █████╗ ███╗   ██╗██╗          ██████╗ ██╗  ██╗    ██╗  ██╗ █████╗ ███╗   ██╗██████╗ ██╗███╗   ██╗
██╔══██╗████╗  ██║██║         ██╔═══██╗██║  ██║    ██║  ██║██╔══██╗████╗  ██║██╔══██╗██║████╗  ██║
███████║██╔██╗ ██║██║         ██║   ██║███████║    ███████║███████║██╔██╗ ██║██║  ██║██║██╔██╗ ██║
██╔══██║██║╚██╗██║██║         ██║▄▄ ██║╚════██║    ██╔══██║██╔══██║██║╚██╗██║██║  ██║██║██║╚██╗██║
██║  ██║██║ ╚████║███████╗    ╚██████╔╝     ██║    ██║  ██║██║  ██║██║ ╚████║██████╔╝██║██║ ╚████║
╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝     ╚══▀▀═╝      ╚═╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝╚═╝  ╚═══╝
             made by Lucas de Haas (1061095), Ezra van der Kolk (1052307) and Tommy Tran (1061590)
"""


def show_logo() -> None:
    print(logo)


def show_message(err: str):
    clear_console()
    print(err)
    input("[Press enter to continue.]")


def clear_console():
    if noclear:
        return
    match (platform.system()):
        case "Windows":
            os.system("cls")
            return
        case _:
            os.system("clear")


def is_valid_input_str(pattern: str, input_value: str) -> bool:
    # Check if input exceeds maximum allowed length
    if len(input_value) > 50:
        print(f"Input exceeds maximum allowed length of 50 characters.")
        return False

    # Check if input contains a null byte
    if "\x00" in input_value:
        db.write_log_short(db.User.username, 2, "Input contains a null byte, which is not allowed.", "Null byte is not allowed in input.", True)
        print("Input contains a null byte, which is not allowed.")
        return False

    return bool(re.match(pattern, input_value))


def validate_int(number: str, min: int, max: int) -> bool:
    if len(number) > 50:
        print(f"Input exceeds maximum allowed length of 50 characters.")
        return False

    if "\x00" in number:
        db.write_log_short(db.User.username, 2, "Input contains a null byte, which is not allowed.", "Null byte is not allowed in input.", True)
        print("Input contains a null byte, which is not allowed.")
        return False

    try:
        number_int = int(number)
        return bool(min <= number_int <= max)
    except:
        print(f"The input was not a valid number")
        return False


def to_main_menu(usr: db.User):
    if usr.isadmin:
        admin_menu(usr)
    else:
        user_menu(usr)


def user_menu(usr: db.User):
    while True:
        clear_console()
        show_logo()
        user_options = [
            "Logout",
            "Search members",
            "Add Member",
            "Show all members",
            "Change Password",
        ]
        selection, index = pick(
            user_options,
            title=f"{logo}\nConsultant - MAIN MENU\nWelcome, {usr.username}!",
            indicator=">",
        )
        match index:
            case 0:
                show_message("Logging out now.")
                break
            case 1:
                clear_console()
                query = input("Search for a member:")
                show_search_menu(usr, query)
            case 2:
                add_member(usr)
                show_message("Member added successfully.")
            case 3:
                show_members(usr)
            case 4:
                change_password(usr)
                show_message("Password changed successfully.")


def add_member(user: db.User):
    while True:
        firstname = input("Enter First Name: ")
        while not is_valid_input_str(r"^[A-Za-z]*$", firstname):
            print("Invalid First Name. Please enter again.")
            firstname = input("Enter First Name: ")

        # names are alpha
        lastname = input("Enter Last Name: ")
        while not is_valid_input_str(r"^[A-Za-z]*$", lastname):
            print("Invalid Last Name. Please enter again.")
            lastname = input("Enter Last Name: ")

        # age is between 0 and 100 (exclusive)
        age = input("Enter Age: ")
        while not validate_int(age, 18, 100):
            print("Invalid Age. Please enter again.")
            age = input("Enter Age: ")
        age = int(age)

        # gender is a single character (normalized to uppercase)
        gender = input("Enter Gender (M, F, O): ").upper()
        while gender != "M" and gender != "F" and gender != "O":
            print("Invalid Gender. Please enter again.")
            gender = input("Enter Gender (M, F, O): ").upper()

        weight = input("Enter Weight: ")
        # human weight is between 0 and 700 (kg, exclusive)
        while not validate_int(weight, 0, 700):
            print("Invalid Weight. Please enter again.")
            weight = input("Enter Weight: ")
        weight = int(weight)

        cities = ["New York", "Los Angeles", "Chicago", "Houston", "Phoenix", "Philadelphia", "San Antonio", "San Diego", "Dallas", "San Jose"]

        # Prompt user for each field
        street_name = input("Enter Street Name: ")
        while not is_valid_input_str(r"^[A-Za-z]*$", street_name):
            print("Invalid Street Name. Please enter again.")
            street_name = input("Enter Street Name: ")
        house_number = input("Enter House Number: ").lower()
        while not is_valid_input_str(r"\d+[a-z]{0,1}$", house_number):
            print("Invalid house number. House numbers may be a number plus an optional character (example: 2c)")
            house_number = input("Enter house number: ")
        zip_code = input("Enter Zip Code (DDDDXX): ").upper()
        while not is_valid_input_str(r"\d{4}[a-zA-Z]{2}$", zip_code):
            print("Invalid Zip Code. Please enter again.")
            zip_code = input("Enter Zip Code (DDDDXX): ").upper()
        print("Select a City:")
        for i, city in enumerate(cities, start=1):
            print(f"{i}. {city}")
        while True:
            try:
                city_choice = int(input("Enter the number corresponding to your city: ")) - 1
                if not 0 <= city_choice < len(cities):
                    raise ValueError
                break  # Exit loop if input is valid
            except ValueError:
                print("Invalid input. Please enter a valid number corresponding to your city.")
        city = cities[city_choice]
        # Combine the address components
        address = f"{street_name}, {house_number}, {zip_code}, {city}"

        email = input("Enter Email: ")
        while not is_valid_input_str(r"[^@]+@[^@]+\.[^@]+", email):
            print("Invalid Email. Please enter again.")
            email = input("Enter Email: ")

        phonenumber = input("Enter Phone Number: +31-6")
        while not is_valid_input_str(r"^[0-9]{8}$", phonenumber):
            print("Invalid Phone Number. Please enter again.")
            phonenumber = input("Enter Phone Number: +31-6")

        new_member = db.Member(
            firstname,
            lastname,
            age,
            gender,
            weight,
            address,
            email,
            str("+31-6") + phonenumber,
            datetime.date.today(),
            db.gen_memberid(),
        )
        db.create_member(user, new_member)
        break


def add_user(admin: db.User, make_admin: bool = False):
    while True:
        username = input("Enter Username: ").lower()
        while not is_valid_input_str(r"^[a-zA-Z_][a-zA-Z0-9_'\.]{7,10}$", username):
            print("Invalid Username. Please enter again.")
            print("Username must be unique and have a length of at least 8 characters")
            print("Must be no longer than 10 characters")
            print("Must be started with a letter or underscores (_)")
            print("Can contain letters (a-z), numbers (0-9), underscores (_), apostrophes ('), and periods (.)")
            print("No distinguish between lowercase or uppercase letters")
            username = input("Enter Username: ")

        first_name = input("Enter First Name: ").title()
        while not is_valid_input_str(r"^[A-Za-z]*$", first_name):
            print("Invalid First Name. Please enter again.")
            first_name = input("Enter First Name: ").title()

        last_name = input("Enter Last Name: ").title()
        while not is_valid_input_str(r"^[A-Za-z]*$", last_name):
            print("Invalid Last Name. Please enter again.")
            last_name = input("Enter Last Name: ").title()

        temp_pw = f"TempPassword-{str(hex(rand.getrandbits(32))[2:])}"
        new_consultant = db.User(
            username,
            bcrypt.hashpw(
                temp_pw.encode("utf-8"),
                bcrypt.gensalt(),
            ),
            role="Consultant" if not make_admin else "Admin",
            fname=first_name,
            lname=last_name,
            regdate=datetime.date.today(),
            isadmin=make_admin,
            uid=uuid4().bytes,
        )
        result = db.create_user(admin, new_consultant)
        if isinstance(result, Exception):
            match (str(result)):
                case "DuplicateError":
                    show_message("A user with this username already exists.")
                case "PrivilegeError":
                    show_message("You are not a valid admin.")
                case _:
                    show_message(f"Error: {result}")
            break
        show_message(f"Created {'admin' if make_admin else 'consultant'} with the password {temp_pw}.")
        break


def change_password(usr: db.User):
    old_user = copy.deepcopy(usr)
    while True:
        clear_console()
        show_logo()
        print("Enter your current password:")
        current_pw = getpass("> ")
        if not bcrypt.checkpw(current_pw.encode("utf-8"), usr.password):
            show_message("Invalid password. Try again.")
            continue
        print("Enter your new password:")
        new_pw = getpass("> ")
        while not is_valid_input_str(r"^(?=.*[A-Z].*[a-z].*[\d].*[!@#$%^&*()_+={}\[\]:;'\"?,.<>\/-]).{12,30}$", new_pw):
            print("Invalid Password. Please enter again.")
            print("Password must have a length of at least 12 characters")
            print("Must be no longer than 30 characters")
            print("Can contain letters (a-z), (A-Z), numbers (0-9), Special characters such as ~!@#$%&_-+=`|\\(){}[]:;'<>,.?/")
            print("Must have a combination of at least one lowercase letter, one uppercase letter, one digit, and one special character")
            new_pw = getpass("> ")
        print("Confirm your new password:")
        confirm_pw = getpass("> ")
        if new_pw != confirm_pw:
            show_message("Passwords do not match.")
            continue
        new_crypt_pw = bcrypt.hashpw(new_pw.encode("utf-8"), bcrypt.gensalt())
        usr.password = new_crypt_pw
        db.edit_user(usr, usr, old_user)
        show_message("Password changed successfully.")
        break


def reset_password(admin: db.User, user: db.User):
    old_user = copy.deepcopy(user)
    new_pw = f"TempPassword-{str(hex(rand.getrandbits(32))[2:])}"
    new_crypt_pw = bcrypt.hashpw(new_pw.encode("utf-8"), bcrypt.gensalt())
    user.password = new_crypt_pw
    db.edit_user(admin, user, old_user)
    show_message(f"Password reset for {user.username}. New password: {new_pw}")


def show_members(user: db.User) -> None:
    while True:
        clear_console()
        options = ["Return"]
        members = db.get_all_members(user)
        options.extend([f"First name: {members[i].firstname} - Last name: {members[i].lastname}" for i in range(len(members))])
        selection, index = pick(options, title=f"{logo}\nMember menu", indicator=">")
        match index:
            case 0:
                return
            case _:
                show_member(user, members[cast(int, index) - 1])


def show_member(user: db.User, member: db.Member) -> None:
    while True:
        options = ["Return to user menu", "Edit information"]
        if user.isadmin:
            options.append("Delete member")
        result, index = pick(options=options, title=f"{logo}Member Info:\n{member}", indicator=">")
        match index:
            case 0:
                return
            case 1:
                edit_member(user, member)
            case 2 if user.isadmin:
                confirm_options = ["No", "Yes"]
                _, index = pick(options=confirm_options, title=f"Are you sure you want to delete {member.fullname()}'s account?", indicator=">")
                match index:
                    case 0:
                        show_message(f"Not deleting {member.firstname} {member.lastname}'s account.")
                        continue
                    case 1:
                        db.delete_member(user, member)
                        show_message(f"Successfully deleted {member.firstname} {member.lastname}'s account.")
                        return


def show_log(log: db.LogPoint) -> None:
    while True:
        options = ["Return"]
        result, index = pick(options=options, title=f"{logo}Log Info:\n{log}", indicator=">")
        match index:
            case 0:
                return


def edit_member(user: db.User, member: db.Member):
    while True:
        options = [
            "Return without saving",
            "Return and save",
            f"First name: {member.firstname}",
            f"Last name: {member.lastname}",
            f"Age: {member.age}",
            f"Gender: {member.gender}",
            f"Weight: {member.weight}",
            f"Address: {member.address}",
            f"Email: {member.email}",
            f"Phone number: {member.phonenumber}",
        ]
        result, index = pick(options=options, title=f"{logo}Edit member info:", indicator=">")
        match index:
            case 0:
                break
            case 1:
                db.edit_member(user, member)
                break
            case _:
                member = change_member(cast(int, index) - 2, member, input("Enter new value:"))


def change_member(index: int, member: db.Member, new_value: str) -> db.Member:
    match index:
        case 0:
            member.firstname = new_value
        case 1:
            member.lastname = new_value
        case 2:
            try:
                member.age = int(new_value)
            except ValueError:
                return member
        case 3:
            member.gender = new_value
        case 4:
            try:
                member.weight = int(new_value)
            except ValueError:
                return member
        case 5:
            member.address = new_value
        case 6:
            member.email = new_value
        case 7:
            member.phonenumber = new_value
    return member


def show_users(currentUser: db.User) -> None:
    while True:
        clear_console()
        users: list[db.User] = db.get_all_users(currentUser)
        options = ["Return to main menu"]
        options.extend([f"Role: {users[i].role} Username: {users[i].username}" for i in range(len(users))])
        selection, index = pick(options, title=f"{logo}\nUser menu", indicator=">")
        match index:
            case 0:
                return
            case _:
                show_user(currentUser, users[cast(int, index) - 1])


def show_user(currentUser: db.User, usr: db.User) -> None:
    while True:
        options = ["Return", "Edit information", "Delete user", "Reset password"]
        result, index = pick(options=options, title=f"{logo}User Info:\n{usr}", indicator=">")
        match index:
            case 0:
                break
            case 1:
                edit_user(currentUser, usr)
            case 2:
                confirm_options = ["No", "Yes"]
                _, index = pick(options=confirm_options, title=f"Are you sure you want to delete {usr.username}'s account?", indicator=">")
                match index:
                    case 0:
                        show_message(f"Not deleting {usr.username}'s account.")
                        continue
                    case 1:
                        db.delete_user(currentUser, usr)
                        show_message(f"Successfully deleted {usr.username}'s account.")
                        return
            case 3:
                reset_password(currentUser, usr)
                return
            case _:
                continue


def edit_user(currentUser: db.User, user: db.User) -> None:
    select: int = 0
    old_user = copy.deepcopy(user)
    while True:
        options = ["Return without saving", "Return and save", f"Username: {user.username}", f"First name: {user.firstname}", f"Last name: {user.lastname}"]
        if currentUser.username == "super_admin":
            options.append(f"Is {'an' if user.isadmin else 'not an'} admin")
        result, index = pick(
            options=options,
            title=f"{logo}Edit user info:",
            indicator=">",
            default_index=select,
        )
        match index:
            case 0:
                break
            case 1:
                db.edit_user(currentUser, user, old_user)
                break
            case 2:
                user.username = input("Enter Username: ")
                while not is_valid_input_str(r"^[a-zA-Z_][a-zA-Z0-9_'\.]{7,10}$", user.username):
                    print("Invalid Username. Please enter again.")
                    print("Username must be unique and have a length of at least 8 characters")
                    print("Must be no longer than 10 characters")
                    print("Must be started with a letter or underscores (_)")
                    print("Can contain letters (a-z), numbers (0-9), underscores (_), apostrophes ('), and periods (.)")
                    print("No distinguish between lowercase or uppercase letters")
                    user.username = input("Enter Username: ")
            case 3:
                user.firstname = input("Enter First Name: ").title()
                while not is_valid_input_str(r"^[A-Za-z]*$", user.firstname):
                    print("Invalid First Name. Please enter again.")
                    user.firstname = input("Enter First Name: ").title()
            case 4:
                user.lastname = input("Enter Last Name: ").title()
                while not is_valid_input_str(r"^[A-Za-z]*$", user.lastname):
                    print("Invalid Last Name. Please enter again.")
                    user.lastname = input("Enter Last Name: ").title()
            case 5 if currentUser.username == "super_admin":
                select = 3
                user.isadmin = not user.isadmin


def admin_menu(admin: db.User):
    while True:
        clear_console()
        show_logo()
        admin_options = [
            "Logout",
            "Search members and consultants",
            "Show members",
            "Show consultants",
            "Add consultant",
            "Show logs",
            "Create/restore backups",
            "Change password",
        ]
        selection, index = pick(
            admin_options,
            title=f"{logo}\nADMIN - MAIN MENU\nWelcome, {admin.username}!",
            indicator=">",
        )
        match index:
            case 0:
                show_message("Logging out now.")
                break
            case 1:
                clear_console()
                query = input("Search for a member:")
                show_search_menu(admin, query)
            case 2:
                show_members(admin)
            case 3:
                show_users(admin)
            case 4:
                add_user(admin, False)
            case 5:
                show_logs(admin)
            case 6:
                clear_console()
                backup_menu(admin)
            case 7:
                change_password(admin)
                show_message("Changed password successfully.")
            case _:
                show_message("Invalid option.")


def super_admin_menu():
    super_admin: db.User = db.User(
        "super_admin",
        bcrypt.hashpw("Admin_123?".encode("utf-8"), bcrypt.gensalt()),
        "super",
        "admin",
        "",
        -1,
        True,
    )
    while True:
        su_admin_options = [
            "Logout",
            "Search members and users",
            "Show members",
            "Show admins and consultants",
            "Add a member",
            "Add a consultant",
            "Add an admin",
            "Show logs",
            "Create/restore backups",
        ]
        selection, index = pick(
            su_admin_options,
            title=f"{logo}\nSUPER ADMIN - MAIN MENU\nWelcome, super admin!",
            indicator=">",
        )
        match index:
            case 0:
                show_message("Logging out now.")
                break
            case 1:
                clear_console()
                query = input("Search for a member:")
                show_search_menu(super_admin, query)
            case 2:
                show_members(super_admin)
            case 3:
                show_users(super_admin)
            case 4:
                clear_console()
                add_member(super_admin)
            case 5:
                clear_console()
                add_user(super_admin, False)
            case 6:
                clear_console()
                add_user(super_admin, True)
            case 7:
                show_logs(super_admin)
            case 8:
                clear_console()
                backup_menu(super_admin)
            case _:
                show_message("Invalid option.")
                continue


def login_screen() -> None:
    fails = 0
    while fails < 3:
        clear_console()
        show_logo()
        print("LOGIN SCREEN\nTo login to the application, enter your username:")
        uname = input("> ")
        print("enter password:")
        unhashed_pw = getpass("> ")
        attempt = db.attempt_login(uname=uname, attemptPassword=unhashed_pw)
        match (attempt):
            case e if isinstance(e, db.User):
                to_main_menu(cast(db.User, attempt))
                return
            case e if isinstance(e, Exception) and (str(attempt) == "UserNotFound" or str(attempt) == "WrongPassword"):
                show_message(f"No user found with that username and password.")
                fails += 1
            case e if isinstance(e, Exception) and str(attempt) == "SuperAdmin":
                super_admin_menu()
                return
            case e if isinstance(e, Exception):
                show_message(str(attempt))

    show_message("Failed to login thrice, returning to main menu")
    db.write_log_short(uname, 5, "Failed to login thrice.", "Failed to login thrice.", True)


def home_screen() -> None:
    while True:
        clear_console()
        options = [
            "Exit",
            "Login",
        ]
        _, num = pick(
            options,
            title=f"{logo}\nMain menu\nIn this application, use ↑ and ↓ to select, and [Enter] to confirm.",
            indicator=">",
        )
        match num:
            case 0:
                return
            case 1:
                login_screen()


def show_search_menu(currentUser: db.User, search_key: str):
    while True:
        clear_console()
        results: list[Union[db.Member, db.User]] = db.search_members_and_users(currentUser, search_key)
        options = ["Return to main menu"]
        max_len: int = get_max(results)
        for i, result in enumerate(results):
            if isinstance(result, db.Member):
                options.append(f"Member: {result.fullname()}{' ' * (max_len - len(f'Member: {result.fullname()}'))} - ID: {result.id}")
            elif isinstance(result, db.User):
                options.append(
                    f"{result.role.title()}: {result.username}{' ' * (max_len - len(f'{result.role}: {result.username}'))} - {result.firstname} {result.lastname}"
                )  # TODO: add padding

        selection, index = pick(options, title=f"{logo}\nSearch Results", indicator=">")
        if index == 0:
            return
        else:
            selected_result = results[cast(int, index) - 1]
            if isinstance(selected_result, db.Member):
                show_member(currentUser, selected_result)
            elif isinstance(selected_result, db.User):
                show_user(currentUser, selected_result)


def show_logs(user: db.User) -> None:
    while True:
        clear_console()
        options = ["Return", "ID - Severity - Timestamp - Username - Description - Info - Suspicious"]
        logs = db.get_all_logs(user)
        options.extend(
            [
                f"{i} - {logs[i].severity} - {logs[i].timestamp.strftime('%Y-%m-%d %H:%M:%S')} - {logs[i].username} - {logs[i].description} - {logs[i].info} - {'Yes' if logs[i].suspicious else 'No'}"
                for i in range(len(logs))
            ]
        )
        selection, index = pick(options, title=f"{logo}\nLogs menu", indicator=">")
        if isinstance(index, int):
            if index == 0:
                return
            if index > 1:  # to prevent them from selecting -1
                show_log(logs[index - 2])
            continue
        return


def get_max(lst: list[Union[db.User, db.Member]]) -> int:
    max_len = 0
    for obj in lst:
        if isinstance(obj, db.Member):
            max_len = max(len(f"Member: {obj.fullname()}"), max_len)
        elif isinstance(obj, db.User):
            max_len = max(max_len, len(f"{obj.role}: {obj.username}"))
    return max_len


def backup_menu(admin: db.User):
    while True:
        clear_console()
        options = ["Return", "Create backup", "Restore backup"]
        selection, index = pick(options, title=f"{logo}\nBackup menu", indicator=">")
        match index:
            case 0:
                return
            case 1:
                db.create_backup(admin)
            case 2:
                restore_backups(admin)
            case _:
                show_message("Invalid option.")


def restore_backups(admin: db.User):
    while True:
        clear_console()
        options = ["Return"]
        backups = db.show_backups()
        if backups is not None:
            options.extend([f"{backups[i]}" for i in range(len(backups))])
            selection, index = pick(options, title=f"{logo}\nRestore backup", indicator=">")
            match index:
                case 0:
                    return
                case _:
                    db.restore_backup(admin, backups[cast(int, index) - 1])
                    show_message(f"Restored backup {backups[cast(int, index) - 1]}")
        else:
            show_message("No backups available.")
            return
