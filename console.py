# for masking password input
from getpass import getpass

from typing import cast, Union

# for clearing the console
import platform, os

# from pick import pick  # TODO: write own
import db
import bcrypt
import datetime
import re

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
            "Search members",
            "Add Member",
            "Show all members",
            "Change Password",
            "Logout",
        ]
        selection, index = pick(
            user_options,
            title=f"{logo}\nConsultant - MAIN MENU\nWelcome, {usr.username}!",
        )
        match index:
            case 0:
                query = input("Search for a member:")
                show_search_menu(usr, query)
            case 1:
                add_member()
                show_message("Member added successfully.")
            case 2:
                show_members(usr)
            case 3:
                change_password(usr)
                show_message("Password changed successfully.")
            case 4:
                show_message("Logging out now.")
                break
            case _:
                show_message("Invalid option.")

def add_member():
    while True:
        firstname = input("Enter First Name: ")
        while not re.match("^[A-Za-z]*$", firstname):
            print("Invalid First Name. Please enter again.")
            firstname = input("Enter First Name: ")

        lastname = input("Enter Last Name: ")
        while not re.match("^[A-Za-z]*$", lastname):
            print("Invalid Last Name. Please enter again.")
            lastname = input("Enter Last Name: ")

        age = input("Enter Age: ")
        while not age.isdigit() or int(age) < 0:
            print("Invalid Age. Please enter again.")
            age = input("Enter Age: ")
        age = int(age)

        gender = input("Enter Gender: ")
        while gender not in ['M', 'F']:
            print("Invalid Gender. Please enter again.")
            gender = input("Enter Gender: ")

        weight = input("Enter Weight: ")
        while not weight.isdigit() or int(weight) < 0:
            print("Invalid Weight. Please enter again.")
            weight = input("Enter Weight: ")
        weight = int(weight)

        address = input("Enter Address: ")

        email = input("Enter Email: ")
        while not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            print("Invalid Email. Please enter again.")
            email = input("Enter Email: ")

        phonenumber = input("Enter Phone Number: ")
        while not re.match("^[0-9]*$", phonenumber):
            print("Invalid Phone Number. Please enter again.")
            phonenumber = input("Enter Phone Number: ")


        new_member = db.Member(
            firstname,
            lastname,
            age,
            gender,
            weight,
            address,
            email,
            phonenumber,
            datetime.date.today(),
            db.gen_memberid(),
        )
        db.create_member(new_member)
        break

def add_consultant():
    while True:
        username = input("Enter Username: ")
        while not re.match("^[a-zA-Z_][a-zA-Z0-9_'\.]{7,10}$", username):
            print("Invalid Username. Please enter again.")
            print("Username must be unique and have a length of at least 8 characters")
            print("Must be no longer than 10 characters")
            print("Must be started with a letter or underscores (_)")
            print("Can contain letters (a-z), numbers (0-9), underscores (_), apostrophes ('), and periods (.)")
            print("No distinguish between lowercase or uppercase letters")
            username = input("Enter Username: ")

        password = input("Enter Password: ")
        while not re.match("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[~!@#$%&_-+=`|\(){}[\]:;'<>,.?/])[A-Za-z\d~!@#$%&_-+=`|\(){}[\]:;'<>,.?/]{12,30}$", password):
            print("Invalid Password. Please enter again.")
            print("Password must have a length of at least 12 characters")
            print("Must be no longer than 30 characters")
            print("Can contain letters (a-z), (A-Z), numbers (0-9), Special characters such as ~!@#$%&_-+=`|\\(){}[]:;'<>,.?/")
            print("Must have a combination of at least one lowercase letter, one uppercase letter, one digit, and one special character")
            password = input("Enter Password: ")

        first_name = input("Enter First Name: ")
        while not re.match("^[A-Za-z]*$", firstname):
            print("Invalid First Name. Please enter again.")
            firstname = input("Enter First Name: ")

        last_name = input("Enter Last Name: ")
        while not re.match("^[A-Za-z]*$", lastname):
            print("Invalid Last Name. Please enter again.")
            lastname = input("Enter Last Name: ")

        new_consultant = db.User(
            username,
            bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()),
            role="Consultant",
            fname=first_name,
            lname=last_name,
            regdate=datetime.date.today(),
            isadmin=False,
        )
        db.create_user(new_consultant)
        break


def change_password(usr: db.User):
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
        while not re.match("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[~!@#$%&_-+=`|\(){}[\]:;'<>,.?/])[A-Za-z\d~!@#$%&_-+=`|\(){}[\]:;'<>,.?/]{12,30}$", new_pw):
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
        db.edit_user(usr)
        show_message("Password changed successfully.")
        break


def show_members(user: db.User) -> None:
    while True:
        clear_console()
        options = ["Return"]
        members = db.get_all_members()
        options.extend(
            [
                f"[{(1 + i):02}] {members[i].firstname} {members[i].lastname}"
                for i in range(len(members))
            ]
        )
        selection, index = pick(options, title=f"{logo}\nMember menu")
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
        result, index = pick(options=options, title=f"{logo}Member Info:\n{member}")
        match index:
            case 0:
                return
            case 1:
                edit_member(member)
            case 2 if user.isadmin:
                confirm_options = ["Yes", "No"]
                _, index = pick(
                    options=confirm_options,
                    title=f"Are you sure you want to delete {member.firstname} {member.lastname}'s account?",
                )
                match index:
                    case 0:
                        db.delete_member(user, member)
                        show_message(
                            f"Successfully deleted {member.firstname} {member.lastname}'s account."
                        )
                        return
                    case 1:
                        show_message(
                            f"Not deleting {member.firstname} {member.lastname}'s account."
                        )
                        continue


def edit_member(member: db.Member):
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
        result, index = pick(options=options, title=f"{logo}Edit member info:")
        match index:
            case 0:
                break
            case 1:
                db.edit_member(member)
                break
            case _:
                member = change_member(
                    cast(int, index) - 2, member, input("Enter new value:")
                )


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
        users: list[db.User] = db.get_all_users(currentUser.isadmin)
        options = ["Return to main menu"]
        # input(users)
        options.extend([f"[{i:02}] {users[i].username}" for i in range(len(users))])
        selection, index = pick(options, title=f"{logo}\nUser menu")
        match index:
            case 0:
                return
            case _:
                show_user(currentUser, users[cast(int, index) - 1])


def show_user(currentUser: db.User, usr: db.User) -> None:
    while True:
        options = ["Return", "Edit information", "Delete user"]
        result, index = pick(
            options=options,
            title=f"{logo}User Info:\n{usr}",
        )
        match index:
            case 0:
                break
            case 1:
                edit_user(currentUser, usr)
            case 2:
                confirm_options = ["Yes", "No"]
                _, index = pick(
                    options=confirm_options,
                    title=f"Are you sure you want to delete {usr.username}'s account?",
                )
                match index:
                    case 0:
                        db.delete_user(currentUser, usr)
                        show_message(f"Successfully deleted {usr.username}'s account.")
                        return
                    case 1:
                        show_message(f"Not deleting {usr.username}'s account.")
                        continue
            case _:
                continue


def edit_user(currentUser: db.User, usr: db.User) -> None:
    while True:
        options = [
            "Return without saving",
            "Return and save",
            f"Username: {usr.username}",
            f"Is {'an' if usr.isadmin else 'not an'} admin",
        ]
        result, index = pick(options=options, title=f"{logo}Edit member info:")
        match index:
            case 0:
                break
            case 1:
                db.edit_user(usr)
                break
            case 2:
                usr.username = input("Enter Username: ")
                while not re.match("^[a-zA-Z_][a-zA-Z0-9_'\.]{7,10}$", usr.username):
                      print("Invalid Username. Please enter again.")
                      print("Username must be unique and have a length of at least 8 characters")
                      print("Must be no longer than 10 characters")
                      print("Must be started with a letter or underscores (_)")
                      print("Can contain letters (a-z), numbers (0-9), underscores (_), apostrophes ('), and periods (.)")
                      print("No distinguish between lowercase or uppercase letters")
                      usr.username = input("Enter Username: ")
            case 3:
                usr.isadmin = not usr.isadmin


def change_user(option: int, usr: db.User, value: str) -> db.User:
    value = value.lower()
    match option:
        case 0:
            usr.username = value
    return usr


def admin_menu(admin: db.User):
    while True:
        clear_console()
        show_logo()
        admin_options = [
            "Search members",
            "Show members",
            "Show consultants",
            "Add Consultant",
            "Change Password",
            "Logout",
        ]
        selection, index = pick(
            admin_options,
            title=f"{logo}\nADMIN - MAIN MENU\nWelcome, {admin.username}!",
        )
        match index:
            case 0:
                query = input("Search for a member:")
                show_search_menu(admin, query)
            case 1:
                show_members(admin)
            case 2:
                show_users(admin)
            case 3:
                add_consultant()
                show_message("Consultant added successfully.")
            case 4:
                change_password(admin)
                show_message(f"{admin} password changed successfully.")
            case 5:
                show_message("Logging out now.")
                break
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
        su_admin_options = [ "Search Members", "Show members", "Show admins and consultants", "Logout"]
        selection, index = pick(
            su_admin_options,
            title=f"{logo}\nSUPER ADMIN - MAIN MENU\nWelcome, super admin!",
        )
        match index:
            case 0:
                query = input("Search for a member:")
                show_search_menu(super_admin, query, isSuperAdmin=True)
            case 1:
                show_members(super_admin)
            case 2:
                show_users(super_admin)
            case 3:
                show_message("Logging out now.")
                break
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
            case e if isinstance(e, Exception) and (
                str(attempt) == "UserNotFound" or str(attempt) == "WrongPassword"
            ):
                show_message(f"No user found with that username and password.")
                fails += 1
            case e if isinstance(e, Exception) and str(attempt) == "SuperAdmin":
                super_admin_menu()
                return
            case e if isinstance(e, Exception):
                show_message(str(attempt))
    show_message("Failed to login thrice, returning to main menu")


def home_screen() -> None:
    while True:
        clear_console()
        options = ["Login", "Exit"]
        _, num = pick(options, title=f"{logo}\nMain menu")
        match num:
            case 0:
                login_screen()
            case 1:
                return


def pick(options: list[str], title: str = "") -> tuple[str, int]:
    while True:
        clear_console()
        print(title)
        for i in range(len(options)):
            print(f"[{i:02}] {options[i]}")
        try:
            selection = int(input("Select an option"))
            if 0 < selection < len(options):
                return (options[selection], selection)
        except TypeError:
            show_message("Incorrect number format.")
            continue


def show_search_menu(currentUser: db.User, search_key: str, isSuperAdmin: bool = False):
    while True:
        clear_console()
        # Perform search based on search_key
        results: list[Union[db.Member, db.User]] = db.search_members_and_users(search_key, include_users=isSuperAdmin)

        options = ["Return to main menu"]
        for i, result in enumerate(results):
            if isinstance(result, db.Member):
                options.append(f"[{i:02}] Member: {result.firstname} {result.lastname} - ID: {result.id}")
            elif isinstance(result, db.User):
                options.append(f"[{i:02}] User: {result.username}")

        # Display the menu and get the user's selection
        selection, index = pick(options, title=f"{logo}\nSearch Results")
        if index == 0:
            return
        else:
            selected_result = results[cast(int, index) - 1]
            if isinstance(selected_result, db.Member):
                show_member(currentUser, selected_result)
            elif isinstance(selected_result, db.User):
                show_user(currentUser, selected_result)