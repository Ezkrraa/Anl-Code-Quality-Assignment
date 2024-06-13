# for masking password input
from getpass import getpass

from typing import cast

# for clearing the console
import platform, os
from pick import pick
import db

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


def show_error(err: str):
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
        user_options = ["Search members", "Show all members", "Logout"]
        selection, index = pick(
            user_options,
            title=f"{logo}\nConsultant - MAIN MENU\nWelcome, {usr.username}!",
            indicator=">",
        )
        match index:
            case 0:
                clear_console()
                members = db.get_all_members()
                query = input("Search for a member:")
                # TODO: add search function
            case 1:
                show_members(usr)
            case 2:
                show_error("Logging out now.")
                break
            case _:
                show_error("Invalid option.")


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
        selection, index = pick(options, indicator=">", title=f"{logo}\nMember menu")
        match index:
            case 0:
                return
            case _:
                show_member(user, members[cast(int, index) - 1])


def show_member(user: db.User, member: db.Member) -> None:
    while True:
        options = ["Return to user menu", "Edit information", "Delete member"]
        result, index = pick(
            options=options, indicator=">", title=f"{logo}Member Info:\n{member}"
        )
        match index:
            case 0:
                return
            case 1:
                edit_member(member)
            case 2:
                confirm_options = ["Yes", "No"]
                _, index = pick(
                    options=confirm_options,
                    title=f"Are you sure you want to delete {member.firstname} {member.lastname}'s account?",
                    indicator="> ",
                )
                match index:
                    case 0:
                        db.delete_member(user, member)
                        show_error(
                            f"Successfully deleted {member.firstname} {member.lastname}'s account."
                        )
                        return
                    case 1:
                        show_error(
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
        result, index = pick(
            options=options, indicator=">", title=f"{logo}Edit member info:"
        )
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
        selection, index = pick(options, indicator=">", title=f"{logo}\nUser menu")
        match index:
            case 0:
                return
            case _:
                show_user(currentUser, users[cast(int, index) - 1])


def show_user(currentUser: db.User, usr: db.User) -> None:
    resettable = False
    if currentUser.isadmin and usr.failedattempts >= 3:
        resettable = True
    while True:
        options = ["Return", "Edit information", "Delete user"]
        if resettable:
            options.append("Unlock user")
        result, index = pick(
            options=options, title=f"{logo}User Info:\n{usr}", indicator=">"
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
                    indicator="> ",
                )
                match index:
                    case 0:
                        db.delete_user(currentUser, usr)
                        show_error(f"Successfully deleted {usr.username}'s account.")
                        return
                    case 1:
                        show_error(f"Not deleting {usr.username}'s account.")
                        continue
            case 3:
                if resettable:
                    db.unlock_account(currentUser, usr)
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
        result, index = pick(
            options=options, indicator=">", title=f"{logo}Edit member info:"
        )
        match index:
            case 0:
                break
            case 1:
                db.edit_user(usr)
                break
            case 2:
                usr.username = input("Enter new username:")
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
        admin_options = ["Show members", "Show consultants", "Logout"]
        selection, index = pick(
            admin_options,
            title=f"{logo}\nADMIN - MAIN MENU\nWelcome, {admin.username}!",
            indicator=">",
        )
        match index:
            case 0:
                show_members(admin)
            case 1:
                show_users(admin)
            case 2:
                show_error("Logging out now.")
                break
            case _:
                show_error("Invalid option.")


def super_admin_menu():
    super_admin: db.User = db.User("super_admin", "", -1, True)
    while True:
        su_admin_options = ["Show members", "Show admins and consultants", "Logout"]
        selection, index = pick(
            su_admin_options,
            title=f"{logo}\nSUPER ADMIN - MAIN MENU\nWelcome, super admin!",
            indicator=">",
        )
        match index:
            case 0:
                show_members(super_admin)
            case 1:
                show_users(super_admin)
            case 2:
                show_error("Logging out now.")
                break
            case _:
                show_error("Invalid option.")
                continue


def login_screen():
    while True:
        clear_console()
        show_logo()
        print(
            "LOGIN SCREEN\nTo login to the application, enter your username:\n> ",
            end="",
        )
        uname = input()
        print("enter password:")
        unhashed_pw = getpass("> ")
        attempt = db.attempt_login(uname=uname, attemptPassword=unhashed_pw)
        match (attempt):
            case e if isinstance(e, db.User):
                to_main_menu(cast(db.User, attempt))

            case e if isinstance(e, Exception) and (
                str(attempt) == "UserNotFound" or str(attempt) == "WrongPassword"
            ):
                show_error(
                    f"No user found with that username and password. ({uname}, {unhashed_pw}) because {attempt}"
                )
            case e if isinstance(e, Exception) and str(
                attempt
            ) == "TooManyFailedAttempts":
                show_error(
                    "You have had too many failed attempts. Ask an admin to unlock your account."
                )
            case e if isinstance(e, Exception) and str(attempt) == "SuperAdmin":
                super_admin_menu()
            case e if isinstance(e, Exception):
                show_error(str(attempt))
