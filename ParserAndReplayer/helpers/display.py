from prettytable import PrettyTable
from colorama import Fore, Style

def ok(str):
    return Fore.GREEN + str + Style.RESET_ALL

def important(str):
    return Fore.RED + str + Style.RESET_ALL

def table_display(headers:list, values):
    if not len(values):
        return 
    prep_table = [headers]
    table = PrettyTable(prep_table[0], max_width=130)
    for value in (values):
        prep_table.append(value)
    table.add_rows(prep_table[1:])
    print(table)

def csv_display():
    pass
