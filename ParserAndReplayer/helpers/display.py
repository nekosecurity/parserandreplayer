from prettytable import PrettyTable
from colorama import Fore, Style

def ok(str):
    return Fore.GREEN + str + Style.RESET_ALL

def important(str):
    return Fore.RED + str + Style.RESET_ALL


def display(dtype):
    def dispatch_display(headers, values):
        # Print new line for readability
        print()
        if dtype == "table":
            return table_display(headers, values)
        if dtype == "csv":
            return csv_display(headers, values)
    return dispatch_display

def table_display(headers, values):
    if not len(values):
        return 
    prep_table = [headers]
    table = PrettyTable(prep_table[0], max_width=130)
    for value in (values):
        prep_table.append(value)
    table.add_rows(prep_table[1:])
    print(table)

def csv_display(headers, values):
    if not len(values):
        return 
    print(",".join(headers))

    # convert all elements in values to str
    values = [map(str, v) for v in values]
    for v in values:
        print(",".join(v))

    

# values = [('10.9.1.67', '445', 'Microsoft Windows SMB NULL Session Authentication', '26920'), ('10.9.5.100', '445', 'Microsoft Windows SMB NULL Session Authentication', '26920'), ('10.9.6.60', '445', 'Microsoft Windows SMB NULL Session Authentication', '26920')]
# csv_display(["IP", "Port", "Vulnerability", "PluginID"], values)