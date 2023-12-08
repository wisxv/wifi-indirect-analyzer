import os
import time

from rich import print as rprint
from rich.box import ROUNDED
from rich.panel import Panel
from rich.prompt import Confirm
from simple_term_menu import TerminalMenu as Tm

from classes import Parser, Statistics


def clear_terminal() -> None:
    os.system('cls' if os.name == 'nt' else 'clear')


def main():
    parser = Parser()
    main_menu_items = ['Import', 'Topology', 'Channels utilization', 'Week probability']
    main_menu_exit = False
    main_menu = Tm(main_menu_items, title='Main Menu.\nPress <Q> or <Esc> to exit.', clear_screen=True)

    import_menu_back = False
    while not main_menu_exit:
        selection_main = main_menu.show()
        if selection_main == 0:

            def list_files(directory=".") -> list:
                files = [file for file in os.listdir(directory) if os.path.isfile(os.path.join(directory, file))]
                files = [file for file in files if any((ext in file) for ext in ('cap', 'pcap', 'pcapng'))]
                return files if len(files) > 0 else None

            while not import_menu_back:
                import_menu_items = list_files()
                import_menu = Tm(import_menu_items, title='Choose files:', clear_screen=True, multi_select=True)
                import_sel_index = import_menu.show()

                if import_sel_index is None:
                    import_menu_back = True
                else:
                    import_sel = [import_menu_items[i] for i in import_sel_index]
                    print('Selecting:')
                    [print(f'    {i}') for i in import_sel]
                    inp = Confirm.ask(f'Continue?')
                    clear_terminal()
                    if inp:
                        files_to_process = list()
                        for i in import_sel:
                            extension = i.split('.')[-1]
                            if extension == 'cap' or extension == 'pcap':
                                files_to_process.append(i)
                        if len(files_to_process) > 0:
                            parser.parse(files_to_process)
                        import_menu_back = True
                    else:
                        import_menu_back = False
            import_menu_back = False
        elif selection_main == 1:
            statistics = Statistics(parser)
            panel = Panel('[#22ff31]⬤[/#22ff31] - AP\n'
                          '[#22f0ff]⬤[/#22f0ff] - station\n'
                          '[#ff9f22]⬤[/#ff9f22] - requested AP\n'
                          '[#ff3222]⬤[/#ff3222] - hidden AP',
                          title='LEGEND', box=ROUNDED,)
            rprint(panel)
            inp = Confirm.ask(f'\nContinue?')
            if inp:
                statistics.graph()

        elif selection_main == 2:
            statistics = Statistics(parser)
            statistics.heatmap()
        elif selection_main == 3:
            statistics = Statistics(parser)
            statistics.reorder_sta_by_weekdays()
            stations_menu_items = statistics.stations_available()
            if len(stations_menu_items) > 0:
                stations_menu = Tm(stations_menu_items, title='Select station:', clear_screen=True)
                stations_sel_index = stations_menu.show()
                if stations_sel_index is not None:
                    ap_menu_items = statistics.aps_available_for_station(stations_menu_items[stations_sel_index])
                    if len(ap_menu_items) > 0:
                        ap_menu = Tm(ap_menu_items, title='Select Access Point:', clear_screen=True)
                        ap_menu_index = ap_menu.show()
                        if ap_menu_index is not None:
                            statistics.week_probability_plot(stations_menu_items[stations_sel_index],
                                                             ap_menu_items[ap_menu_index])
                        else:
                            print('No ap selected or Noting to do')
                            time.sleep(2)
                    else:
                        print('No ap available')
                        time.sleep(2)
                else:
                    print('No station selected')
                    time.sleep(2)
            else:
                print('No stations available')
                time.sleep(2)
        elif selection_main is None:
            main_menu_exit = True


if __name__ == "__main__":
    main()
