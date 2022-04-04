import lief
from sys import argv
import colorama

def _color_print(name):
    colorama.init(autoreset=True)
    def color_print(func):
        def wrapper(*args, **kwargs):
            ret = func(*args, **kwargs)
            if ret != False:
                color = colorama.Fore.GREEN
            else:
                color = colorama.Fore.RED
            print(color+name+": %s" % (ret))
        return wrapper
    return color_print

class PESecurity:
    def __init__(self, pe):
        self.pe = pe
        self.optional_header = pe.optional_header
        self.characteristics = self.optional_header.dll_characteristics_lists
        self.display_results()

    @_color_print("ASLR")
    def aslr(self):
        if lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE in self.characteristics:
            return True
        else:
            return False

    @_color_print("SafeSEH")
    def seh(self):
        if lief.PE.DLL_CHARACTERISTICS.NO_SEH in self.characteristics:
            return True
        else:
            return False

    @_color_print("DEP")
    def dep(self):
        if lief.PE.DLL_CHARACTERISTICS.NX_COMPAT in self.characteristics:
            return True
        else:
            return False

    @_color_print("ControlFlowGuard")
    def cfg(self):
        if lief.PE.DLL_CHARACTERISTICS.GUARD_CF in self.characteristics:
            return True
        else:
            return False

    @_color_print("HighEntropyVA")
    def high_entropy_va(self):
        if lief.PE.DLL_CHARACTERISTICS.HIGH_ENTROPY_VA in self.characteristics:
            return True
        else:
            return False

    def display_results(self):
        self.aslr()
        self.seh()
        self.dep()
        self.cfg()
        self.high_entropy_va()

class ELFSecurity:
    # lief.segments (GNU_RELRO && DT_BIND_NOW -> full relro)
    # lief.segments (GNU_RELRO  -> partial relro)
    # lief.sections (__stack_chk_fail -> stack canary)
    def __init__(self, elf):
        self.elf = elf
        self.fortified_function = []
        self.display_results()

    @_color_print("RELRO")
    def relro(self):
        try:
            self.elf.get(lief.ELF.SEGMENT_TYPES.GNU_RELRO)
            if self.elf.get(lief.ELF.DYNAMIC_TAGS.BIND_NOW):
                return "FULL Relro"
            else:
                return "Partial Relro"
        except:
            return False

    @_color_print("Stack Canary")
    def canary(self):
        try:
            self.elf.get_symbol("__stack_chk_fail")
            return True
        except:
            return False

    @_color_print("NX")
    def nx(self):
        try:
            if self.elf.get(lief.ELF.SEGMENT_TYPES.GNU_STACK).flags == 6:
                return True
        except:
            return False

    @_color_print("Pie")
    def pie(self):
        return self.elf.is_pie

    @_color_print("RPATH")
    def rpath(self):
        try:
            if elf.get(lief.ELF.DYNAMIC_TAGS.RPATH):
                return True
        except:
            return "No RPATH"

    @_color_print("RUNPATH")
    def runpath(self):
        try:
            if elf.get(lief.ELF.DYNAMIC_TAGS.RUNPATH):
                return True
        except:
            return "No RUNPATH"

    @_color_print("Fortify")
    def fortify(self):
        func_fortified = 0
        for function in self.elf.symbols:
            if function.name.endswith("_chk"):
                func_fortified += 1
                self.fortified_function.append(function.name)

        if func_fortified > 0:
            return True
        else:
            return False

    def fortified_functions(self):
        print("Fortified Functions:")
        for function in self.fortified_function:
            print("{: >20}".format(function))

    def display_results(self):
        self.relro()
        self.canary()
        self.nx()
        self.pie()
        self.fortify()
        self.rpath()
        self.runpath()
        self.fortified_functions()

class Checker:
    def __init__(self, filename):
        self.binary = lief.parse(filename)
        if lief.is_elf(filename):
            ELFSecurity(self.binary)
        if lief.is_pe(filename):
            PESecurity(self.binary)

b = Checker(argv[1])