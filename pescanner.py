import argparse
import os
import sys
import pefile
import pickle
import colorama
import pandas as pd
import numpy as np
from colorama import Fore, Back, Style

colorama.init(autoreset=True)

drop_cols = [
    'Name', 'e_magic', 'SectionMaxEntropy', 'SectionMaxRawsize', 
    'SectionMaxVirtualsize', 'SectionMinPhysical', 'SectionMinVirtual', 
    'SectionMinPointerData', 'SectionMainChar'
]
rs = pickle.load(open("./outputs/process/rs.pkl", "rb")) 
model = pickle.load(open("./outputs/models/LGBM + ADASYN + k=63 + isotonic.pkl", "rb"))
features = [
    "e_cblp","e_cp","e_crlc","e_cparhdr","e_minalloc","e_maxalloc","e_ss",
    "e_sp","e_csum","e_ip","e_cs","e_lfarlc","e_ovno","e_oemid","e_oeminfo",
    "e_lfanew","Machine","NumberOfSections","TimeDateStamp","PointerToSymbolTable",
    "NumberOfSymbols","SizeOfOptionalHeader","Characteristics","Magic","MajorLinkerVersion",
    "MinorLinkerVersion","SizeOfCode","SizeOfInitializedData","SizeOfUninitializedData",
    "AddressOfEntryPoint","BaseOfCode","ImageBase","SectionAlignment","FileAlignment",
    "MajorOperatingSystemVersion","MinorOperatingSystemVersion","MajorImageVersion",
    "MinorImageVersion","MajorSubsystemVersion","MinorSubsystemVersion",
    "SizeOfHeaders","CheckSum","Subsystem","DllCharacteristics","SizeOfStackReserve",
    "SizeOfStackCommit","SizeOfHeapReserve","SizeOfHeapCommit","LoaderFlags",
    "NumberOfRvaAndSizes","SectionsLength","SectionMinEntropy","SectionMinRawsize",
    "SectionMinVirtualsize","SectionMaxPhysical","SectionMaxVirtual","SectionMaxPointerData",
    "SectionMaxChar","DirectoryEntryImport","DirectoryEntryExport","ImageDirectoryEntryImport",
    "ImageDirectoryEntryException","ImageDirectoryEntrySecurity"
]


def analyze(df):
    for i in range(len(df)):
        file_path = str(df.loc[i, "Name"])
        pe = pefile.PE(file_path)
        df.loc[i, "e_magic"] = pe.DOS_HEADER.e_magic
        df.loc[i, "e_cblp"] = pe.DOS_HEADER.e_cblp
        df.loc[i, "e_cp"] = pe.DOS_HEADER.e_cp
        df.loc[i, "e_crlc"] = pe.DOS_HEADER.e_crlc
        df.loc[i, "e_cparhdr"] = pe.DOS_HEADER.e_cparhdr
        df.loc[i, "e_minalloc"] = pe.DOS_HEADER.e_minalloc
        df.loc[i, "e_maxalloc"] = pe.DOS_HEADER.e_maxalloc
        df.loc[i, "e_ss"] = pe.DOS_HEADER.e_ss
        df.loc[i, "e_sp"] = pe.DOS_HEADER.e_sp
        df.loc[i, "e_csum"] = pe.DOS_HEADER.e_csum
        df.loc[i, "e_ip"] = pe.DOS_HEADER.e_ip
        df.loc[i, "e_cs"] = pe.DOS_HEADER.e_cs
        df.loc[i, "e_lfarlc"] = pe.DOS_HEADER.e_lfarlc
        df.loc[i, "e_ovno"] = pe.DOS_HEADER.e_ovno
        df.loc[i, "e_oemid"] = pe.DOS_HEADER.e_oemid
        df.loc[i, "e_oeminfo"] = pe.DOS_HEADER.e_oeminfo
        df.loc[i, "e_lfanew"] = pe.DOS_HEADER.e_lfanew
        df.loc[i, "Machine"] = pe.FILE_HEADER.Machine
        df.loc[i, "NumberOfSections"] = pe.FILE_HEADER.NumberOfSections
        df.loc[i, "TimeDateStamp"] = pe.FILE_HEADER.TimeDateStamp
        df.loc[i, "PointerToSymbolTable"] = pe.FILE_HEADER.PointerToSymbolTable
        df.loc[i, "NumberOfSymbols"] = pe.FILE_HEADER.NumberOfSymbols
        df.loc[i, "SizeOfOptionalHeader"] = pe.FILE_HEADER.SizeOfOptionalHeader
        df.loc[i, "Characteristics"] = pe.FILE_HEADER.Characteristics
        df.loc[i, "Magic"] = pe.OPTIONAL_HEADER.Magic
        df.loc[i, "MajorLinkerVersion"] = pe.OPTIONAL_HEADER.MajorLinkerVersion
        df.loc[i, "MinorLinkerVersion"] = pe.OPTIONAL_HEADER.MinorLinkerVersion
        df.loc[i, "SizeOfCode"] = pe.OPTIONAL_HEADER.SizeOfCode
        df.loc[i, "SizeOfInitializedData"] = pe.OPTIONAL_HEADER.SizeOfInitializedData
        df.loc[i, "SizeOfUninitializedData"] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
        df.loc[i, "AddressOfEntryPoint"] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        df.loc[i, "BaseOfCode"] = pe.OPTIONAL_HEADER.BaseOfCode
        df.loc[i, "ImageBase"] = pe.OPTIONAL_HEADER.ImageBase
        df.loc[i, "SectionAlignment"] = pe.OPTIONAL_HEADER.SectionAlignment
        df.loc[i, "FileAlignment"] = pe.OPTIONAL_HEADER.FileAlignment
        df.loc[i, "MajorOperatingSystemVersion"] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        df.loc[i, "MinorOperatingSystemVersion"] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
        df.loc[i, "MajorImageVersion"] = pe.OPTIONAL_HEADER.MajorImageVersion
        df.loc[i, "MinorImageVersion"] = pe.OPTIONAL_HEADER.MinorImageVersion
        df.loc[i, "MajorSubsystemVersion"] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
        df.loc[i, "MinorSubsystemVersion"] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
        df.loc[i, "SizeOfHeaders"] = pe.OPTIONAL_HEADER.SizeOfHeaders
        df.loc[i, "CheckSum"] = pe.OPTIONAL_HEADER.CheckSum
        df.loc[i, "SizeOfImage"] = pe.OPTIONAL_HEADER.SizeOfImage
        df.loc[i, "Subsystem"] = pe.OPTIONAL_HEADER.Subsystem
        df.loc[i, "DllCharacteristics"] = pe.OPTIONAL_HEADER.DllCharacteristics
        df.loc[i, "SizeOfStackReserve"] = pe.OPTIONAL_HEADER.SizeOfStackReserve
        df.loc[i, "SizeOfStackCommit"] = pe.OPTIONAL_HEADER.SizeOfStackCommit
        df.loc[i, "SizeOfHeapReserve"] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
        df.loc[i, "SizeOfHeapCommit"] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
        df.loc[i, "LoaderFlags"] = pe.OPTIONAL_HEADER.LoaderFlags
        df.loc[i, "NumberOfRvaAndSizes"] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
        df.loc[i, "SectionsLength"] = len(pe.sections)
        
        section_entropy_dict = {}
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').strip('\x00')
            entropy = section.get_entropy()
            section_entropy_dict[section_name] = entropy
            
        df.loc[i, "SectionMinEntropy"] = min(section_entropy_dict.values())
        df.loc[i, "SectionMaxEntropy"] = max(section_entropy_dict.values())
        
        section_raw_size_dict = {}
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').strip('\x00')
            raw_size = section.SizeOfRawData
            section_raw_size_dict[section_name] = raw_size

        df.loc[i, "SectionMinRawsize"] = min(section_raw_size_dict.values())
        df.loc[i, "SectionMaxRawsize"] = max(section_raw_size_dict.values())
        
        section_virt_size_dict = {}
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').strip('\x00')
            virt_size = section.Misc_VirtualSize
            section_virt_size_dict[section_name] = virt_size
            
        df.loc[i, "SectionMinVirtualsize"] = min(section_virt_size_dict.values())
        df.loc[i, "SectionMaxVirtualsize"] = max(section_virt_size_dict.values())
        
        section_physical_addr_dict = {}
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').strip('\x00')
            physical = section.Misc_PhysicalAddress
            section_physical_addr_dict[section_name] = physical
            
        df.loc[i, "SectionMaxPhysical"] = max(section_physical_addr_dict.values())
        df.loc[i, "SectionMinPhysical"] = min(section_physical_addr_dict.values())
        
        section_virt_addr_dict = {}
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').strip('\x00')
            virtual = section.VirtualAddress
            section_virt_addr_dict[section_name] = virtual
    
        df.loc[i, "SectionMaxVirtual"] = max(section_virt_addr_dict.values())
        df.loc[i, "SectionMinVirtual"] = min(section_virt_addr_dict.values())
        
        section_pointer_data_dict = {}
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').strip('\x00')
            pointer_data = section.PointerToRawData
            section_pointer_data_dict[section_name] = pointer_data
            
        df.loc[i, "SectionMaxPointerData"] = max(section_pointer_data_dict.values())
        df.loc[i, "SectionMinPointerData"] = min(section_pointer_data_dict.values())

        section_char_dict = {}
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').strip('\x00')
            chars = section.Characteristics
            section_char_dict[section_name] = chars
            
        df.loc[i, "SectionMaxChar"] = max(section_char_dict.values())
        df.loc[i, "SectionMainChar"] = min(section_char_dict.values())
        
        try:
            df.loc[i, "DirectoryEntryImport"] = len(pe.DIRECTORY_ENTRY_IMPORT)
        except:
            df.loc[i, "DirectoryEntryImport"] = 0
        try:
            df.loc[i, "DirectoryEntryExport"] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        except:
            df.loc[i, "DirectoryEntryExport"] = 0
        
        df.loc[i, "ImageDirectoryEntryExport"] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].Size
        df.loc[i, "ImageDirectoryEntryImport"] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].Size
        df.loc[i, "ImageDirectoryEntryResource"] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']].Size
        df.loc[i, "ImageDirectoryEntryException"] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']].Size
        df.loc[i, "ImageDirectoryEntrySecurity"] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size
        
    return df

def list_files_in_directory(directory):
    f = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                pe = pefile.PE(os.path.abspath(file_path))
                f.append(os.path.abspath(file_path))
            except:
                continue

    return f

def test_file(file_path, model, is_remove):
    test_df = pd.DataFrame({"Name": file_path})
    result_df = analyze(test_df)

    if result_df.shape[0] > 0:
        test_df = result_df.drop(drop_cols, axis=1)

        test = rs.transform(test_df)
        test = pd.DataFrame(test, columns=test_df.columns)
        test = test[features]
        
        for i in range(len(test)):
            result = model.predict_proba(test)
            if np.argmax(result[i]) == 0:
                print(f"{Fore.GREEN}[+]{Fore.RESET} File {result_df.loc[i, 'Name']} labeled {Fore.GREEN} ({round(result[i].max() * 100, 4)}%) benign{Fore.RESET}.")
                result_df[i, "Label"] = "benign"
            else:
                print(f"{Fore.RED}[-]{Fore.RESET} File {result_df.loc[i, 'Name']} labeled {Fore.RED} ({round(result[i].max() * 100, 4)}%) malware{Fore.RESET}.")
                result_df[i, "Label"] = "malicious"
                if is_remove:
                    os.remove(os.path.abspath(file_path[i]))

        return result_df

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PEScanner - ML-Based PE file analyzer.")
    parser.add_argument("--remove", action="store_true", help="If file is malicious; delete automatically.")
    parser.add_argument("--path", type=str, help="Path to scan.")
    parser.add_argument("--file", type=str, help="Scan single file.")
    parser.add_argument("--report", type=str, help="Report file.")
    args = parser.parse_args()


    if args.file and not args.path:
        if not os.path.exists(args.file):
            sys.exit(f"{Fore.RED}[!] No such file or directory.{Fore.RESET}")

        df = test_file([args.file], model, is_remove=False)
        
        if args.report:
            df.to_csv(args.report)
    
    elif args.path and not args.file:
        if not os.path.exists(args.path):
            sys.exit(f"{Fore.RED}[!] No such file or directory.{Fore.RESET}")
    
        f = list_files_in_directory(args.path)
        if not args.remove:
            df = test_file(f, model, is_remove=False)
        else:
            df = test_file(f, model, is_remove=True)

        if args.report:
            df.to_csv(args.report)
            print(f"{Fore.YELLOW}[*] Report created at:{Fore.RESET} {Style.BRIGHT}{os.path.abspath(args.report)}{Style.NORMAL}")

    else:
        sys.exit(f"[-]{Fore.RED}Wrong parameters. Use '-h' to see help.{Fore.RESET}")