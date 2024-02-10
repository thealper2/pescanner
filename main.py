import pickle
import pandas as pd
import streamlit as st
import pefile
import json
import os
import tempfile
import numpy as np
from streamlit_option_menu import option_menu
import plotly.graph_objects as go        

fi = open('./languages.json')
config = json.load(fi)
fi.close()

model = pickle.load(open("./outputs/models/LGBM + RandomOverSampler + k=63 + isotonic.pkl", "rb"))
rs = pickle.load(open("./outputs/process/rs.pkl", "rb"))
features = [
    "e_cblp","e_cp","e_crlc","e_cparhdr","e_minalloc","e_maxalloc","e_ss","e_sp","e_csum","e_ip","e_cs",
    "e_lfarlc","e_ovno","e_oemid","e_oeminfo","e_lfanew","Machine","NumberOfSections","TimeDateStamp",
    "PointerToSymbolTable","NumberOfSymbols","SizeOfOptionalHeader","Characteristics","Magic","MajorLinkerVersion",
    "MinorLinkerVersion","SizeOfCode","SizeOfInitializedData","SizeOfUninitializedData","AddressOfEntryPoint",
    "BaseOfCode","ImageBase","SectionAlignment","FileAlignment","MajorOperatingSystemVersion","MinorOperatingSystemVersion",
    "MajorImageVersion","MinorImageVersion","MajorSubsystemVersion","MinorSubsystemVersion","SizeOfHeaders",
    "CheckSum","SizeOfImage","Subsystem","DllCharacteristics","SizeOfStackReserve","SizeOfStackCommit",
    "SizeOfHeapReserve","SizeOfHeapCommit","LoaderFlags","NumberOfRvaAndSizes","SectionsLength",
    "SectionMinEntropy","SectionMinRawsize","SectionMinVirtualsize","SectionMaxPointerData",
    "SectionMaxChar","DirectoryEntryImport","DirectoryEntryExport","ImageDirectoryEntryImport",
    "ImageDirectoryEntryResource","ImageDirectoryEntryException","ImageDirectoryEntrySecurity"
]
drop_cols = [
    'Name', 'e_magic', 'SectionMaxEntropy', 'SectionMaxRawsize', 
    'SectionMaxVirtualsize', 'SectionMinPhysical', 'SectionMinVirtual', 
    'SectionMinPointerData', 'SectionMainChar'
]

def analyze(df):
    for i in range(len(df)):
        file_path = str(df.loc[i, "Name"])
        try:
            pe = pefile.PE(file_path)
        except:
            continue
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

def test_file(file_path, features, drop_cols):
    test_df = pd.DataFrame({"Name": [file_path]})
    result_df = analyze(test_df)
    test_df = result_df.drop(drop_cols, axis=1)
    test = rs.transform(test_df)
    test = pd.DataFrame(test, columns=test_df.columns)
    test = test[features]
    result = model.predict_proba(test)
    if np.argmax(result) == 1:
        print("[-] This file is malicious.")
    else:
        print("[+] This file is benign.")


def main():
    PAGE_TITLE = "pescanner"
    PAGE_ICON = ":shield:"

    st.set_page_config(page_title=PAGE_TITLE, page_icon=PAGE_ICON, layout="wide")

    with st.sidebar:
        language_picker = st.selectbox("Language", options=["Türkçe", "English"])

        if language_picker == "Türkçe":
            ui = config["TR"]
        elif language_picker == "English":
            ui = config["EN"]

        options = [
            ui["PAGE_OPTIONS_HOME"],
            ui["PAGE_OPTIONS_UPLOAD"],
            ui["PAGE_OPTIONS_MODELS"],
            ui["PAGE_OPTIONS_FEATURES"],
            ui["PAGE_OPTIONS_ABOUT"]
        ]

        selected = option_menu(
            menu_title="PEML",
            options=options,
            icons=['house-fill', 'cpu-fill', 'box-fill', 'collection-fill', 'info-circle-fill'],
            menu_icon='shield-shaded',
            default_index=0,
            styles={
                "container": {
                    "padding": "5 !important",
                    "background-color": "black"
                },
                "icon": {
                    "color": "white",
                    "font-size": "23px"
                },
                "nav-link": {
                    "color": "white",
                    "font-size": "20px",
                    "text-align": "left",
                    "margin": "0px",
                    "--hover-color": "blue"
                },
                "nav-link-selected": {
                    "background-color": "#02ab21"
                }
            }
        )

    if selected == ui["PAGE_OPTIONS_HOME"]:
        st.title(ui["PAGE_OPTIONS_HOME_TITLE"])

        with st.container(border=True):
            st.markdown(ui["PAGE_OPTIONS_HOME_PARAGRAPH"])
            st.markdown(ui["PAGE_OPTIONS_HOME_STEPS_1"])
            st.markdown(ui["PAGE_OPTIONS_HOME_STEPS_2"])
            st.markdown(ui["PAGE_OPTIONS_HOME_STEPS_3"])
            st.markdown(ui["PAGE_OPTIONS_HOME_STEPS_4"])
            st.markdown(ui["PAGE_OPTIONS_HOME_STEPS_5"])
            st.markdown(ui["PAGE_OPTIONS_HOME_STEPS_6"])
            st.markdown(ui["PAGE_OPTIONS_HOME_STEPS_7"])
            st.markdown(ui["PAGE_OPTIONS_HOME_STEPS_8"])
            st.markdown(ui["PAGE_OPTIONS_HOME_STEPS_9"])

            st.markdown(ui["PAGE_OPTIONS_HOME_INSTALLATION_TITLE"])
            st.write(ui["PAGE_OPTIONS_HOME_INSTALLATION_PARAGRAPH"])
            st.code("""
                    cd pescanner/
                    pip install -r requirements.txt""", language="bash")
            
            st.markdown(ui["PAGE_OPTIONS_HOME_USAGE_TITLE"])
            st.write(ui["PAGE_OPTIONS_HOME_USAGE_1"])
            st.code("""python3 pescanner.py --file './test/python3.exe'""", language="bash")
            st.write(ui["PAGE_OPTIONS_HOME_USAGE_2"])
            st.code("""python3 pescanner.py --path './test'""", language="bash")
            st.write(ui["PAGE_OPTIONS_HOME_USAGE_3"])
            st.code("""python3 pescanner.py --path './test' --remove""", language="bash")
            st.write(ui["PAGE_OPTIONS_HOME_USAGE_4"])
            st.code("""python3 pescanner.py --path './test' --report""", language="bash")
            st.image("./images/terminal_output.png")


    elif selected ==  ui["PAGE_OPTIONS_UPLOAD"]:
        st.title(ui["PAGE_OPTIONS_UPLOAD_TITLE"])

        with st.container(border=True):
            uploaded_file = st.file_uploader("Choose a PE File", type="exe")

        with st.container(border=True):
                if uploaded_file is not None:
                    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                        temp_file.write(uploaded_file.getvalue())
                        temp_file_path = temp_file.name

                    st.header(ui["PAGE_OPTIONS_UPLOAD_HEADER"] + temp_file.name)
                    pe = pefile.PE(temp_file_path)
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write("DOS HEADER")
                        dos_header_df = pd.DataFrame({
                            "Feature": ["e_magic", "e_cblp", "e_cp", "e_crlc", "e_cparhdr", "e_minalloc", "e_maxalloc", 
                                        "e_ss", "e_sp", "e_csum", "e_ip", "e_cs", "e_lfarlc", "e_ovno", "e_oemid", "e_oeminfo", "e_lfanew"],
                            "Value": [pe.DOS_HEADER.e_magic, pe.DOS_HEADER.e_cblp, pe.DOS_HEADER.e_cp, pe.DOS_HEADER.e_crlc, pe.DOS_HEADER.e_cparhdr, pe.DOS_HEADER.e_minalloc, pe.DOS_HEADER.e_maxalloc,
                                    pe.DOS_HEADER.e_ss, pe.DOS_HEADER.e_sp, pe.DOS_HEADER.e_csum, pe.DOS_HEADER.e_ip, pe.DOS_HEADER.e_cs, pe.DOS_HEADER.e_lfarlc, pe.DOS_HEADER.e_ovno, pe.DOS_HEADER.e_oemid,
                                    pe.DOS_HEADER.e_oeminfo, pe.DOS_HEADER.e_lfanew]
                        })
                        st.table(dos_header_df)

                    with col2:
                        st.write("FILE HEADER")
                        file_header_df = pd.DataFrame({
                            "Feature": ["Machine", "NumberOfSections", "TimeDateStamp", "PointerToSymbolTable", "NumberOfSymbols", "SizeOfOptionalHeader", "Characteristics"],
                            "Value": [pe.FILE_HEADER.Machine, pe.FILE_HEADER.NumberOfSections, pe.FILE_HEADER.TimeDateStamp, pe.FILE_HEADER.PointerToSymbolTable,
                                    pe.FILE_HEADER.NumberOfSymbols, pe.FILE_HEADER.SizeOfOptionalHeader, pe.FILE_HEADER.Characteristics]
                        })
                        st.table(file_header_df)

                    col3, col4 = st.columns(2)
                    with col3:
                        st.write("OPTIONAL HEADER")
                        optional_header_df = pd.DataFrame({
                            "Feature": ["Magic", "MajorLinkerVersion", "MinorLinkerVersion", "SizeOfCode", "SizeOfInitializedData", "SizeOfUninitializedData",
                                        "AddressOfEntryPoint", "BaseOfCode", "ImageBase", "SectionAlignment", "FileAlignment", "MajorOperatingSystemVersion",
                                        "MinorOperatingSystemVersion", "MajorImageVersion", "MinorImageVersion", "MajorSubsystemVersion", "MinorSubsystemVersion",
                                        "SizeOfHeaders", "CheckSum", "SizeOfImage", "Subsystem", "DllCharacteristics", "SizeOfStackReserve", "SizeOfStackCommit",
                                        "SizeOfHeapReserve", "SizeOfHeapCommit", "LoaderFlags", "NumberOfRvaAndSizes"],
                            "Value": [pe.OPTIONAL_HEADER.Magic, pe.OPTIONAL_HEADER.MajorLinkerVersion, pe.OPTIONAL_HEADER.MinorLinkerVersion, pe.OPTIONAL_HEADER.SizeOfCode,
                                    pe.OPTIONAL_HEADER.SizeOfInitializedData, pe.OPTIONAL_HEADER.SizeOfUninitializedData, pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                                    pe.OPTIONAL_HEADER.BaseOfCode, pe.OPTIONAL_HEADER.ImageBase, pe.OPTIONAL_HEADER.SectionAlignment, pe.OPTIONAL_HEADER.FileAlignment,
                                    pe.OPTIONAL_HEADER.MajorOperatingSystemVersion, pe.OPTIONAL_HEADER.MinorOperatingSystemVersion, pe.OPTIONAL_HEADER.MajorImageVersion,
                                    pe.OPTIONAL_HEADER.MinorImageVersion, pe.OPTIONAL_HEADER.MajorSubsystemVersion, pe.OPTIONAL_HEADER.MinorSubsystemVersion, pe.OPTIONAL_HEADER.SizeOfHeaders,
                                    pe.OPTIONAL_HEADER.CheckSum, pe.OPTIONAL_HEADER.SizeOfImage, pe.OPTIONAL_HEADER.Subsystem, pe.OPTIONAL_HEADER.DllCharacteristics, pe.OPTIONAL_HEADER.SizeOfStackReserve,
                                    pe.OPTIONAL_HEADER.SizeOfStackCommit, pe.OPTIONAL_HEADER.SizeOfHeapReserve, pe.OPTIONAL_HEADER.SizeOfHeapCommit, pe.OPTIONAL_HEADER.LoaderFlags, pe.OPTIONAL_HEADER.NumberOfRvaAndSizes]
                        })
                        st.table(optional_header_df)

                    with col4:
                        st.write("OTHER HEADER")
                        
                        section_entropy_dict = {}
                        for section in pe.sections:
                            section_name = section.Name.decode('utf-8').strip('\x00')
                            entropy = section.get_entropy()
                            section_entropy_dict[section_name] = entropy

                        section_raw_size_dict = {}
                        for section in pe.sections:
                            section_name = section.Name.decode('utf-8').strip('\x00')
                            raw_size = section.SizeOfRawData
                            section_raw_size_dict[section_name] = raw_size

                        section_virt_size_dict = {}
                        for section in pe.sections:
                            section_name = section.Name.decode('utf-8').strip('\x00')
                            virt_size = section.Misc_VirtualSize
                            section_virt_size_dict[section_name] = virt_size

                        section_physical_addr_dict = {}
                        for section in pe.sections:
                            section_name = section.Name.decode('utf-8').strip('\x00')
                            physical = section.Misc_PhysicalAddress
                            section_physical_addr_dict[section_name] = physical

                        section_virt_addr_dict = {}
                        for section in pe.sections:
                            section_name = section.Name.decode('utf-8').strip('\x00')
                            virtual = section.VirtualAddress
                            section_virt_addr_dict[section_name] = virtual

                        section_pointer_data_dict = {}
                        for section in pe.sections:
                            section_name = section.Name.decode('utf-8').strip('\x00')
                            pointer_data = section.PointerToRawData
                            section_pointer_data_dict[section_name] = pointer_data 

                        section_char_dict = {}
                        for section in pe.sections:
                            section_name = section.Name.decode('utf-8').strip('\x00')
                            chars = section.Characteristics
                            section_char_dict[section_name] = chars

                        try:
                            dei = len(pe.DIRECTORY_ENTRY_IMPORT)
                        except:
                            dei = 0
                        
                        try:
                            dee = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
                        except:
                            dee = 0

                        other_header_df = pd.DataFrame({
                            "Feature": ["SectionsLength", "SectionMinEntropy", "SectionMaxEntropy", "SectionMinRawsize", "SectionMaxRawsize", "SectionMinVirtualsize", "SectionMaxVirtualsize",
                                        "SectionMaxPhysical", "SectionMinPhysical", "SectionMaxVirtual", "SectionMinVirtual", "SectionMaxPointerData", "SectionMinPointerData",
                                        "SectionMaxChar", "SectionMinChar", "DirectoryEntryImport", "DirectoryEntryExport", "ImageDirectoryEntryExport", "ImageDirectoryEntryImport",
                                        "ImageDirectoryEntryResource", "ImageDirectoryEntryException", "ImageDirectoryEntrySecurity"],
                            "Value": [len(pe.sections), min(section_entropy_dict.values()), max(section_entropy_dict.values()), min(section_raw_size_dict.values()), max(section_raw_size_dict.values()),
                                    min(section_virt_size_dict.values()), max(section_virt_size_dict.values()), max(section_physical_addr_dict.values()), min(section_physical_addr_dict.values()),
                                    max(section_virt_addr_dict.values()), min(section_virt_addr_dict.values()), max(section_pointer_data_dict.values()), min(section_pointer_data_dict.values()),
                                    max(section_char_dict.values()), min(section_char_dict.values()), dei, dee,
                                    pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].Size,
                                    pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].Size,
                                    pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']].Size,
                                    pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']].Size,
                                    pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size]
                        })
                        st.table(other_header_df)
                    
                    os.remove(temp_file_path)
                
    elif selected == ui["PAGE_OPTIONS_MODELS"]:
        st.title(ui["PAGE_OPTIONS_MODELS_TITLE"])

        with st.container(border=True):
            st.header(ui["PAGE_OPTIONS_MODELS_HEADER"])
            models_df = pd.read_csv("./outputs/scores.csv", index_col=0)
            st.dataframe(models_df)

        with st.container(border=True):
            fig1 = go.Figure(
            data = [
                    go.Bar(name=ui["PAGE_OPTIONS_MODELS_LEGEND_1"], y=models_df["Model Name"], x=models_df["Train Accuracy"], orientation='h'),
                    go.Bar(name=ui["PAGE_OPTIONS_MODELS_LEGEND_2"], y=models_df["Model Name"], x=models_df["Train Accuracy"], orientation='h')
                ],
            )
            fig1.update_layout(template='plotly_dark', title=ui["PAGE_OPTIONS_MODELS_GRAPH_TITLE"], width=1000, height=800)
            fig1.update_layout(showlegend=False)
            fig1.update_layout(yaxis={'categoryorder':'total ascending'})
            st.plotly_chart(fig1)

    elif selected == ui["PAGE_OPTIONS_FEATURES"]:
        st.title(ui["PAGE_OPTIONS_FEATURES_TITLE"])

        with st.container(border=True):
            st.markdown(f"- **e_magic**: {ui['PAGE_OPTIONS_FEATURES_e_magic']}")
            st.markdown(f"- **e_cblp**: {ui['PAGE_OPTIONS_FEATURES_e_cblp']}")
            st.markdown(f"- **e_cp**: {ui['PAGE_OPTIONS_FEATURES_e_cp']}")
            st.markdown(f"- **e_crlc**: {ui['PAGE_OPTIONS_FEATURES_e_crlc']}")
            st.markdown(f"- **e_cparhdr**: {ui['PAGE_OPTIONS_FEATURES_e_cparhdr']}")
            st.markdown(f"- **e_minalloc**: {ui['PAGE_OPTIONS_FEATURES_e_minalloc']}")
            st.markdown(f"- **e_maxalloc**: {ui['PAGE_OPTIONS_FEATURES_e_maxalloc']}")
            st.markdown(f"- **e_ss**: {ui['PAGE_OPTIONS_FEATURES_e_ss']}")
            st.markdown(f"- **e_sp**: {ui['PAGE_OPTIONS_FEATURES_e_sp']}")
            st.markdown(f"- **e_csum**: {ui['PAGE_OPTIONS_FEATURES_e_csum']}")
            st.markdown(f"- **e_ip**: {ui['PAGE_OPTIONS_FEATURES_e_ip']}")
            st.markdown(f"- **e_cs**: {ui['PAGE_OPTIONS_FEATURES_e_cs']}")
            st.markdown(f"- **e_lfarlc**: {ui['PAGE_OPTIONS_FEATURES_e_lfarlc']}")
            st.markdown(f"- **e_ovno**: {ui['PAGE_OPTIONS_FEATURES_e_ovno']}")
            st.markdown(f"- **e_oemid**: {ui['PAGE_OPTIONS_FEATURES_e_oemid']}")
            st.markdown(f"- **e_lfanew**: {ui['PAGE_OPTIONS_FEATURES_e_lfanew']}")
            st.markdown(f"- **Machine**: {ui['PAGE_OPTIONS_FEATURES_Machine']}")
            st.markdown(f"- **NumberOfSections**: {ui['PAGE_OPTIONS_FEATURES_NumberOfSections']}")
            st.markdown(f"- **TimeDateStamp**: {ui['PAGE_OPTIONS_FEATURES_TimeDateStamp']}")
            st.markdown(f"- **PointerToSymbolTable**: {ui['PAGE_OPTIONS_FEATURES_PointerToSymbolTable']}")
            st.markdown(f"- **NumberOfSymbols**: {ui['PAGE_OPTIONS_FEATURES_NumberOfSymbols']}")
            st.markdown(f"- **SizeOfOptionalHeader**: {ui['PAGE_OPTIONS_FEATURES_SizeOfOptionalHeader']}")
            st.markdown(f"- **Characteristics**: {ui['PAGE_OPTIONS_FEATURES_Characteristics']}")
            st.markdown(f"- **Magic**: {ui['PAGE_OPTIONS_FEATURES_Magic']}")
            st.markdown(f"- **MajorLinkerVersion**: {ui['PAGE_OPTIONS_FEATURES_MajorLinkerVersion']}")
            st.markdown(f"- **MinorLinkerVersion**: {ui['PAGE_OPTIONS_FEATURES_MinorLinkerVersion']}")
            st.markdown(f"- **SizeOfCode**: {ui['PAGE_OPTIONS_FEATURES_SizeOfCode']}")
            st.markdown(f"- **SizeOfInitializedData**: {ui['PAGE_OPTIONS_FEATURES_SizeOfInitializedData']}")
            st.markdown(f"- **SizeOfUninitializedData**: {ui['PAGE_OPTIONS_FEATURES_SizeOfUninitializedData']}")
            st.markdown(f"- **AddressOfEntryPoint**: {ui['PAGE_OPTIONS_FEATURES_AddressOfEntryPoint']}")
            st.markdown(f"- **BaseOfCode**: {ui['PAGE_OPTIONS_FEATURES_BaseOfCode']}")
            st.markdown(f"- **ImageBase**: {ui['PAGE_OPTIONS_FEATURES_ImageBase']}")
            st.markdown(f"- **SectionAlignment**: {ui['PAGE_OPTIONS_FEATURES_SectionAlignment']}")
            st.markdown(f"- **FileAlignment**: {ui['PAGE_OPTIONS_FEATURES_FileAlignment']}")
            st.markdown(f"- **MajorOperatingSystemVersion**: {ui['PAGE_OPTIONS_FEATURES_MajorOperatingSystemVersion']}")
            st.markdown(f"- **MinorOperatingSystemVersion**: {ui['PAGE_OPTIONS_FEATURES_MinorOperatingSystemVersion']}")
            st.markdown(f"- **MajorImageVersion**: {ui['PAGE_OPTIONS_FEATURES_MajorImageVersion']}")
            st.markdown(f"- **MinorImageVersion**: {ui['PAGE_OPTIONS_FEATURES_MinorImageVersion']}")
            st.markdown(f"- **MajorSubsystemVersion**: {ui['PAGE_OPTIONS_FEATURES_MajorSubsystemVersion']}")
            st.markdown(f"- **MinorSubsystemVersion**: {ui['PAGE_OPTIONS_FEATURES_MinorSubsystemVersion']}")
            st.markdown(f"- **SizeOfHeaders**: {ui['PAGE_OPTIONS_FEATURES_SizeOfHeaders']}")
            st.markdown(f"- **CheckSum**: {ui['PAGE_OPTIONS_FEATURES_CheckSum']}")
            st.markdown(f"- **SizeOfImage**: {ui['PAGE_OPTIONS_FEATURES_SizeOfImage']}")
            st.markdown(f"- **Subsystem**: {ui['PAGE_OPTIONS_FEATURES_Subsystem']}")
            st.markdown(f"- **DllCharacteristics**: {ui['PAGE_OPTIONS_FEATURES_DllCharacteristics']}")
            st.markdown(f"- **SizeOfStackReserve**: {ui['PAGE_OPTIONS_FEATURES_SizeOfStackReserve']}")
            st.markdown(f"- **SizeOfStackCommit**: {ui['PAGE_OPTIONS_FEATURES_SizeOfStackCommit']}")
            st.markdown(f"- **SizeOfHeapReserve**: {ui['PAGE_OPTIONS_FEATURES_SizeOfHeapReserve']}")
            st.markdown(f"- **SizeOfHeapCommit**: {ui['PAGE_OPTIONS_FEATURES_SizeOfHeapCommit']}")
            st.markdown(f"- **LoaderFlags**: {ui['PAGE_OPTIONS_FEATURES_LoaderFlags']}")
            st.markdown(f"- **NumberOfRvaAndSizes**: {ui['PAGE_OPTIONS_FEATURES_NumberOfRvaAndSizes']}")
            st.markdown(f"- **DirectoryEntryImport**: {ui['PAGE_OPTIONS_FEATURES_DirectoryEntryImport']}")
            st.markdown(f"- **DirectoryEntryExport**: {ui['PAGE_OPTIONS_FEATURES_DirectoryEntryExport']}")

    elif selected == ui["PAGE_OPTIONS_ABOUT"]:
        st.title(ui["PAGE_OPTIONS_ABOUT_TITLE"])
        with st.container(border=True):
            with st.expander(ui["PAGE_OPTIONS_ABOUT_EXPANDER_TITLE"]):
                st.markdown(ui["PAGE_OPTIONS_ABOUT_EXPANDER_R1"])
                st.markdown(ui["PAGE_OPTIONS_ABOUT_EXPANDER_R2"])


if __name__ == "__main__":
    main()
