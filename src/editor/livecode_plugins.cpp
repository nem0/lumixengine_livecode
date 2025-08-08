// non-Lumix stuff in this file (most of this file) is copy-pasted from blink and slightly modified with following license:
// also see blink files in this repo
/**
 * Copyright (C) 2016 Patrick Mours. All rights reserved.
 * License: https://github.com/crosire/blink#license
 */

// the rest is Lumix 

#define NOMINMAX
#define LUMIX_NO_CUSTOM_CRT
#include <string.h>
#include "core/allocator.h"
#include "core/log.h"
#include "core/os.h"
#include "core/thread.h"
#include "core/path.h"
#include "core/profiler.h"
#include "core/sync.h"
#include "editor/action.h"
#include "editor/file_system_watcher.h"
#include "editor/settings.h"
#include "editor/studio_app.h"
#include "editor/text_filter.h"
#include "editor/utils.h"
#include "editor/world_editor.h"
#include "engine/component_uid.h"

#include "../../external/blink/src/coff_reader.hpp"
#include "../../external/blink/src/pdb_reader.hpp"
#include "../../external/blink/src/scoped_handle.hpp"

#include <imgui/imgui.h>
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>

using namespace Lumix;

// from blink
struct thread_scope_guard : scoped_handle
{
	thread_scope_guard() :
		handle(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0))
	{
		if (handle == INVALID_HANDLE_VALUE)
			return;

		THREADENTRY32 te = { sizeof(te) };

		if (Thread32First(handle, &te) && te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32ThreadID) + sizeof(te.th32ThreadID))
		{
			do
			{
				if (te.th32OwnerProcessID != GetCurrentProcessId() || te.th32ThreadID == GetCurrentThreadId())
					continue; // Do not suspend the current thread (which belongs to blink)

				const scoped_handle thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);

				if (thread == nullptr)
					continue;

				SuspendThread(thread);
			} while (Thread32Next(handle, &te));
		}
	}
	~thread_scope_guard()
	{
		if (handle == INVALID_HANDLE_VALUE)
			return;

		THREADENTRY32 te = { sizeof(te) };

		if (Thread32First(handle, &te) && te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32ThreadID) + sizeof(te.th32ThreadID))
		{
			do
			{
				if (te.th32OwnerProcessID != GetCurrentProcessId() || te.th32ThreadID == GetCurrentThreadId())
					continue;

				const scoped_handle thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);

				if (thread == nullptr)
					continue;

				ResumeThread(thread);
			} while (Thread32Next(handle, &te));
		}
	}

	HANDLE handle;
};

struct LiveCodeEditorPlugin : StudioApp::IPlugin, StudioApp::GUIPlugin {
	struct SourceFile {
		SourceFile(IAllocator& allocator) : path(allocator), project(allocator) {}
		String path;
		String project;
		u64 modified_timestamp;
	};

	struct FileTab {
		FileTab(IAllocator& allocator) : src_file(allocator) {}
		UniquePtr<CodeEditor> editor;
		SourceFile src_file;
	};

	bool showGizmo(WorldView& view, ComponentUID) override { return false; }

	void init() override {
		PROFILE_FUNCTION();
		// Try to find msbuild.exe in common locations
		const char* msbuild_candidates[] = {
			"C:/Program Files/Microsoft Visual Studio/2022/Community/MSBuild/Current/Bin/amd64/msbuild.exe",
			"C:/Program Files (x86)/Microsoft Visual Studio/2019/Community/MSBuild/Current/Bin/amd64/msbuild.exe",
			"C:/Program Files/Microsoft Visual Studio/2022/Professional/MSBuild/Current/Bin/amd64/msbuild.exe",
			"C:/Program Files/Microsoft Visual Studio/2022/Enterprise/MSBuild/Current/Bin/amd64/msbuild.exe"
		};
		for (const char* candidate : msbuild_candidates) {
			if (os::fileExists(candidate)) {
				m_msbuild_path = candidate;
				break;
			}
		}
		if (m_msbuild_path.length() == 0) logWarning("Could not find msbuild.exe.");
		
		// based on blink
		MODULEINFO module_info;
		if (!GetModuleInformation(GetCurrentProcess(), GetModuleHandle(nullptr), &module_info, sizeof(module_info))) {
			logError("Could not get module information.");
			return;
		}

		m_image_base = (BYTE*)module_info.lpBaseOfDll;

		struct RSDS_DEBUG_FORMAT {
			uint32_t signature;
			blink::guid guid;
			uint32_t age;
			char path[1];
		} const* debug_data = nullptr;

		const auto headers = reinterpret_cast<const IMAGE_NT_HEADERS*>(m_image_base + reinterpret_cast<const IMAGE_DOS_HEADER*>(m_image_base)->e_lfanew);

		const IMAGE_DATA_DIRECTORY& debug_directory = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
		const auto debug_directory_entries = reinterpret_cast<const IMAGE_DEBUG_DIRECTORY*>(
			m_image_base + debug_directory.VirtualAddress);

		for (unsigned int i = 0; i < debug_directory.Size / sizeof(IMAGE_DEBUG_DIRECTORY); ++i) {
			if (debug_directory_entries[i].Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
				debug_data = reinterpret_cast<const RSDS_DEBUG_FORMAT*>(m_image_base + debug_directory_entries[i].AddressOfRawData);
				if (debug_data->signature == 'RSDS') break;
			}
		}

		if (debug_data == nullptr) {
			logError("No debug data found.");
			return;
		}

		blink::pdb_reader pdb(debug_data->path);
		if (pdb.guid() != debug_data->guid) {
			logError("Debug data mismatch.");
			return;
		}

		logInfo("Found PDB: ", debug_data->path);
		pdb.read_object_files(m_object_files);
		m_symbols.insert({ "__ImageBase", m_image_base });
		pdb.read_symbol_table(m_image_base, m_symbols);

		parseProjectFiles();

		char exe_path[MAX_PATH];
		os::getExecutablePath(Span(exe_path));
		m_objs_path = Path::getDir(Path::getDir(Path::getDir(exe_path)));
		m_objs_path.append("obj");
		m_watcher = FileSystemWatcher::create(m_objs_path, m_app.getAllocator());
		m_watcher->getCallback().bind<&LiveCodeEditorPlugin::onFileChanged>(this);
	}

	void parseProjectFile(const char* path) {
		os::InputFile file;
		if (!file.open(path)) {
			logError("Failed to open ", path);
			return;
		}
		OutputMemoryStream blob(m_app.getAllocator());
		blob.resize(file.size() + 1);
		if (!file.read(blob.getMutableData(), blob.size() - 1)) {
			file.close();
			logError("Failed to read ", path);
			return;
		}
		file.close();
		blob.getMutableData()[blob.size() - 1] = 0;
		const char* content = (const char*)blob.data();
		
		const char* iter = content;
		for (;;) {
			iter = strstr(iter, "<ClCompile Include=");
			if (!iter) break;
			StringView src_path(iter + 20, u32(0));
			while (*src_path.end != '"' && *src_path.end != '\0') ++src_path.end;
			SourceFile& f = m_source_files.emplace(m_app.getAllocator());
			f.path = src_path;
			f.project = Path::getBasename(path);
			StaticString<MAX_PATH> full_path(m_sln_dir, src_path);
			f.modified_timestamp = os::getLastModified(full_path);
			++iter;
		}
	}

	// we read VS projects files because we need to map cpp files to projects to compile them
	// this is (probably?) not possible in pdb
	void parseProjectFiles() {
		char exe_path[MAX_PATH];
		os::getExecutablePath(Span(exe_path));
		StringView dir = Path::getDir(Path::getDir(Path::getDir(exe_path)));
		m_sln_dir = dir;
		os::FileIterator* iter = os::createFileIterator(dir, m_app.getAllocator());
		os::FileInfo info;
		while (os::getNextFile(iter, &info)) {
			if (Path::hasExtension(info.filename, "vcxproj")) {
				StaticString<MAX_PATH> tmp(dir, info.filename);
				parseProjectFile(tmp);
			}
		}
		os::destroyFileIterator(iter);
	}

	void onFileChanged(const char* path) {
		if (!Path::hasExtension(path, "obj")) return;
		StaticString<MAX_PATH> full_path(m_objs_path, "/", path);
		
		MutexGuard guard(m_to_reload_mutex);
		m_to_reload.emplace(full_path, m_app.getAllocator());
		m_to_reload_timeout = 0.1f;
	}

	// from blink
	static uint8_t* findFreeMemoryRegion(uint8_t* address, size_t size) {
		SYSTEM_INFO sysinfo;
		MEMORY_BASIC_INFORMATION meminfo;
		GetSystemInfo(&sysinfo);

		address -= reinterpret_cast<uintptr_t>(address) % sysinfo.dwAllocationGranularity;
		address += sysinfo.dwAllocationGranularity;
		auto maxaddress = static_cast<uint8_t*>(sysinfo.lpMaximumApplicationAddress);
		maxaddress -= size;

		while (address < maxaddress) {
			if (VirtualQuery(address, &meminfo, sizeof(meminfo)) == 0)
				break;

			if (meminfo.State == MEM_FREE)
				return address;

			address = static_cast<uint8_t*>(meminfo.BaseAddress) + meminfo.RegionSize;

			// Round up to the next allocation granularity
			address += sysinfo.dwAllocationGranularity - 1;
			address -= reinterpret_cast<uintptr_t>(address) % sysinfo.dwAllocationGranularity;
		}
		return nullptr;
	}

	// from blink
	template <typename SYMBOL_TYPE, typename HEADER_TYPE>
	bool link(HANDLE file, const HEADER_TYPE& header) {
		thread_scope_guard _scope_guard_;
		os::Timer timer;

		if (header.Machine != IMAGE_FILE_MACHINE_AMD64) {
			logError("Input file is not of a valid format or was compiled for a different processor architecture.");
			return false;
		}

		// Read section headers from input file (there is no optional header in COFF files, so it is right after the header read above)
		std::vector<IMAGE_SECTION_HEADER> sections(header.NumberOfSections);
		if (DWORD read; !ReadFile(file, sections.data(), header.NumberOfSections * sizeof(IMAGE_SECTION_HEADER), &read, nullptr)) {
			logError("Failed to read an image file sections.");
			return false;
		}

		// Read symbol table from input file
		SetFilePointer(file, header.PointerToSymbolTable, nullptr, FILE_BEGIN);

		std::vector<SYMBOL_TYPE> symbols(header.NumberOfSymbols);
		if (DWORD read; !ReadFile(file, symbols.data(), header.NumberOfSymbols * sizeof(SYMBOL_TYPE), &read, nullptr)) {
			logError("Failed to read an image file symbols.");
			return false;
		}

		// The string table follows after the symbol table and is usually at the end of the file
		const DWORD string_table_size = GetFileSize(file, nullptr) - (header.PointerToSymbolTable + header.NumberOfSymbols * sizeof(SYMBOL_TYPE));

		std::vector<char> strings(string_table_size);
		if (DWORD read; !ReadFile(file, strings.data(), string_table_size, &read, nullptr)) {
			logError("Failed to read a string table.");
			return false;
		}

		// Calculate total module size
		SIZE_T allocated_module_size = 0;

		for (const IMAGE_SECTION_HEADER& section : sections) {
			// Add space for section data and potential alignment
			allocated_module_size += 256 + section.SizeOfRawData + section.NumberOfRelocations * sizeof(IMAGE_RELOCATION);

			// Add space for relay thunk
			if (section.Characteristics & IMAGE_SCN_CNT_CODE)
				allocated_module_size += section.NumberOfRelocations * 12;
		}

		// Allocate executable memory region close to the executable image base (this is done so that relative jumps like 'IMAGE_REL_AMD64_REL32' fit into the required 32-bit).
		// Successfully loaded object files are never deallocated again to avoid corrupting the function rerouting generated below. The virtual memory is freed at process exit by Windows.
		const auto module_base = static_cast<BYTE*>(VirtualAlloc(findFreeMemoryRegion(m_image_base, allocated_module_size), allocated_module_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));

		if (module_base == nullptr) {
			logError("Failed to allocate executable memory region.");
			return false;
		}

		// Initialize sections
		auto section_base = module_base;

		for (IMAGE_SECTION_HEADER& section : sections) {
			// Skip over all sections that do not need linking
			if (section.Characteristics & (IMAGE_SCN_LNK_INFO | IMAGE_SCN_LNK_REMOVE | IMAGE_SCN_MEM_DISCARDABLE)) {
				section.PointerToRawData = 0xFFFFFFFF; // Mark this section as being unused
				section.NumberOfRelocations = 0; // Ensure that these are not handled by relocation below
				continue;
			}

			// Check section alignment
			UINT_PTR alignment = section.Characteristics & IMAGE_SCN_ALIGN_MASK;
			alignment = alignment ? 1 << ((alignment >> 20) - 1) : 1;

			// Align section memory base pointer to its required alignment
			section_base = reinterpret_cast<BYTE*>((reinterpret_cast<UINT_PTR>(section_base) + (alignment - 1)) & ~(alignment - 1));

			// Uninitialized sections do not have any data attached and they were already zeroed by 'VirtualAlloc', so skip them here
			if (section.PointerToRawData != 0) {
				SetFilePointer(file, section.PointerToRawData, nullptr, FILE_BEGIN);

				if (DWORD read; !ReadFile(file, section_base, section.SizeOfRawData, &read, nullptr))
				{
					logError("Failed to read a section raw data.");
					return false;
				}
			}

			section.PointerToRawData = static_cast<DWORD>(section_base - module_base);
			section_base += section.SizeOfRawData;

			// Read any relocation data attached to this section
			if (section.PointerToRelocations != 0) {
				SetFilePointer(file, section.PointerToRelocations, nullptr, FILE_BEGIN);

				if (DWORD read; !ReadFile(file, section_base, section.NumberOfRelocations * sizeof(IMAGE_RELOCATION), &read, nullptr))
				{
					logError("Failed to read relocations.");
					return false;
				}
			}

			section.PointerToRelocations = static_cast<DWORD>(section_base - module_base);
			section_base += section.NumberOfRelocations * sizeof(IMAGE_RELOCATION);
		}

		// Resolve internal and external symbols
		std::vector<BYTE*> local_symbol_addresses(header.NumberOfSymbols);
		std::vector<std::pair<BYTE*, const BYTE*>> image_function_relocations;

		u32 num_new_functions = 0;
		for (DWORD i = 0; i < header.NumberOfSymbols; i++) {
			BYTE* target_address = nullptr;
			const SYMBOL_TYPE& symbol = symbols[i];

			// Get symbol name from string table if it is a long name
			std::string symbol_name;
			if (symbol.N.Name.Short == 0) {
				ASSERT(symbol.N.Name.Long < string_table_size);

				symbol_name = strings.data() + symbol.N.Name.Long;
			}
			else {
				const auto short_name = reinterpret_cast<const char*>(symbol.N.ShortName);

				symbol_name = std::string(short_name, strnlen(short_name, IMAGE_SIZEOF_SHORT_NAME));
			}

			const auto symbol_table_lookup = m_symbols.find(symbol_name);

			if (symbol.StorageClass == IMAGE_SYM_CLASS_EXTERNAL && symbol.SectionNumber == IMAGE_SYM_UNDEFINED) {
				if (symbol_table_lookup == m_symbols.end()) {
					VirtualFree(module_base, 0, MEM_RELEASE);

					logError("Unresolved external symbol '", symbol_name.c_str(), "'.");
					return false;
				}

				target_address = static_cast<BYTE*>(symbol_table_lookup->second);
			}
			else if (symbol.StorageClass == IMAGE_SYM_CLASS_WEAK_EXTERNAL) {
				if (symbol_table_lookup != m_symbols.end()) {
					target_address = static_cast<BYTE*>(symbol_table_lookup->second);
				}
				else if (symbol.NumberOfAuxSymbols != 0) {
					const auto aux_symbol = reinterpret_cast<const IMAGE_AUX_SYMBOL_EX&>(symbols[i + 1]).Sym;

					ASSERT(aux_symbol.WeakDefaultSymIndex < i && "Unexpected symbol ordering for weak external symbol.");

					target_address = local_symbol_addresses[aux_symbol.WeakDefaultSymIndex];
				}
				else {
					VirtualFree(module_base, 0, MEM_RELEASE);

					logError("Unresolved weak external symbol '", symbol_name.c_str(), "'.");
					return false;
				}
			}
			else if (symbol.SectionNumber > IMAGE_SYM_UNDEFINED) {
				const IMAGE_SECTION_HEADER& section = sections[symbol.SectionNumber - 1];

				if (section.PointerToRawData != 0xFFFFFFFF) // Skip sections that do not need linking (see section initialization above)
				{
					target_address = module_base + section.PointerToRawData + symbol.Value;

					if (symbol_table_lookup != m_symbols.end() && symbol_name != reinterpret_cast<const char(&)[]>(section.Name))
					{
						const auto old_address = static_cast<BYTE*>(symbol_table_lookup->second);

						if (ISFCN(symbol.Type))
						{
							image_function_relocations.push_back({ old_address, target_address });
						}
						else if (strcmp(reinterpret_cast<const char*>(section.Name), ".bss") == 0 || strcmp(reinterpret_cast<const char*>(section.Name), ".data") == 0)
						{
							// Continue to use existing data from previous uninitialized (.bss) and initialized (.data) sections instead of replacing it
							target_address = old_address;
						}
					}
					else if (ISFCN(symbol.Type)) {
						++num_new_functions;
					}
				}
			}

			m_symbols[symbol_name] = local_symbol_addresses[i] = target_address;

			i += symbol.NumberOfAuxSymbols;
		}

		// Perform relocation on each section
		for (const IMAGE_SECTION_HEADER& section : sections) {
			const auto section_relocation_table = reinterpret_cast<const IMAGE_RELOCATION*>(module_base + section.PointerToRelocations);

			for (unsigned int k = 0; k < section.NumberOfRelocations; ++k) {
				const IMAGE_RELOCATION& relocation = section_relocation_table[k];
				const auto relocation_address = module_base + section.PointerToRawData + section.VirtualAddress + relocation.VirtualAddress;
				auto target_address = local_symbol_addresses[relocation.SymbolTableIndex];

				// Add relay thunk if distance to target exceeds 32-bit range
				if (target_address - relocation_address > 0xFFFFFFFF && ISFCN(symbols[relocation.SymbolTableIndex].Type)) {
					write_jump(section_base, target_address);

					target_address = section_base;
					section_base += 12;
				}
				switch (relocation.Type) {
						// Absolute virtual 64-bit address
					case IMAGE_REL_AMD64_ADDR64:
						*reinterpret_cast<uint64_t*>(relocation_address) = reinterpret_cast<uintptr_t>(target_address);
						break;
						// Absolute virtual 32-bit address
					case IMAGE_REL_AMD64_ADDR32:
						ASSERT(reinterpret_cast<uint64_t>(target_address) >> 32 == 0 && "Address overflow in absolute relocation.");
						*reinterpret_cast<uint32_t*>(relocation_address) = reinterpret_cast<uintptr_t>(target_address) & 0xFFFFFFFF;
						break;
						// Relative virtual address to __ImageBase
					case IMAGE_REL_AMD64_ADDR32NB:
						ASSERT(target_address - m_image_base == static_cast<int32_t>(target_address - m_image_base) && "Address overflow in relative relocation.");
						*reinterpret_cast<int32_t*>(relocation_address) = static_cast<int32_t>(target_address - m_image_base);
						break;
						// Relative virtual address to next instruction after relocation
					case IMAGE_REL_AMD64_REL32:
					case IMAGE_REL_AMD64_REL32_1:
					case IMAGE_REL_AMD64_REL32_2:
					case IMAGE_REL_AMD64_REL32_3:
					case IMAGE_REL_AMD64_REL32_4:
					case IMAGE_REL_AMD64_REL32_5:
						ASSERT(target_address - relocation_address == static_cast<int32_t>(target_address - relocation_address) && "Address overflow in relative relocation.");
						*reinterpret_cast<int32_t*>(relocation_address) = static_cast<int32_t>(target_address - (relocation_address + 4 + (relocation.Type - IMAGE_REL_AMD64_REL32)));
						break;
					case IMAGE_REL_AMD64_SECREL:
						*reinterpret_cast<uint32_t*>(relocation_address) = reinterpret_cast<uintptr_t>(target_address) & 0xFFF; // TODO: This was found by comparing generated ASM, probably not correct
						break;
					default:
						logError("Unimplemented relocation type");
						break;
				}
			}
		}

		// Reroute old functions to new code
		for (const auto& relocation : image_function_relocations)
			write_jump(relocation.first, relocation.second);

		FlushInstructionCache(GetCurrentProcess(), module_base, allocated_module_size);

		logInfo(image_function_relocations.size(), " functions were rerouted to new code.");
		if (num_new_functions > 0) {
			logInfo(num_new_functions, " new functions linked.");
		}
		logInfo("Successfully linked object file into executable image in ", timer.getTimeSinceStart(), " seconds.");

		return true;
	}

	// from blink
	bool link(const std::filesystem::path& path)
	{
		logInfo("Relinking ", path.u8string().c_str());
		// Object file can be a normal COFF or an extended COFF
		COFF_HEADER header;
		const scoped_handle file = open_coff_file(path, header);
		if (file == INVALID_HANDLE_VALUE) return false;

		return !header.is_extended() ?
			link<IMAGE_SYMBOL>(file, header.obj) :
			link<IMAGE_SYMBOL_EX>(file, header.bigobj);
	}

	// from blink
	static void write_jump(uint8_t* address, const uint8_t* jump_target) {
		DWORD protect = PAGE_EXECUTE_READWRITE;
		BOOL res = VirtualProtect(address, 12, protect, &protect);
		ASSERT(res);

		// MOV RAX, [target_address]
		// JMP RAX
		address[0] = 0x48;
		address[1] = 0xB8;
		*reinterpret_cast<uint64_t*>(address + 2) = reinterpret_cast<uintptr_t>(jump_target);
		address[10] = 0xFF;
		address[11] = 0xE0;

		VirtualProtect(address, 12, protect, &protect);
	}

	LiveCodeEditorPlugin(StudioApp& app) 
		: m_app(app)
		, m_source_files(app.getAllocator())
		, m_tabs(app.getAllocator())
		, m_to_reload(app.getAllocator())
		, m_msbuild_path(app.getAllocator())
	{
		m_app.getSettings().registerOption("livecode_opend", &m_is_open);
	}

	void openTab(const SourceFile& src_file) {
		if (m_tabs.find([&](const FileTab& t){ return t.src_file.path == src_file.path; }) >= 0) return;
		os::InputFile file;

		StaticString<MAX_PATH> full_path(m_sln_dir, src_file.path);

		if (!file.open(full_path)) {
			logError("Failed to open ", src_file.path);
			return;
		}

		Array<char> content(m_app.getAllocator());
		content.resize((u32)file.size() + 1);
		if (!file.read(content.begin(), content.size() - 1)) {
			logError("Failed to read ", src_file.path);
			file.close();
			return;
		}
		file.close();

		FileTab& tab = m_tabs.emplace(m_app.getAllocator());
		tab.src_file = src_file;
		tab.editor = createCppCodeEditor(m_app);
		content.back() = 0;
		tab.editor->setText(content.data());
	}

	void buildModifiedSource() {
		if (m_msbuild_path.length() == 0) {
			logError("msbuild.exe not found.");
			return;
		}

		// check all m_source_files for modified timestamps
		for (SourceFile& source_file : m_source_files) {
			StaticString<MAX_PATH> full_path(m_sln_dir, source_file.path);
			u64 modified_timestamp = os::getLastModified(full_path);
			if (modified_timestamp == 0) {
				logError("Failed to get last modified time for ", source_file.path);
				continue;
			}
			if (modified_timestamp > source_file.modified_timestamp) {
				source_file.modified_timestamp = modified_timestamp;
				os::Timer timer;
				logInfo("Building modified source file ", source_file.path, " ...");
				
				String args("/t:ClCompile /p:Configuration=Debug /p:Platform=x64 ", m_app.getAllocator());
				args.append("/p:SelectedFiles=");
				args.append(source_file.path);
				args.append(" ");
				args.append(source_file.project);
				args.append(".vcxproj");
				os::shellExecuteOpen(m_msbuild_path, args.c_str(), m_sln_dir, false);

				logInfo("Built in ", timer.getTimeSinceStart(), " seconds.");
			}
		}
	}

	void update(float td) override {
		MutexGuard guard(m_to_reload_mutex);
		
		if (m_to_reload.empty()) return;
		
		m_to_reload_timeout -= td;
		if (m_to_reload_timeout > 0) return;

		m_to_reload.removeDuplicates();
		for (const String& path : m_to_reload) {
			link(path.c_str());
		}

		m_to_reload.clear();
	}

	void onGUI() override {
		if (m_app.checkShortcut(m_build, true)) buildModifiedSource();
		if (m_app.checkShortcut(m_toggle_ui, true)) m_is_open = !m_is_open;
		if (!m_is_open) return;
		
		ImGui::SetNextWindowSize(ImVec2(200, 200), ImGuiCond_FirstUseEver);
		bool save_request = false;
		if (ImGui::Begin("LiveCode", &m_is_open)) {
			if (m_app.getCommonActions().save.iconButton()) save_request = true;
			ImGui::SameLine();
			if (m_build.iconButton()) buildModifiedSource();
			ImGui::Columns(2);
			static TextFilter filter;
			filter.gui("Filter");
			ImGui::BeginChild("left_col");
			for (const SourceFile& source_file: m_source_files) {
				if (filter.pass(source_file.path)) {
					StringView basename = Path::getBasename(source_file.path);
					if (ImGui::Selectable(basename.begin, false, ImGuiSelectableFlags_AllowDoubleClick) && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
						openTab(source_file);
					}
				}
			}
			ImGui::EndChild();
			ImGui::NextColumn();
			if (ImGui::BeginTabBar("tabbar")) {
				for (FileTab& tab : m_tabs) {
					StringView basename = Path::getBasename(tab.src_file.path.c_str());
					bool open = true;
					if (ImGui::BeginTabItem(basename.begin, &open)) {
						if (save_request) {
							os::OutputFile file;
							StaticString<MAX_PATH> full_path(m_sln_dir, tab.src_file.path);
							if (file.open(full_path)) {
								OutputMemoryStream blob(m_app.getAllocator());
								tab.editor->serializeText(blob);
								if (!file.write(blob.data(), blob.size())) {
									logError("Failed to write", tab.src_file.path);
								}
								file.close();
							}
							else {
								logError("Failed to open ", tab.src_file.path);
							}
						}
						ImGui::PushFont(m_app.getMonospaceFont());
						tab.editor->gui("live_code_editor", ImVec2(0, 0), m_app.getMonospaceFont(), m_app.getDefaultFont());
						ImGui::PopFont();
						ImGui::EndTabItem();
					}
					if (!open) {
						m_tabs.erase(u32(&tab - m_tabs.begin()));
						break;
					}
				}
				ImGui::EndTabBar();
			}
			ImGui::Columns();
		}
		ImGui::End();
	}

	const char* getName() const override { return "livecode"; }

	StudioApp& m_app;
	Action m_toggle_ui{"LiveCode", "LiveCode", "Toggle UI", "livecode_toggle_ui", nullptr, Action::WINDOW};
	Action m_build{"LiveCode", "Rebuild modified sources", "Rebuild modified sources", "livecode_build", ICON_FA_RECYCLE, Action::NORMAL};
	bool m_is_open = false;

	BYTE* m_image_base;
	std::vector<std::filesystem::path> m_object_files;
	std::unordered_map<std::string, void*> m_symbols;
	UniquePtr<FileSystemWatcher> m_watcher;
	StaticString<MAX_PATH> m_objs_path;
	StaticString<MAX_PATH> m_sln_dir;
	Mutex m_to_reload_mutex;
	Array<String> m_to_reload;
	float m_to_reload_timeout = -1;
	Array<SourceFile> m_source_files;
	Array<FileTab> m_tabs;
	String m_msbuild_path;
};


LUMIX_STUDIO_ENTRY(livecode) {
	auto* plugin = LUMIX_NEW(app.getAllocator(), LiveCodeEditorPlugin)(app);
	app.addPlugin((StudioApp::GUIPlugin&)*plugin);
	return plugin;
}
