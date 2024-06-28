#define LUMIX_NO_CUSTOM_CRT
#include "core/allocator.h"
#include "core/log.h"
#include "core/os.h"
#include "core/path.h"
#include "editor/studio_app.h"
#include "editor/utils.h"
#include "editor/world_editor.h"

#include "imgui/imgui.h"
#include <Windows.h>


using namespace Lumix;

struct EditorPlugin : StudioApp::GUIPlugin {
	EditorPlugin(StudioApp& app) 
		: m_app(app)
	{
		m_toggle_ui.init("LiveCode", "Toggle LiveCode UI", "livecode", "", Action::IMGUI_PRIORITY);
		m_toggle_ui.func.bind<&EditorPlugin::toggleUI>(this);
		m_toggle_ui.is_selected.bind<&EditorPlugin::isOpen>(this);
		m_app.addWindowAction(&m_toggle_ui);
	}

	~EditorPlugin() { m_app.removeAction(&m_toggle_ui); }

	bool isOpen() const { return m_is_open; }
	void toggleUI() { m_is_open = !m_is_open; }

	void start() {
		STARTUPINFOA startup_info = { sizeof(startup_info) };
		PROCESS_INFORMATION process_info = {};
		const DWORD pid = GetCurrentProcessId();
		StaticString<MAX_PATH> tmp("../plugins/livecode/external/blink/blink.exe --no-compile ", u32(pid));
		
		char exe_path[MAX_PATH];
		os::getExecutablePath(Span(exe_path));
		const StringView dir = Path::getDir(Path::getDir(Path::getDir(exe_path)));
		StaticString<MAX_PATH> blink_working_dir(dir);

		if (!CreateProcess(nullptr, tmp.data, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, blink_working_dir, &startup_info, &process_info)) {
			logError("Failed to start ../plugins/livecode/external/blink/blink.exe");
			return;
		}
		m_is_running = true;
	}

	void onGUI() override {
		if (!m_is_open) return;
		ImGui::SetNextWindowSize(ImVec2(200, 200), ImGuiCond_FirstUseEver);
		if (ImGui::Begin("LiveCode", &m_is_open)) {
			if (m_is_running) {
				ImGui::Text("Running");
			}
			else if (ImGui::Button("Start")) {
				start();
			}
		}
		ImGui::End();
	}
	
	const char* getName() const override { return "livecode"; }

	StudioApp& m_app;
	Action m_toggle_ui;
	bool m_is_open = false;
	bool m_is_running = false;
};


LUMIX_STUDIO_ENTRY(livecode)
{
	WorldEditor& editor = app.getWorldEditor();

	auto* plugin = LUMIX_NEW(editor.getAllocator(), EditorPlugin)(app);
	app.addPlugin(*plugin);
	return nullptr;
}
