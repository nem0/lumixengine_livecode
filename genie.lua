if plugin "livecode" then
	files { 
		"external/blink/src/**.h",
		"external/blink/src/**.cpp",
		"src/**.c",
		"src/**.cpp",
		"src/**.h",
		"genie.lua"
	}
	excludes { "external/blink/src/main.cpp" }
	defines { "BUILDING_LIVECODE" }
	dynamic_link_plugin { "engine" }
end