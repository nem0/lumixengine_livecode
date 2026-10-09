-- Runs inside the plugin project. Paths are relative to this file.
-- needs external/blink (not in this checkout)
files { "external/blink/src/**.h", "external/blink/src/**.cpp", "src/**.c", "src/**.cpp", "src/**.h" }
excludes { "external/blink/src/main.cpp" }
defines { "BUILDING_LIVECODE" }
if _OPTIONS["dynamic-plugins"] then
	links { "engine" }
end
