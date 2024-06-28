project "livecode"
	libType()
	files { 
		"src/**.c",
		"src/**.cpp",
		"src/**.h",
		"genie.lua"
	}
	defines { "BUILDING_LIVECODE" }
	links { "engine" }
	useLua()
	defaultConfigurations()

linkPlugin("livecode")