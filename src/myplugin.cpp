#define LUMIX_NO_CUSTOM_CRT
#include "core/stream.h"
#include "engine/engine.h"
#include "engine/plugin.h"
#include "engine/world.h"
#include "imgui/imgui.h"


using namespace Lumix;


// each world has its own instance of this module
struct MyModule : IModule {
	MyModule(Engine& engine, ISystem& system, World& world, IAllocator& allocator)
		: m_engine(engine)
		, m_system(system)
		, m_world(world)
		, m_allocator(allocator)
	{}

	const char* getName() const override { return "myplugin"; }

	void serialize(struct OutputMemoryStream& serializer) override {
		// save our module data
		serializer.write(m_some_value);
	}

	void deserialize(struct InputMemoryStream& serializer, const struct EntityMap& entity_map, i32 version) override {
		// load our module data
		serializer.read(m_some_value);

	}
	ISystem& getSystem() const override { return m_system; }
	World& getWorld() override { return m_world; }
	
	void update(float time_delta) {
		// called each frame
		m_some_value += time_delta; 
	}

	Engine& m_engine;
	ISystem& m_system;
	World& m_world;
	IAllocator& m_allocator;
	float m_some_value = 0;
};


// there will be only one instance of system
struct MySystem : ISystem {
	MySystem(Engine& engine) : m_engine(engine) {}

	const char* getName() const override { return "myplugin"; }
	
	void serialize(OutputMemoryStream& serializer) const override {}
	bool deserialize(i32 version, InputMemoryStream& serializer) override {
		// do not try to deserialize newer versions, since we have no idea what's there
		return version == 0;
	}

	void createModules(World& world) override {
		// this is when a world is created
		// usually we want to add our module to world here
		IAllocator& allocator = m_engine.getAllocator();
		UniquePtr<MyModule> module = UniquePtr<MyModule>::create(allocator, m_engine, *this, world, allocator);
		world.addModule(module.move());
	}

	Engine& m_engine;
};


LUMIX_PLUGIN_ENTRY(myplugin)
{
	return LUMIX_NEW(engine.getAllocator(), MySystem)(engine);
}


