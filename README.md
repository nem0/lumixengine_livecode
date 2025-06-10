# C++ Hot patching or Lumix Engine

[![License](http://img.shields.io/:license-mit-blue.svg)](http://doge.mit-license.org)

**Early prototype!**

This plugin allows developers to hotpatch C++ functions - that is, to modify a function, recompile it, and replace it at runtime without restarting the application. While similar in concept to [Live++](https://liveplusplus.tech/), this plugin is much more limited in scope but it is open source.

Based on [blink](https://github.com/crosire/blink)

# How to use
1. Download and build this plugin
2. Run Studio
3. Change some cpp file in your project and build the file. 
4. The plugin detects change in .obj file and automatically hot patches the functions.

Note: you can use simple builtin C++ editor in step 3

Alternatively, you can use an editor action (UI button or keyboard shortcut) that detects modified source files and recompiles them automatically.

Known limitations:
* Windows only.
* Debugging of hotpatched functions is not supported.
* Not all code changes are handled - for example, if the layout of a struct used by existing objects is modified, those objects are not updated. This can lead to undefined behavior or crashes.

![Animation](https://github.com/nem0/lumixengine_livecode/assets/153526/bc38baf2-ceac-4f9e-8734-1ea0e9cd83c9)
