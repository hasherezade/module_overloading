# Module Overloading

[![Build status](https://ci.appveyor.com/api/projects/status/tm61oypiqwif24vt?svg=true)](https://ci.appveyor.com/project/hasherezade/module-overloading)

A PoC based on the ideas of [thewover](https://github.com/thewover) (twitter [@TheRealWover](https://twitter.com/TheRealWover)):
https://twitter.com/TheRealWover/status/1193284444687392768?s=20 + my own experiments

Using: [libpeconv](https://github.com/hasherezade/libpeconv).

![](/docs/img/module_overload.png)

Characteristics:
-

+ Payload mapped as `MEM_IMAGE`, impersonating a legitimate DLL (image linked to a file on the disk)
+ Sections mapped with original access rights (no `RWX`)
+ Not connected* to the list of modules (invisible for `Module32First`/`Module32Next`) 
  +   *may be connected if the 'classic DLL hollowing' was selected*
+ Only self-injection supported

Demo:
-
![demo_view](/docs/img/demo.png)

Clone:
-
Use recursive clone to get the repo together with all the submodules:

```console
git clone --recursive https://github.com/hasherezade/module_overloading.git
```
