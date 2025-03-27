// lumina fix IDA 8.3.230608

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

struct plugin_ctx_t : public plugmod_t
{
  virtual bool idaapi run(size_t) override;
};

bool idaapi plugin_ctx_t::run(size_t)
{
  return true;
}

static plugmod_t *idaapi init()
{
  return new plugin_ctx_t;
}

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_HIDE | PLUGIN_MULTI,
  init,                 // initialize
  nullptr,
  nullptr,
  nullptr,
  nullptr,
  "luminafix83",       // the preferred short name of the plugin
  nullptr,
};

static void write_word(ULONG_PTR addr, WORD w)
{
  MEMORY_BASIC_INFORMATION memBI;
  DWORD old_rights, new_rights;
  memset(&memBI, 0, sizeof(memBI));
  if (VirtualQuery((void*)addr, &memBI, sizeof(memBI))) {
    old_rights = memBI.Protect;
    new_rights = (old_rights & ~(PAGE_NOACCESS | PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_WRITECOPY | PAGE_GUARD)) | PAGE_EXECUTE_READWRITE;
    if (old_rights != new_rights) {
      VirtualProtect((void*)addr, sizeof(WORD), new_rights, &old_rights);
    }
    *(WORD*)addr = w;
    if (old_rights != new_rights) {
      VirtualProtect((void*)addr, sizeof(WORD), old_rights, &new_rights);
    }
  }
}

BOOL __stdcall DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
  if (dwReason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(hModule);

    ULONG_PTR ida = (ULONG_PTR)GetModuleHandleA("ida.dll");
    if (ida) {
      if (*(ULONGLONG*)(ida+0xAEFA9) == 0xE8F6324000000053) {
        write_word(ida+0xAEFAE, 0x01B6);
      }
      if (*(ULONGLONG*)(ida+0xAEFC2) == 0xE9C032404F894848) {
        write_word(ida+0xAEFC7, 0x01B0);
      }
      if (*(ULONGLONG*)(ida+0xAF1D4) == 0x8B48C032404F8948) {
        write_word(ida+0xAF1D8, 0x01B0);
      }
    }
    ULONG_PTR ida64 = (ULONG_PTR)GetModuleHandleA("ida64.dll");
    if (ida64) {
      if (*(ULONGLONG*)(ida64+0xB0AB9) == 0xE8F6324000000053) {
        write_word(ida64+0xB0ABE, 0x01B6);
      }
      if (*(ULONGLONG*)(ida64+0xB0AD2) == 0xE9C032404F894848) {
        write_word(ida64+0xB0AD7, 0x01B0);
      }
      if (*(ULONGLONG*)(ida64+0xB0CE4) == 0x8B48C032404F8948) {
        write_word(ida64+0xB0CE8, 0x01B0);
      }
    }
  }

  return TRUE;
}
