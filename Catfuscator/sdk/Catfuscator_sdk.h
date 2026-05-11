#pragma once

//
// Catfuscator SDK - Include this header in your project and link Catfuscator_markers.obj
//
// Usage:
//   VIRTUALIZE_BEGIN
//   ... code to be virtualized ...
//   VIRTUALIZE_END
//
//   MUTATE_BEGIN
//   ... code to be mutated (instruction substitution) ...
//   MUTATE_END
//

#ifdef __cplusplus
extern "C" {
#endif

void CatfuscatorVirtualizeBegin(void);
void CatfuscatorVirtualizeEnd(void);
void CatfuscatorMutateBegin(void);
void CatfuscatorMutateEnd(void);
void CatfuscatorUltraBegin(void);
void CatfuscatorUltraEnd(void);

#ifdef __cplusplus
}
#endif

#define VIRTUALIZE_BEGIN CatfuscatorVirtualizeBegin()
#define VIRTUALIZE_END   CatfuscatorVirtualizeEnd()
#define MUTATE_BEGIN     CatfuscatorMutateBegin()
#define MUTATE_END       CatfuscatorMutateEnd()
#define ULTRA_BEGIN      CatfuscatorUltraBegin()
#define ULTRA_END        CatfuscatorUltraEnd()
