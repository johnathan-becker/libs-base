// ========== Keysight Technologies Added Changes To Satisfy LGPL 2.x Section 2(a) Requirements ========== 
// Committed by: Adam Fox 
// Commit ID: a312acb8373b24c50854978fa4c2334d2565e870 
// Date: 2020-01-02 18:37:58 -0700 
// ========== End of Keysight Technologies Notice ========== 
#include <stdio.h>
#include <stdlib.h>
#include <ffi.h>


typedef struct cls_struct_combined {
  float a;
  float b;
  float c;
  float d;

#ifndef __MINGW64__
  // Testplant: Work around 64bit libffi bug passing 16byte structs by value.
  // Note that this workaround was removed for Windows when we moved from
  // clang 3 to clang 7, so this can probably be removed for Linux as well
  // when we get those toolchains up to 7.
  float e;
#endif
} cls_struct_combined;

void cls_struct_combined_fn(struct cls_struct_combined arg)
{
/*
  printf("GOT %g %g %g %g,  EXPECTED 4 5 1 8\n",
	 arg.a, arg.b,
	 arg.c, arg.d);
  fflush(stdout);
*/
  if (arg.a != 4 || arg.b != 5 || arg.c != 1 || arg.d != 8) abort();
}

static void
cls_struct_combined_gn(ffi_cif* cif, void* resp, void** args, void* userdata)
{
  struct cls_struct_combined a0;

  a0 = *(struct cls_struct_combined*)(args[0]);

  cls_struct_combined_fn(a0);
}


int main (void)
{
  ffi_cif cif;
  void *code;
  ffi_closure *pcl = ffi_closure_alloc(sizeof(ffi_closure), &code);
  ffi_type* cls_struct_fields0[6];
  ffi_type cls_struct_type0;
  ffi_type* dbl_arg_types[6];
  struct cls_struct_combined g_dbl = {4.0, 5.0, 1.0, 8.0, 6.0};

  cls_struct_type0.size = 0;
  cls_struct_type0.alignment = 0;
  cls_struct_type0.type = FFI_TYPE_STRUCT;
  cls_struct_type0.elements = cls_struct_fields0;

  cls_struct_fields0[0] = &ffi_type_float;
  cls_struct_fields0[1] = &ffi_type_float;
  cls_struct_fields0[2] = &ffi_type_float;
  cls_struct_fields0[3] = &ffi_type_float;
  cls_struct_fields0[4] = &ffi_type_float;
  cls_struct_fields0[5] = NULL;

  dbl_arg_types[0] = &cls_struct_type0;
  dbl_arg_types[1] = NULL;

cls_struct_combined_fn(g_dbl);

  if (ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 1, &ffi_type_void, dbl_arg_types)
    != FFI_OK) abort();

  if (ffi_prep_closure_loc(pcl, &cif, cls_struct_combined_gn, NULL, code)
    != FFI_OK) abort();

  ((void(*)(cls_struct_combined)) (code))(g_dbl);
  exit(0);
}
