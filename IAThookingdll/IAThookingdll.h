#ifdef IATHOOKINGDLL_EXPORTS
#define IATHOOKINGDLL_API __declspec(dllexport)
#else
#define IATHOOKINGDLL_API __declspec(dllimport)
#endif

extern "C" IATHOOKINGDLL_API int hook();


