
#include "ui.h"

static HWND cspHWND = 0; //< Window handle of the main CSP #11 window.
static HINSTANCE csphInstance = 0; //< Dll Instance.

void setCSPInstance(HINSTANCE _csphInstance) {

	csphInstance = _csphInstance;
}
