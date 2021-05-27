import ctypes
import struct
import logging

from ctypes import *
from ctypes import POINTER, c_int, byref, wintypes
from ctypes.wintypes import *
from ctypes.wintypes import LPARAM
from typing import Sequence

from py_compose_key.char_db import CharDB

logging.basicConfig()
logger = logging.getLogger(__name__)
# logger.setLevel(logging.DEBUG)
logger.setLevel(logging.INFO)

###

def errcheck_bool(result, func, args):
    if not result:
        raise WinError(get_last_error())
    return args

###


kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# HMODULE GetModuleHandleW(
#   LPCWSTR lpModuleName
# );
kernel32.GetModuleHandleW.restype = wintypes.HMODULE
kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]

# BOOL WINAPI SetConsoleCtrlHandler(
#   _In_opt_ PHANDLER_ROUTINE HandlerRoutine,
#   _In_     BOOL             Add
# );
PHANDLER_ROUTINE = ctypes.WINFUNCTYPE(BOOL, DWORD)
kernel32.SetConsoleCtrlHandler.argtypes = [PHANDLER_ROUTINE, wintypes.BOOL]
kernel32.SetConsoleCtrlHandler.restype = wintypes.BOOL
kernel32.SetConsoleCtrlHandler.errcheck = errcheck_bool

# DWORD GetCurrentThreadId();
kernel32.GetCurrentThreadId.argtypes = []
kernel32.GetCurrentThreadId.restype = wintypes.DWORD

###
###

user32 = ctypes.WinDLL('user32', use_last_error=True)

WM_QUIT = 18

# BOOL PostThreadMessageW(
#   DWORD  idThread,
#   UINT   Msg,
#   WPARAM wParam,
#   LPARAM lParam
# );
user32.PostThreadMessageW.argtypes = [wintypes.DWORD, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.PostThreadMessageW.restype = wintypes.BOOL
user32.PostThreadMessageW.errcheck = errcheck_bool

# #define WM_KEYDOWN                      0x0100
# #define WM_SYSKEYDOWN                   0x0104
# #define WM_KEYUP                        0x0101
# #define WM_SYSKEYUP                     0x0105

WM_KEYDOWN = 0x0100
WM_KEYUP = 0x0101
WM_SYSKEYDOWN = 0x0104
WM_SYSKEYUP = 0x0105


class KBDLLHOOKSTRUCT(Structure):
    _fields_ = [
        ('vkCode', DWORD),
        ('scanCode', DWORD),
        ('flags', DWORD),
        ('time', DWORD),
        ('dwExtraInfo', DWORD)
    ]


LRESULT = LPARAM
HOOKPROC = ctypes.WINFUNCTYPE(LRESULT, c_int, wintypes.WPARAM, wintypes.LPARAM)


user32.SetWindowsHookExW.errcheck = errcheck_bool
user32.SetWindowsHookExW.restype = HHOOK
user32.SetWindowsHookExW.argtypes = (c_int,     # _In_ idHook
                                     HOOKPROC,  # _In_ lpfn
                                     HINSTANCE, # _In_ hMod
                                     DWORD)     # _In_ dwThreadId

user32.CallNextHookEx.restype = LRESULT
user32.CallNextHookEx.argtypes = (HHOOK,  # _In_opt_ hhk
                                  c_int,  # _In_     nCode
                                  WPARAM, # _In_     wParam
                                  LPARAM) # _In_     lParam


# def errcheck_GetMessageW(result, func, args):
#     if not result == -1:
#         raise WinError(get_last_error())
#     return args

# BOOL GetMessageW(
#   LPMSG lpMsg,
#   HWND  hWnd,
#   UINT  wMsgFilterMin,
#   UINT  wMsgFilterMax
# );
user32.GetMessageW.argtypes = (LPMSG, # _Out_    lpMsg
                               HWND,  # _In_opt_ hWnd
                               UINT,  # _In_     wMsgFilterMin
                               UINT)  # _In_     wMsgFilterMax
user32.GetMessageW.restype = wintypes.BOOL
# user32.GetMessageW.errcheck = errcheck_GetMessageW


user32.TranslateMessage.argtypes = (LPMSG,)
user32.DispatchMessageW.argtypes = (LPMSG,)

# BOOL UnhookWindowsHookEx(
#   HHOOK hhk
# );
user32.UnhookWindowsHookEx.restype = wintypes.BOOL
user32.UnhookWindowsHookEx.argtypes = [HHOOK]
user32.UnhookWindowsHookEx.errcheck = errcheck_bool

# int ToUnicodeEx(
#   UINT       wVirtKey,
#   UINT       wScanCode,
#   const BYTE *lpKeyState,
#   LPWSTR     pwszBuff,
#   int        cchBuff,
#   UINT       wFlags,
#   HKL        dwhkl
# );

user32.ToUnicodeEx.restype = c_int
user32.ToUnicodeEx.argtypes = [wintypes.UINT, wintypes.UINT, wintypes.PBYTE, wintypes.LPWSTR, c_int, wintypes.UINT,
                               wintypes.HKL]

# SHORT GetKeyState(
#   int nVirtKey
# );
user32.GetKeyState.argtypes = [c_int]
user32.GetKeyState.restype = wintypes.SHORT

# HKL GetKeyboardLayout(
#   DWORD idThread
# );
user32.GetKeyboardLayout.restype = wintypes.HKL
user32.GetKeyboardLayout.argtypes = [wintypes.DWORD]

# BOOL GetKeyboardState(
#   PBYTE lpKeyState
# );
user32.GetKeyboardState.argtypes = [wintypes.PBYTE]
user32.GetKeyboardState.restype = wintypes.BOOL
user32.GetKeyboardState.errcheck = errcheck_bool

# int GetKeyNameTextW(
#   LONG   lParam,
#   LPWSTR lpString,
#   int    cchSize
# );
user32.GetKeyNameTextW.restype = c_int
# FIXME: use correct types
user32.GetKeyNameTextW.argtypes = [wintypes.LONG, wintypes.LPWSTR, ctypes.c_int]
# user32.GetKeyNameTextW.argtypes = [wintypes.LONG, POINTER(ctypes.c_wchar), ctypes.c_int]

# UINT MapVirtualKeyExW(
#   UINT uCode,
#   UINT uMapType,
#   HKL  dwhkl
# );
user32.MapVirtualKeyExW.argtypes = [wintypes.UINT, wintypes.UINT, wintypes.HKL]
user32.MapVirtualKeyExW.restype = wintypes.UINT


class GUITHREADINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("hwndActive", wintypes.HWND),
        ("hwndFocus", wintypes.HWND),
        ("hwndCapture", wintypes.HWND),
        ("hwndMenuOwner", wintypes.HWND),
        ("hwndMoveSize", wintypes.HWND),
        ("hwndCaret", wintypes.HWND),
        ("rcCaret", wintypes.RECT),
    ]

MAPVK_VK_TO_VSC = 0

VK_SHIFT = 0x10
VK_CONTROL = 0x11
VK_MENU = 0x12
VK_CAPITAL = 0x14  # CAPS LOCK key

VK_ESCAPE = 0x1B
VK_LWIN = 0x5B
VK_RWIN = 0x5C
VK_APPS = 0x5D
VK_LSHIFT = 0xA0
VK_RSHIFT = 0xA1
VK_LCONTROL = 0xA2
VK_RCONTROL = 0xA3
VK_LMENU = 0xA4
VK_RMENU = 0xA5

WH_KEYBOARD_LL = 13

###
###

KEYEVENTF_SCANCODE = 0x8
KEYEVENTF_UNICODE = 0x4
KEYEVENTF_KEYUP = 0x2
SPACE = 0x39
INPUT_KEYBOARD = 1

ULONG_PTR = ctypes.wintypes.WPARAM


class KEYBDINPUT(Structure):
    _fields_ = [('wVk', wintypes.WORD),
                ('wScan', wintypes.WORD),
                ('dwFlags', wintypes.DWORD),
                ('time', wintypes.DWORD),
                ('dwExtraInfo', ULONG_PTR)]


class MOUSEINPUT(Structure):
    _fields_ = [('dx', wintypes.LONG),
                ('dy', wintypes.LONG),
                ('mouseData', wintypes.DWORD),
                ('dwFlags', wintypes.DWORD),
                ('time', wintypes.DWORD),
                ('dwExtraInfo', ULONG_PTR)]


class HARDWAREINPUT(Structure):
    _fields_ = [('uMsg', wintypes.DWORD),
                ('wParamL', wintypes.WORD),
                ('wParamH', wintypes.WORD)]


class DUMMYUNIONNAME(Union):
    _fields_ = [('mi', MOUSEINPUT),
                ('ki', KEYBDINPUT),
                ('hi', HARDWAREINPUT)]


class INPUT(Structure):
    _anonymous_ = ['u']
    _fields_ = [('type', wintypes.DWORD),
                ('u', DUMMYUNIONNAME)]


def errcheck_SendInput(result, func, args):
    if result == 0:
        raise WinError(get_last_error())
    return args

user32.SendInput.argtypes = [wintypes.UINT, POINTER(INPUT), c_int]
user32.SendInput.restype = wintypes.UINT
user32.SendInput.errcheck = errcheck_SendInput


# def send_scancode(code):
#     i = INPUT()
#     i.type = INPUT_KEYBOARD
#     i.ki = KEYBDINPUT(0, code, KEYEVENTF_SCANCODE, 0, 0)
#     user32.SendInput(1, byref(i), sizeof(INPUT))
#     i.ki.dwFlags |= KEYEVENTF_KEYUP
#     user32.SendInput(1, byref(i), sizeof(INPUT))


def send_unicode(codepoints: Sequence[int]):
    nInputs = len(codepoints)
    LPINPUT = INPUT * nInputs
    pInputs = LPINPUT()
    cbSize = ctypes.c_int(ctypes.sizeof(INPUT))

    for j, codepoint in enumerate(codepoints):
        pInputs[j].type = INPUT_KEYBOARD
        pInputs[j].ki = KEYBDINPUT(0, codepoint, KEYEVENTF_UNICODE, 0, 0)

    user32.SendInput(nInputs, pInputs, cbSize)

    # for j, codepoint in enumerate(codepoints):
    #     pInputs[j].ki.dwFlags |= KEYEVENTF_KEYUP
    #
    # user32.SendInput(nInputs, pInputs, cbSize)


_test_sequences = [
    "\ud83d\udc69\u200d\u2708\ufe0f"
]


def utf16_codepoints(s: str) -> Sequence[int]:
    encoded = s.encode('utf-16le', 'surrogatepass')
    num_words = len(encoded) // 2
    return struct.unpack('<{}H'.format(num_words), encoded)

###
###

class KeyStatus:
    def __init__(self, key, state):
        self.key = key
        self.state = state
        self.down = state < 0
        self.toggle = (state & 1) != 0

    def __str__(self):
        # return f"{self.__class__.__name__}(key={self.key}, state={self.state}, down={self.down}, toggle={self.toggle})"
        return f"{self.__class__.__name__}(key={self.key}, Afdown={self.down}, toggle={self.toggle})"


class Composer:
    def __init__(self, char_db: CharDB):
        self.input_buffer = []
        self.char_db = char_db
        self._is_on = False

    def start(self):
        logger.debug("start compose")
        self.input_buffer.clear()
        self._is_on = True

    def end(self):
        logger.debug("end compose")
        self.input_buffer.clear()
        self._is_on = False

    def add_char(self, typed_character):
        self.input_buffer.append(typed_character)
        result = self.char_db.lookup(self.input_buffer)

        if result == CharDB.NOT_FOUND:
            pass
        elif result == CharDB.POTENTIAL_MATCH:
            pass
        elif result == CharDB.MATCH_FOUND:
            pass
        else:
            assert False, "unknown result"

        return result

    def get_composed_chars(self) -> str:
        return self.char_db.get_composed_chars(
            self.input_buffer
        )

    def get_input_string(self) -> str:
        return "".join(self.input_buffer)

    def is_on(self) -> bool:
        return self._is_on


def is_compose_key(kb_vkCode):
    if kb_vkCode == VK_RMENU:
        return True
    else:
        return False


def is_escape_key(kb_vkCode):
    if kb_vkCode == VK_ESCAPE:
        return True
    else:
        return False


def listen():
    """
    Calls `handlers` for each keyboard event received. This is a blocking call.
    """
    char_db = CharDB.create()
    composer = Composer(char_db)

    state = dict(
        compose_down=False,
        escape_down=False,
        count_escapes=0,
    )

    # @dataclasses.dataclass
    # class State:
    #     compose_down: bool = False

    def low_level_handler(nCode, wParam, lParam):
        """
        Processes a low level Windows keyboard event.
        """

        if nCode < 0:
            return user32.CallNextHookEx(hook_id, nCode, wParam, lParam)

        kb = KBDLLHOOKSTRUCT.from_address(lParam)

        logger.debug("key pressed %s", kb.vkCode)

        if (wParam == WM_SYSKEYDOWN or wParam == WM_KEYDOWN) and is_compose_key(kb.vkCode):
            logger.debug("is compose key (down)")
            state['compose_down'] = True
            composer.start()
            # return user32.CallNextHookEx(hook_id, nCode, wParam, lParam)
            return 1
        elif (wParam == WM_SYSKEYUP or wParam == WM_KEYUP) and is_compose_key(kb.vkCode):
            logger.debug("is compose key (up): %s %s", wParam == WM_SYSKEYUP, wParam == WM_KEYUP)
            if state.get('compose_down', False) is True:
                state['compose_down'] = False
                return 1
            else:
                return user32.CallNextHookEx(hook_id, nCode, wParam, lParam)
        elif is_escape_key(kb.vkCode):
            if (wParam == WM_SYSKEYDOWN or wParam == WM_KEYDOWN):
                logger.debug("escape (down)")
                state['escape_down'] = True
                state['count_escapes'] += 1
                if state['count_escapes'] == 1:
                    if composer.is_on():
                        composer.end()
                        return 1
                    else:
                        logger.debug("escape (down) call next")
                        return user32.CallNextHookEx(hook_id, nCode, wParam, lParam)
                else:
                    logger.debug("escape (down) multiple call next")
                    return user32.CallNextHookEx(hook_id, nCode, wParam, lParam)
            elif (wParam == WM_SYSKEYUP or wParam == WM_KEYUP):
                logger.debug("espace (up)")
                state['count_escapes'] = 0
                if state['count_escapes'] == 1:
                    return 1
                else:
                    return user32.CallNextHookEx(hook_id, nCode, wParam, lParam)
                state['count_escapes'] = 0
            else:
                assert False

            return user32.CallNextHookEx(hook_id, nCode, wParam, lParam)
        else:
            # continue execution
            pass

        guithreadinfo = GUITHREADINFO()
        guithreadinfo.cbSize = ctypes.sizeof(GUITHREADINFO)

        user32.GetGUIThreadInfo(None, byref(guithreadinfo))

        kbfocus_thread = user32.GetWindowThreadProcessId(guithreadinfo.hwndFocus, None)

        cchBuff = 64
        pwszBuff = create_unicode_buffer(cchBuff)

        # The output from this isn't actually used but it forces the Api
        # to evaluate the modifiers for the key code
        user32.GetKeyState(0)

        lpKeyState = (wintypes.BYTE * 256)()
        user32.GetKeyboardState(lpKeyState)


        kblayout = user32.GetKeyboardLayout(kbfocus_thread)

        scancode = user32.MapVirtualKeyExW(kb.vkCode, MAPVK_VK_TO_VSC, kblayout)

        cchSize = 256
        lpString = (ctypes.c_wchar * cchSize)()
        user32.GetKeyNameTextW(wintypes.LONG(scancode << 16), lpString, cchSize)

        chars_written = user32.ToUnicodeEx(
            kb.vkCode,
            kb.scanCode,
            ctypes.cast(lpKeyState, wintypes.PBYTE), ctypes.cast(pwszBuff, wintypes.LPWSTR),
            cchBuff, kb.flags,
            kblayout
        )

        # TODO: "However, the buffer may contain more characters than the return value specifies.
        #  When this happens, any extra characters are invalid and should be ignored."
        typed_character = pwszBuff.value

        if composer.is_on():
            if (wParam == WM_SYSKEYDOWN or wParam == WM_KEYDOWN):
                if chars_written > 0:
                    adding_result = composer.add_char(typed_character)
                    if adding_result == CharDB.NOT_FOUND:
                        logger.debug("should reset: %s", repr(composer.get_input_string()))

                        chars = composer.get_input_string()
                        codepoints = utf16_codepoints(chars)
                        send_unicode(codepoints)

                        composer.end()
                        return 1
                    elif adding_result == CharDB.POTENTIAL_MATCH:
                        # continue
                        logger.debug("should continue")
                        return 1
                    elif adding_result == CharDB.MATCH_FOUND:
                        chars = composer.get_composed_chars()
                        logger.debug("found char %s", repr(chars))

                        # codepoints = utf16_codepoints(_test_sequences[0])
                        # logger.debug("stuff %s", codepoints)
                        # send_unicode(codepoints)

                        codepoints = utf16_codepoints(chars)
                        send_unicode(codepoints)

                        logger.debug("SENT!!! %s", codepoints)
                        composer.end()
                        return 1
                        # return user32.CallNextHookEx(hook_id, nCode, wParam, lParam)
                    else:
                        assert False
                else:
                    # special char (shift, for example)
                    # logger.debug("non-char character entened")
                    # composer.end()
                    # return 1
                    return user32.CallNextHookEx(hook_id, nCode, wParam, lParam)
            elif (wParam == WM_SYSKEYUP or wParam == WM_KEYUP):
                logger.debug("compose on (key up)")
                if chars_written > 0:
                    logger.debug("compose on (ignoring key up)")
                    return 1
                else:
                    # special char (shift)
                    logger.debug("compose on (allowing special char)")
                    return user32.CallNextHookEx(hook_id, nCode, wParam, lParam)
            else:
                assert False, "should not happen"
        else:
            logger.debug("default action")
            # Be a good neighbor and call the next hook.
            return user32.CallNextHookEx(hook_id, nCode, wParam, lParam)

    ##

    hMod = kernel32.GetModuleHandleW(None)

    pointer = HOOKPROC(low_level_handler)
    hook_id = user32.SetWindowsHookExW(WH_KEYBOARD_LL, pointer, hMod, 0)

    mainThreadId = kernel32.GetCurrentThreadId()

    def _exit_handler(*args):
        logger.debug("exit_handler: %s", args)
        wParam = 0  # postQuitExitCode gets this
        lParam = 0  # not sure if used
        user32.PostThreadMessageW(mainThreadId, WM_QUIT, wParam, lParam)
        return True

    handler = PHANDLER_ROUTINE(_exit_handler)
    kernel32.SetConsoleCtrlHandler(handler, True)

    try:
        msg = ctypes.wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), 0, 0, 0) != 0:
            logger.debug('msg %s', msg)
            user32.TranslateMessage(msg)
            user32.DispatchMessageW(msg)
    except KeyboardInterrupt as e:
        logger.debug("Kbinter")
    finally:
        logger.debug("hook_id %s", hook_id)
        user32.UnhookWindowsHookEx(hook_id)
        logger.debug('unhooked')


if __name__ == '__main__':
    listen()