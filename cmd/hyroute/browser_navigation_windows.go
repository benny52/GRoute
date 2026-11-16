package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/go-ole/go-ole"
	"golang.org/x/sys/windows"
)

// Chromium can discard its internal URLs on the command line. Open a local
// page first. Only its new window, its address bar and the selected browser
// executable are eligible for the subsequent UI Automation operation.
func navigateBrowserExtensions(exe, page string) error {
	return navigateBrowserExtensionsWith(exe, page, shellExecuteArgs)
}

func navigateBrowserExtensionsWith(exe, page string, launch func(string, string) error) error {
	valid := false
	for _, k := range browserKinds {
		if k.page == page {
			valid = true
			break
		}
	}
	if !valid {
		return errors.New("неизвестная страница расширений")
	}
	f, err := os.CreateTemp("", "GRoute-extensions-*.html")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	marker := strings.TrimSuffix(filepath.Base(f.Name()), ".html")
	_, err = fmt.Fprintf(f, "<!doctype html><meta charset=utf-8><title>%s</title><p>GRoute открывает страницу расширений. Если переход не произошёл, вставьте в адресную строку <code>%s</code>.</p>", marker, page)
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	if err := launch(exe, "--new-window "+syscall.EscapeArg(f.Name())); err != nil {
		return err
	}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		w := windows.GetForegroundWindow()
		if strings.Contains(browserWindowTitle(w), marker) && browserWindowOwnedBy(w, exe) {
			return inSTA(func() error { return navigateBrowserWindow(w, page, marker) })
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("не удалось подтвердить открытие нового окна выбранного браузера")
}

var (
	getBrowserTitle = user32.NewProc("GetWindowTextW")
	getBrowserRoot  = user32.NewProc("GetAncestor")
	errBrowserFocus = errors.New("активное окно или адресная строка браузера изменились")
	iidBrowserValue = ole.NewGUID("{a94cd8b1-0844-4cd6-9d2d-640537ab39e9}")
)

func browserWindowTitle(w windows.HWND) string {
	var title [512]uint16
	n, _, _ := getBrowserTitle.Call(uintptr(w), uintptr(unsafe.Pointer(&title[0])), uintptr(len(title)))
	return windows.UTF16ToString(title[:n])
}

func browserWindowOwnedBy(w windows.HWND, exe string) bool {
	var pid uint32
	if _, err := windows.GetWindowThreadProcessId(w, &pid); err != nil {
		return false
	}
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(p)
	var buf [32768]uint16
	n := uint32(len(buf))
	return windows.QueryFullProcessImageName(p, 0, &buf[0], &n) == nil &&
		strings.EqualFold(windows.UTF16ToString(buf[:n]), exe)
}

// The slots below follow UIAutomationClient.h. Use the native interfaces
// directly so portable Windows needs neither a scripting host nor a driver.
type browserUI struct{ *ole.IUnknown }

//go:uintptrescapes
func (u browserUI) call(slot int, args ...uintptr) bool {
	method := *(*uintptr)(unsafe.Add(unsafe.Pointer(u.RawVTable), uintptr(slot)*unsafe.Sizeof(uintptr(0))))
	hr, _, _ := syscall.SyscallN(method, append([]uintptr{uintptr(unsafe.Pointer(u.IUnknown))}, args...)...)
	return int32(hr) >= 0
}

// A marker match in the value of an Edit control disambiguates the browser
// address bar from search fields in sidebars and from the document.
func browserAddressBar(root, condition browserUI, marker string) (browserUI, browserUI) {
	var list browserUI
	if !root.call(6, 4 /* TreeScope_Descendants */, uintptr(unsafe.Pointer(condition.IUnknown)), uintptr(unsafe.Pointer(&list))) || list.IUnknown == nil {
		return browserUI{}, browserUI{}
	}
	defer list.Release()
	var count int32
	list.call(3, uintptr(unsafe.Pointer(&count)))
	for i := int32(0); i < count; i++ {
		var elem, pattern browserUI
		if !list.call(4, uintptr(i), uintptr(unsafe.Pointer(&elem))) || elem.IUnknown == nil {
			continue
		}
		if elem.call(14, 10002 /* UIA_ValuePatternId */, uintptr(unsafe.Pointer(iidBrowserValue)), uintptr(unsafe.Pointer(&pattern))) && pattern.IUnknown != nil {
			if strings.Contains(pattern.value(), marker) {
				return elem, pattern
			}
			pattern.Release()
		}
		elem.Release()
	}
	return browserUI{}, browserUI{}
}

func (pattern browserUI) value() string {
	var s *int16
	if !pattern.call(4, uintptr(unsafe.Pointer(&s))) || s == nil {
		return ""
	}
	defer ole.SysFreeString(s)
	return ole.BstrToString((*uint16)(unsafe.Pointer(s)))
}

func navigateBrowserWindow(w windows.HWND, page, marker string) error {
	obj, err := ole.CreateInstance(ole.NewGUID("{FF48DBA4-60EF-4201-AA87-54103EEF594E}"), ole.NewGUID("{30CBE57D-D9D0-452A-AB13-7AC5AC4825EE}"))
	if err != nil {
		return err
	}
	u := browserUI{obj}
	defer u.Release()
	var root, edit browserUI
	if !u.call(6, uintptr(w), uintptr(unsafe.Pointer(&root))) || root.IUnknown == nil {
		return errors.New("интерфейс окна браузера недоступен")
	}
	defer root.Release()
	kind := ole.NewVariant(ole.VT_I4, 50004) // UIA_EditControlTypeId
	if !u.call(23, 30003 /* UIA_ControlTypePropertyId */, uintptr(unsafe.Pointer(&kind)), uintptr(unsafe.Pointer(&edit))) || edit.IUnknown == nil {
		return errors.New("не удалось найти поля ввода браузера")
	}
	defer edit.Release()
	var bar, value browserUI
	for deadline := time.Now().Add(4 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if windows.GetForegroundWindow() != w || !strings.Contains(browserWindowTitle(w), marker) {
			return errBrowserFocus
		}
		bar, value = browserAddressBar(root, edit, marker)
		if bar.IUnknown != nil {
			break
		}
	}
	if bar.IUnknown == nil {
		return errors.New("не удалось найти адресную строку выбранного браузера")
	}
	defer bar.Release()
	defer value.Release()
	marked := func() bool {
		return windows.GetForegroundWindow() == w && strings.Contains(browserWindowTitle(w), marker)
	}
	focused := func() bool {
		var focus int32
		return marked() && bar.call(26, uintptr(unsafe.Pointer(&focus))) && focus != 0
	}
	if !marked() || !bar.call(3) {
		return fmt.Errorf("выделение адресной строки: %w", errBrowserFocus)
	}
	if !focused() && marked() {
		// Yandex may acknowledge UIA SetFocus while its document keeps
		// focus. F6 moves focus from that document to the browser toolbar.
		postBrowserKey(w, 0x75, 0x40) // VK_F6
	}
	for deadline := time.Now().Add(1500 * time.Millisecond); !focused(); time.Sleep(50 * time.Millisecond) {
		if !marked() || !time.Now().Before(deadline) {
			return fmt.Errorf("подтверждение фокуса адресной строки: %w", errBrowserFocus)
		}
	}
	dest := ole.SysAllocString(page)
	defer ole.SysFreeString(dest)
	if !value.call(3, uintptr(unsafe.Pointer(dest))) || !focused() || value.value() != page {
		return errors.New("браузер не принял адрес страницы расширений")
	}
	// Post Enter to this window's own focused HWND. A global synthetic key
	// could instead reach an unrelated application after a focus change.
	tid, _ := windows.GetWindowThreadProcessId(w, nil)
	var gui windows.GUIThreadInfo
	gui.Size = uint32(unsafe.Sizeof(gui))
	if tid == 0 || windows.GetGUIThreadInfo(tid, &gui) != nil || gui.Active != w || gui.Focus == 0 {
		return fmt.Errorf("окно ввода: %w", errBrowserFocus)
	}
	ancestor, _, _ := getBrowserRoot.Call(uintptr(gui.Focus), 2 /* GA_ROOT */)
	if windows.HWND(ancestor) != w || !focused() {
		return fmt.Errorf("отправка перехода: %w", errBrowserFocus)
	}
	if !postBrowserKey(gui.Focus, 13, 0x1c) { // VK_RETURN
		return errors.New("не удалось перейти по адресу в браузере")
	}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if windows.GetForegroundWindow() != w {
			return errBrowserFocus
		}
		title := browserWindowTitle(w)
		if title != "" && !strings.Contains(title, marker) && extensionLocation(value.value(), page) {
			return nil
		}
	}
	return errors.New("не удалось подтвердить переход на страницу расширений")
}

func postBrowserKey(w windows.HWND, key, scanCode uintptr) bool {
	param := scanCode<<16 | 1
	down, _, _ := procPostMessageW.Call(uintptr(w), 0x0100 /* WM_KEYDOWN */, key, param)
	if down != 0 {
		procPostMessageW.Call(uintptr(w), 0x0101 /* WM_KEYUP */, key, param|0xc0000000)
	}
	return down != 0
}

func extensionLocation(actual, expected string) bool {
	actual = strings.TrimSuffix(strings.TrimSpace(actual), "/")
	return actual == strings.TrimSuffix(expected, "/") || actual == "chrome://extensions"
}
