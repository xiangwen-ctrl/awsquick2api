//go:build windows

package tray

import (
	"fmt"
	"log"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modUser32   = windows.NewLazySystemDLL("user32.dll")
	modShell32  = windows.NewLazySystemDLL("shell32.dll")
	modKernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procRegisterClassExW         = modUser32.NewProc("RegisterClassExW")
	procUnregisterClassW         = modUser32.NewProc("UnregisterClassW")
	procCreateWindowExW          = modUser32.NewProc("CreateWindowExW")
	procDestroyWindow            = modUser32.NewProc("DestroyWindow")
	procDefWindowProcW           = modUser32.NewProc("DefWindowProcW")
	procGetMessageW              = modUser32.NewProc("GetMessageW")
	procTranslateMessage         = modUser32.NewProc("TranslateMessage")
	procDispatchMessageW         = modUser32.NewProc("DispatchMessageW")
	procPostQuitMessage          = modUser32.NewProc("PostQuitMessage")
	procPostMessageW             = modUser32.NewProc("PostMessageW")
	procRegisterWindowMessageW   = modUser32.NewProc("RegisterWindowMessageW")
	procCreatePopupMenu          = modUser32.NewProc("CreatePopupMenu")
	procAppendMenuW              = modUser32.NewProc("AppendMenuW")
	procSetMenuDefaultItem       = modUser32.NewProc("SetMenuDefaultItem")
	procTrackPopupMenuEx         = modUser32.NewProc("TrackPopupMenuEx")
	procDestroyMenu              = modUser32.NewProc("DestroyMenu")
	procSetForegroundWindow      = modUser32.NewProc("SetForegroundWindow")
	procGetCursorPos             = modUser32.NewProc("GetCursorPos")
	procCreateIconFromResEx      = modUser32.NewProc("CreateIconFromResourceEx")
	procLoadIconW                = modUser32.NewProc("LoadIconW")
	procDestroyIcon              = modUser32.NewProc("DestroyIcon")
	procMessageBoxW              = modUser32.NewProc("MessageBoxW")
	procOpenClipboard            = modUser32.NewProc("OpenClipboard")
	procEmptyClipboard           = modUser32.NewProc("EmptyClipboard")
	procSetClipboardData         = modUser32.NewProc("SetClipboardData")
	procCloseClipboard           = modUser32.NewProc("CloseClipboard")
	procRegisterClipboardFormatW = modUser32.NewProc("RegisterClipboardFormatW")
	procShellNotifyIconW         = modShell32.NewProc("Shell_NotifyIconW")
	procShellExecuteW            = modShell32.NewProc("ShellExecuteW")
	procGetModuleHandleW         = modKernel32.NewProc("GetModuleHandleW")
	procGlobalAlloc              = modKernel32.NewProc("GlobalAlloc")
	procGlobalLock               = modKernel32.NewProc("GlobalLock")
	procGlobalUnlock             = modKernel32.NewProc("GlobalUnlock")
	procGlobalFree               = modKernel32.NewProc("GlobalFree")
	procRtlMoveMemory            = modKernel32.NewProc("RtlMoveMemory")
	procSetTimer                 = modUser32.NewProc("SetTimer")
	procKillTimer                = modUser32.NewProc("KillTimer")
)

const (
	wmNull            = 0x0000
	wmDestroy         = 0x0002
	wmClose           = 0x0010
	wmQueryEndSession = 0x0011
	wmEndSession      = 0x0016
	wmContextMenu     = 0x007B
	wmTimer           = 0x0113
	wmLButtonUp       = 0x0202
	wmLButtonDblClk   = 0x0203
	wmRButtonUp       = 0x0205
	wmTrayCallback    = 0x8000 + 1
	wmTrayStop        = 0x8000 + 2

	timerRetryAddID = 1

	nimAdd    = 0x00000000
	nimModify = 0x00000001
	nimDelete = 0x00000002

	nifMessage = 0x00000001
	nifIcon    = 0x00000002
	nifTip     = 0x00000004
	nifInfo    = 0x00000010

	niifInfo = 0x00000001

	mfString    = 0x00000000
	mfUnchecked = 0x00000000
	mfChecked   = 0x00000008
	mfSeparator = 0x00000800

	tpmRightButton = 0x0002
	tpmNonotify    = 0x0080
	tpmReturnCmd   = 0x0100

	mbOK        = 0x00000000
	mbIconError = 0x00000010
	mbTopmost   = 0x00040000

	cfUnicodeText = 13
	gmemMoveable  = 0x0002

	swShowNormal   = 1
	idiApplication = 32512

	cmdOpenPanel    = 1001
	cmdCopyAPIKey   = 1002
	cmdCopyAdminKey = 1007
	cmdCopyBaseURL  = 1003
	cmdOpenCfgDir   = 1004
	cmdOpenLogFile  = 1005
	cmdToggleAuto   = 1006
	cmdQuit         = 1099
)

type wndClassExW struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     windows.Handle
	hIcon         windows.Handle
	hCursor       windows.Handle
	hbrBackground windows.Handle
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       windows.Handle
}

type winPoint struct {
	x int32
	y int32
}

type winMsg struct {
	hWnd    windows.Handle
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      winPoint
}

type notifyIconDataW struct {
	cbSize           uint32
	hWnd             windows.Handle
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            windows.Handle
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uVersion         uint32
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         windows.GUID
	hBalloonIcon     windows.Handle
}

var (
	trayClassSeq atomic.Uint64
	trayRegMu    sync.RWMutex
	trayByHwnd   = map[windows.Handle]*Controller{}
	wndProcOnce  sync.Once
	wndProcPtr   uintptr
)

type Controller struct {
	cfg            Config
	hwnd           windows.Handle
	hIcon          windows.Handle
	ownsIcon       bool
	iconAdded      bool
	destroyed      bool // set by WM_DESTROY (window thread only)
	addRetries     int
	hInst          windows.Handle
	className      string
	taskbarCreated uint32
	quitOnce       sync.Once
	stopOnce       sync.Once
	done           chan struct{}
}

func Start(cfg Config) (*Controller, error) {
	if cfg.Tooltip == "" {
		cfg.Tooltip = "AWSQuick2API"
	}
	c := &Controller{
		cfg:  cfg,
		done: make(chan struct{}),
	}

	ready := make(chan error, 1)
	go c.runLoop(ready)

	if err := <-ready; err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Controller) Stop() {
	if c == nil {
		return
	}
	c.stopOnce.Do(func() {
		if c.hwnd != 0 {
			_, _, _ = procPostMessageW.Call(uintptr(c.hwnd), wmTrayStop, 0, 0)
		}
		select {
		case <-c.done:
		case <-time.After(3 * time.Second):
		}
	})
}

func (c *Controller) triggerQuit() {
	c.quitOnce.Do(func() {
		if c.cfg.OnQuit != nil {
			go c.cfg.OnQuit()
		}
	})
}

func (c *Controller) runLoop(ready chan<- error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer close(c.done)

	hInst, _, _ := procGetModuleHandleW.Call(0)
	c.hInst = windows.Handle(hInst)

	wndProcOnce.Do(func() {
		wndProcPtr = syscall.NewCallback(trayWndProc)
	})

	c.className = fmt.Sprintf("AWSQuick2API_TrayWnd_%d", trayClassSeq.Add(1))
	clsPtr, err := windows.UTF16PtrFromString(c.className)
	if err != nil {
		ready <- err
		return
	}

	wc := wndClassExW{
		cbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
		lpfnWndProc:   wndProcPtr,
		hInstance:     c.hInst,
		lpszClassName: clsPtr,
	}
	atom, _, regErr := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	if atom == 0 {
		ready <- fmt.Errorf("RegisterClassExW: %w", regErr)
		return
	}
	defer func() {
		_, _, _ = procUnregisterClassW.Call(uintptr(unsafe.Pointer(clsPtr)), uintptr(c.hInst))
	}()

	titlePtr, _ := windows.UTF16PtrFromString("AWSQuick2API")
	hwndRet, _, crErr := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(clsPtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		0,
		0, 0, 0, 0,
		0, 0,
		uintptr(c.hInst),
		0,
	)
	if hwndRet == 0 {
		ready <- fmt.Errorf("CreateWindowExW: %w", crErr)
		return
	}
	c.hwnd = windows.Handle(hwndRet)

	tbMsgPtr, _ := windows.UTF16PtrFromString("TaskbarCreated")
	tbMsg, _, _ := procRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(tbMsgPtr)))
	c.taskbarCreated = uint32(tbMsg)

	trayRegMu.Lock()
	trayByHwnd[c.hwnd] = c
	trayRegMu.Unlock()
	defer func() {
		trayRegMu.Lock()
		delete(trayByHwnd, c.hwnd)
		trayRegMu.Unlock()
	}()

	iconH, owns := createTrayIconHandle()
	c.hIcon = iconH
	c.ownsIcon = owns
	defer func() {
		if c.ownsIcon && c.hIcon != 0 {
			_, _, _ = procDestroyIcon.Call(uintptr(c.hIcon))
		}
	}()

	if err := c.addTrayIcon(); err != nil {
		log.Printf("WARN: [tray] initial Shell_NotifyIconW deferred (waiting for taskbar): %v", err)
		_, _, _ = procSetTimer.Call(uintptr(c.hwnd), timerRetryAddID, 2000, 0)
	} else {
		c.iconAdded = true
		if c.cfg.ShowStartup && c.cfg.StartupBody != "" {
			c.showBalloon(c.cfg.StartupTitle, c.cfg.StartupBody)
		}
	}
	// Teardown order (defers run LIFO): notification icon -> window -> icon
	// handle -> hwnd registry entry -> window class. WM_DESTROY normally removes
	// the notification icon while the window is still valid; this covers a
	// message loop that ended without WM_DESTROY. The window must be gone before
	// the icon handle it references is freed and before its class is unregistered.
	defer func() {
		if !c.destroyed {
			_, _, _ = procKillTimer.Call(uintptr(c.hwnd), timerRetryAddID)
			c.deleteTrayIcon()
			_, _, _ = procDestroyWindow.Call(uintptr(c.hwnd))
		}
	}()

	ready <- nil

	var msg winMsg
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		_, _, _ = procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		_, _, _ = procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

func createTrayIconHandle() (windows.Handle, bool) {
	pngBytes := renderTrayIconPNG()
	if len(pngBytes) > 0 {
		h, _, _ := procCreateIconFromResEx.Call(
			uintptr(unsafe.Pointer(&pngBytes[0])),
			uintptr(len(pngBytes)),
			1,
			0x00030000,
			32, 32,
			0,
		)
		if h != 0 {
			return windows.Handle(h), true
		}
	}
	h, _, _ := procLoadIconW.Call(0, idiApplication)
	return windows.Handle(h), false
}

func (c *Controller) addTrayIcon() error {
	var nid notifyIconDataW
	nid.cbSize = uint32(unsafe.Sizeof(nid))
	nid.hWnd = c.hwnd
	nid.uID = 1
	nid.uFlags = nifMessage | nifIcon | nifTip
	nid.uCallbackMessage = wmTrayCallback
	nid.hIcon = c.hIcon
	copyUTF16Fixed(nid.szTip[:], c.cfg.Tooltip)

	r, _, err := procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&nid)))
	if r == 0 {
		return fmt.Errorf("Shell_NotifyIconW(NIM_ADD): %w", err)
	}
	return nil
}

func (c *Controller) deleteTrayIcon() {
	if c.hwnd == 0 || !c.iconAdded {
		return
	}
	c.iconAdded = false
	var nid notifyIconDataW
	nid.cbSize = uint32(unsafe.Sizeof(nid))
	nid.hWnd = c.hwnd
	nid.uID = 1
	_, _, _ = procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
}

func (c *Controller) showBalloon(title, body string) {
	if c.hwnd == 0 || body == "" {
		return
	}
	if title == "" {
		title = "AWSQuick2API"
	}
	var nid notifyIconDataW
	nid.cbSize = uint32(unsafe.Sizeof(nid))
	nid.hWnd = c.hwnd
	nid.uID = 1
	nid.uFlags = nifInfo
	nid.dwInfoFlags = niifInfo
	copyUTF16Fixed(nid.szInfoTitle[:], title)
	copyUTF16Fixed(nid.szInfo[:], body)
	_, _, _ = procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&nid)))
}

func (c *Controller) showContextMenu() {
	hMenu, _, _ := procCreatePopupMenu.Call()
	if hMenu == 0 {
		return
	}
	defer func() {
		_, _, _ = procDestroyMenu.Call(hMenu)
	}()

	addItem := func(flags uint32, id uintptr, label string) {
		var ptr uintptr
		if label != "" {
			if p, err := windows.UTF16PtrFromString(label); err == nil {
				ptr = uintptr(unsafe.Pointer(p))
			}
		}
		_, _, _ = procAppendMenuW.Call(hMenu, uintptr(flags), id, ptr)
	}

	addItem(mfString, cmdOpenPanel, "打开管理面板")
	_, _, _ = procSetMenuDefaultItem.Call(hMenu, cmdOpenPanel, 0)
	addItem(mfString, cmdCopyAdminKey, "复制面板管理密钥 (admin_key)")
	addItem(mfString, cmdCopyAPIKey, "复制推理密钥 (api_key)")
	addItem(mfString, cmdCopyBaseURL, "复制 OpenAI Base URL")
	addItem(mfSeparator, 0, "")
	addItem(mfString, cmdOpenCfgDir, "打开配置目录")
	addItem(mfString, cmdOpenLogFile, "查看运行日志")
	addItem(mfSeparator, 0, "")

	autoFlags := uint32(mfString | mfUnchecked)
	if IsAutostartEnabled(c.cfg.ExePath, c.cfg.ConfigPath) {
		autoFlags = mfString | mfChecked
	}
	addItem(autoFlags, cmdToggleAuto, "开机自启动")
	addItem(mfSeparator, 0, "")
	addItem(mfString, cmdQuit, "退出 AWSQuick2API")

	var pt winPoint
	_, _, _ = procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	_, _, _ = procSetForegroundWindow.Call(uintptr(c.hwnd))

	cmd, _, _ := procTrackPopupMenuEx.Call(
		hMenu,
		tpmRightButton|tpmReturnCmd|tpmNonotify,
		uintptr(pt.x),
		uintptr(pt.y),
		uintptr(c.hwnd),
		0,
	)
	_, _, _ = procPostMessageW.Call(uintptr(c.hwnd), wmNull, 0, 0)

	c.handleMenuCommand(cmd)
}

func (c *Controller) handleMenuCommand(cmd uintptr) {
	switch cmd {
	case cmdOpenPanel:
		if c.cfg.PanelURL != nil {
			_ = OpenTarget(c.cfg.PanelURL())
		}
	case cmdCopyAdminKey:
		key := ""
		if c.cfg.AdminKey != nil {
			key = c.cfg.AdminKey()
		}
		if key == "" {
			c.showBalloon("AWSQuick2API", "当前 admin_key 为空，请先在 config.json 中配置")
			return
		}
		if err := copySecretToClipboard(key); err == nil {
			c.showBalloon("AWSQuick2API", "已复制面板管理密钥 (admin_key) 到剪贴板")
		}
	case cmdCopyAPIKey:
		key := ""
		if c.cfg.APIKey != nil {
			key = c.cfg.APIKey()
		}
		if key == "" {
			c.showBalloon("AWSQuick2API", "当前 api_key 为空，请先在 config.json 中配置")
			return
		}
		if err := copySecretToClipboard(key); err == nil {
			c.showBalloon("AWSQuick2API", "已复制推理密钥 (api_key) 到剪贴板")
		}
	case cmdCopyBaseURL:
		if c.cfg.OpenAIBase != nil {
			u := c.cfg.OpenAIBase()
			if err := CopyClipboardText(u); err == nil {
				c.showBalloon("AWSQuick2API", "已复制 "+u)
			}
		}
	case cmdOpenCfgDir:
		if c.cfg.ConfigDir != "" {
			_ = OpenTarget(c.cfg.ConfigDir)
		}
	case cmdOpenLogFile:
		if c.cfg.LogFile != "" {
			_ = OpenTarget(c.cfg.LogFile)
		}
	case cmdToggleAuto:
		next := !IsAutostartEnabled(c.cfg.ExePath, c.cfg.ConfigPath)
		if err := SetAutostartEnabled(c.cfg.ExePath, c.cfg.ConfigPath, next); err != nil {
			log.Printf("WARN: [tray] toggle autostart=%v failed: %v", next, err)
			c.showBalloon("AWSQuick2API", "设置开机自启动失败："+err.Error())
			return
		}
		if next {
			c.showBalloon("AWSQuick2API", "已开启 Windows 登录开机自启动")
		} else {
			c.showBalloon("AWSQuick2API", "已关闭开机自启动")
		}
	case cmdQuit:
		c.triggerQuit()
		_, _, _ = procDestroyWindow.Call(uintptr(c.hwnd))
	}
}

func trayWndProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	trayRegMu.RLock()
	c := trayByHwnd[windows.Handle(hwnd)]
	trayRegMu.RUnlock()

	if c != nil {
		if c.taskbarCreated != 0 && uint32(msg) == c.taskbarCreated {
			if err := c.addTrayIcon(); err == nil {
				c.iconAdded = true
				_, _, _ = procKillTimer.Call(hwnd, timerRetryAddID)
			}
			return 0
		}
		switch uint32(msg) {
		case wmTimer:
			if wParam == timerRetryAddID && !c.iconAdded {
				c.addRetries++
				if err := c.addTrayIcon(); err == nil {
					c.iconAdded = true
					_, _, _ = procKillTimer.Call(hwnd, timerRetryAddID)
					if c.cfg.ShowStartup && c.cfg.StartupBody != "" {
						c.showBalloon(c.cfg.StartupTitle, c.cfg.StartupBody)
					}
				} else if c.addRetries >= 15 {
					_, _, _ = procKillTimer.Call(hwnd, timerRetryAddID)
				}
			}
			return 0
		case wmTrayCallback:
			ev := uint32(lParam & 0xFFFF)
			switch ev {
			case wmLButtonUp, wmLButtonDblClk:
				if c.cfg.PanelURL != nil {
					_ = OpenTarget(c.cfg.PanelURL())
				}
				return 0
			case wmRButtonUp, wmContextMenu:
				c.showContextMenu()
				return 0
			}
		case wmTrayStop, wmClose:
			_, _, _ = procDestroyWindow.Call(hwnd)
			return 0
		case wmQueryEndSession:
			return 1
		case wmEndSession:
			if wParam != 0 {
				c.triggerQuit()
				_, _, _ = procDestroyWindow.Call(hwnd)
			}
			return 0
		case wmDestroy:
			// Remove the notification icon while the window is still valid, then
			// end the message loop.
			_, _, _ = procKillTimer.Call(hwnd, timerRetryAddID)
			c.deleteTrayIcon()
			c.destroyed = true
			_, _, _ = procPostQuitMessage.Call(0)
			return 0
		}
	}
	ret, _, _ := procDefWindowProcW.Call(hwnd, msg, wParam, lParam)
	return ret
}

func OpenTarget(target string) error {
	if target == "" {
		return nil
	}
	verb, err := windows.UTF16PtrFromString("open")
	if err != nil {
		return err
	}
	path, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	r, _, callErr := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(path)),
		0,
		0,
		swShowNormal,
	)
	if r <= 32 {
		return fmt.Errorf("ShellExecuteW(%s): %w", target, callErr)
	}
	return nil
}

// CopyClipboardText places non-sensitive text (e.g. the Base URL) on the clipboard.
func CopyClipboardText(text string) error { return copyClipboard(text, false) }

// copySecretToClipboard places a secret (api_key / admin_key) on the clipboard and
// marks it so Windows clipboard history (Win+V), Cloud Clipboard sync and
// clipboard monitors skip it.
func copySecretToClipboard(text string) error { return copyClipboard(text, true) }

// sensitiveClipboardFormats are the documented opt-out formats: the presence of
// ExcludeClipboardContentFromMonitorProcessing, and a DWORD 0 for the other two.
var sensitiveClipboardFormats = []string{
	"ExcludeClipboardContentFromMonitorProcessing",
	"CanIncludeInClipboardHistory",
	"CanUploadToCloudClipboard",
}

func copyClipboard(text string, sensitive bool) error {
	u16, err := windows.UTF16FromString(text)
	if err != nil {
		return err
	}
	if r, _, err := procOpenClipboard.Call(0); r == 0 {
		return fmt.Errorf("OpenClipboard: %w", err)
	}
	defer func() {
		_, _, _ = procCloseClipboard.Call()
	}()

	_, _, _ = procEmptyClipboard.Call()
	hMem, err := globalCopy(unsafe.Pointer(&u16[0]), uintptr(len(u16)*2))
	if err != nil {
		return err
	}
	if r, _, err := procSetClipboardData.Call(cfUnicodeText, hMem); r == 0 {
		_, _, _ = procGlobalFree.Call(hMem)
		return fmt.Errorf("SetClipboardData: %w", err)
	}
	if sensitive {
		for _, name := range sensitiveClipboardFormats {
			if err := setClipboardDWORD(name, 0); err != nil {
				log.Printf("WARN: [tray] clipboard privacy format %s: %v", name, err)
			}
		}
	}
	return nil
}

// globalCopy copies n bytes from src into a new movable global memory block
// suitable for SetClipboardData (which takes ownership on success).
func globalCopy(src unsafe.Pointer, n uintptr) (uintptr, error) {
	hMem, _, err := procGlobalAlloc.Call(gmemMoveable, n)
	if hMem == 0 {
		return 0, fmt.Errorf("GlobalAlloc: %w", err)
	}
	ptr, _, err := procGlobalLock.Call(hMem)
	if ptr == 0 {
		_, _, _ = procGlobalFree.Call(hMem)
		return 0, fmt.Errorf("GlobalLock: %w", err)
	}
	_, _, _ = procRtlMoveMemory.Call(ptr, uintptr(src), n)
	_, _, _ = procGlobalUnlock.Call(hMem)
	return hMem, nil
}

// setClipboardDWORD adds a registered clipboard format carrying a DWORD value to
// the currently open clipboard.
func setClipboardDWORD(formatName string, value uint32) error {
	namePtr, err := windows.UTF16PtrFromString(formatName)
	if err != nil {
		return err
	}
	fmtID, _, callErr := procRegisterClipboardFormatW.Call(uintptr(unsafe.Pointer(namePtr)))
	if fmtID == 0 {
		return fmt.Errorf("RegisterClipboardFormatW: %w", callErr)
	}
	v := value
	hMem, err := globalCopy(unsafe.Pointer(&v), unsafe.Sizeof(v))
	if err != nil {
		return err
	}
	if r, _, callErr := procSetClipboardData.Call(fmtID, hMem); r == 0 {
		_, _, _ = procGlobalFree.Call(hMem)
		return fmt.Errorf("SetClipboardData: %w", callErr)
	}
	return nil
}

func ShowErrorDialog(title, body string) {
	tPtr, _ := windows.UTF16PtrFromString(title)
	bPtr, _ := windows.UTF16PtrFromString(body)
	_, _, _ = procMessageBoxW.Call(
		0,
		uintptr(unsafe.Pointer(bPtr)),
		uintptr(unsafe.Pointer(tPtr)),
		mbOK|mbIconError|mbTopmost,
	)
}

func copyUTF16Fixed(dst []uint16, s string) {
	if len(dst) == 0 {
		return
	}
	u16, err := windows.UTF16FromString(s)
	if err != nil {
		return
	}
	if len(u16) > len(dst) {
		copy(dst, u16[:len(dst)-1])
		dst[len(dst)-1] = 0
		return
	}
	copy(dst, u16)
}
