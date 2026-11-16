package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"github.com/lardan099/hyroute/internal/store"
	"github.com/lardan099/hyroute/internal/update"
	"golang.org/x/sys/windows"
)

// Hashes of every companion file in this ZIP, embedded in the running EXE.
var installManifest string

func grouteInstallTarget() string {
	return filepath.Join(filepath.Dir(upstreamMoveTarget()), "GRoute")
}

func installedGRouteData() (string, error) {
	base, err := store.DefaultDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(base), "GRoute", "Data"), nil
}

func (g *GUI) installGRoute() error {
	if runningInstalledGRoute() {
		return errors.New("GRoute уже установлен")
	}
	if !g.restartingAsAdmin.CompareAndSwap(false, true) {
		return errors.New("дождитесь завершения предыдущего действия")
	}
	defer g.restartingAsAdmin.Store(false)
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if canRestartAsAdmin() {
		err = runInstallHelper(self)
	} else {
		err = installGRouteProgram()
	}
	if err != nil {
		return err
	}
	data, err := installedGRouteData()
	if err != nil {
		return err
	}
	if err := migrateGRouteProfile(data, g.ctl.CopyInstallSettings); err != nil {
		return fmt.Errorf("перенос настроек GRoute: %w", err)
	}
	installed := filepath.Join(grouteInstallTarget(), "GRoute.exe")
	cmd := exec.Command(installed, "--wait-pid="+strconv.Itoa(os.Getpid()))
	cmd.Dir = filepath.Dir(installed)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("запуск установленного GRoute: %w", err)
	}
	g.quit()
	return nil
}

// Only the machine files and shortcut are installed by the elevated helper.
// DPAPI data is migrated by the original user even if UAC uses another account.
func runInstallHelper(self string) error {
	type shellExecuteInfo struct {
		size, mask            uint32
		window                windows.Handle
		verb, file, args, dir *uint16
		show                  int32
		instance, idList      uintptr
		class                 *uint16
		classKey              windows.Handle
		hotKey                uint32
		icon, process         windows.Handle
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, err := windows.UTF16PtrFromString(self)
	if err != nil {
		return err
	}
	args, _ := windows.UTF16PtrFromString("--install-groute-files")
	si := shellExecuteInfo{mask: 0x40 | 0x100, verb: verb, file: file, args: args, show: windows.SW_SHOWNORMAL}
	si.size = uint32(unsafe.Sizeof(si))
	proc := windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")
	ok, _, err := proc.Call(uintptr(unsafe.Pointer(&si)))
	if ok == 0 {
		if errors.Is(err, windows.ERROR_CANCELLED) {
			return errors.New("установка отменена")
		}
		return fmt.Errorf("не удалось начать установку: %w", err)
	}
	defer windows.CloseHandle(si.process)
	if _, err := windows.WaitForSingleObject(si.process, windows.INFINITE); err != nil {
		return err
	}
	var code uint32
	if err := windows.GetExitCodeProcess(si.process, &code); err != nil {
		return err
	}
	if code != 0 {
		return errors.New("установка не завершена. Портативная копия продолжает работать")
	}
	return nil
}

// Publish the finished profile at once. A repeat install retains the installed
// user's data. Only the fresh staging directory belongs to this operation.
func migrateGRouteProfile(dest string, copySettings func(*os.Root) error) error {
	parent := filepath.Dir(dest)
	if err := store.Guard(parent); err != nil {
		return err
	}
	base, err := os.OpenRoot(parent)
	if err != nil {
		return err
	}
	defer base.Close()
	if st, err := base.Lstat(filepath.Base(dest)); err == nil {
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return errors.New("путь профиля GRoute уже занят")
		}
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	temp, err := os.MkdirTemp(parent, ".install-")
	if err != nil {
		return err
	}
	name := filepath.Base(temp)
	defer base.RemoveAll(name)
	stage, err := base.OpenRoot(name)
	if err != nil {
		return err
	}
	err = copySettings(stage)
	stage.Close()
	if err != nil {
		return err
	}
	return base.Rename(name, filepath.Base(dest))
}

func grouteBundleHashes() (map[string]string, error) {
	var files map[string]string
	raw, err := base64.StdEncoding.DecodeString(installManifest)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &files); err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, errors.New("в сборке отсутствует перечень файлов установки")
	}
	return files, nil
}

func installGRouteProgram() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if installedGRoute(self) {
		return errors.New("запустите установку из распакованной копии GRoute")
	}
	release, err := update.PinFile(self)
	if err != nil {
		return err
	}
	defer release()
	files, err := grouteBundleHashes()
	if err != nil {
		return err
	}
	target := grouteInstallTarget()
	if !protectedLocationOf(filepath.Dir(target), "") {
		return errors.New("каталог Program Files доступен для записи без прав администратора")
	}
	// A system-wide file lock also covers concurrent installs from other sessions.
	lockName, err := windows.UTF16PtrFromString(target + ".install-lock")
	if err != nil {
		return err
	}
	lock, err := windows.CreateFile(lockName, windows.GENERIC_WRITE|windows.DELETE, 0, nil, windows.CREATE_NEW, windows.FILE_FLAG_DELETE_ON_CLOSE, 0)
	if err != nil {
		return fmt.Errorf("не удалось занять папку для установки GRoute: %w", err)
	}
	defer windows.CloseHandle(lock)
	for _, dir := range []string{target, target + ".previous"} {
		st, err := os.Lstat(dir)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !st.IsDir() || !protectedLocationOf(dir, filepath.Join(dir, "GRoute.exe")) {
			return fmt.Errorf("не удалось подтвердить защиту папки %s", dir)
		}
	}
	if err := installGRouteBundle(self, target, files); err != nil {
		return err
	}
	programs, err := windows.KnownFolderPath(windows.FOLDERID_CommonPrograms, 0)
	if err != nil {
		return err
	}
	return createShortcut(filepath.Join(programs, "GRoute.lnk"), filepath.Join(target, "GRoute.exe"))
}

const installReceipt = ".groute-installed.json"

// Refuse to displace an unrelated folder or remove files the owner added.
func checkManagedFolder(dir string) error {
	marker, err := os.ReadFile(filepath.Join(dir, installReceipt))
	if err != nil {
		return fmt.Errorf("папка %s уже занята. Для установки требуется папка GRoute, созданная установщиком: %w", dir, err)
	}
	var files map[string]string
	if err := json.Unmarshal(marker, &files); err != nil || len(files) == 0 {
		return fmt.Errorf("повреждён перечень файлов в %s", dir)
	}
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if d.Type().IsRegular() && (name == installReceipt || name == "GRoute.exe" || files[filepath.ToSlash(name)] != "") {
			return nil
		}
		return fmt.Errorf("перед обновлением перенесите свой файл из папки программы: %s", path)
	})
}

func installGRouteBundle(self, target string, files map[string]string) error {
	parent := filepath.Dir(target)
	stage, err := os.MkdirTemp(parent, ".groute-install-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	src, err := os.OpenRoot(filepath.Dir(self))
	if err != nil {
		return err
	}
	defer src.Close()
	for name, hash := range files {
		if err := copyBundleFile(src, name, filepath.Join(stage, filepath.FromSlash(name)), hash); err != nil {
			return err
		}
	}
	if err := copyBundleFile(src, filepath.Base(self), filepath.Join(stage, "GRoute.exe"), ""); err != nil {
		return err
	}
	receipt, err := json.Marshal(files)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stage, installReceipt), receipt, 0600); err != nil {
		return err
	}
	previous := target + ".previous"
	_, prevErr := os.Lstat(previous)
	if prevErr != nil && !errors.Is(prevErr, fs.ErrNotExist) {
		return prevErr
	}
	if prevErr == nil {
		if err := checkManagedFolder(previous); err != nil {
			return err
		}
		if _, err := os.Lstat(target); errors.Is(err, fs.ErrNotExist) {
			// Recover an interrupt between the two directory renames.
			if err := os.Rename(previous, target); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else if err := os.RemoveAll(previous); err != nil {
			return err
		}
	}
	hadOld := false
	if _, err := os.Lstat(target); err == nil {
		if err := checkManagedFolder(target); err != nil {
			return err
		}
		if err := os.Rename(target, previous); err != nil {
			return err
		}
		hadOld = true
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Rename(stage, target); err != nil {
		if hadOld {
			return errors.Join(err, os.Rename(previous, target))
		}
		return err
	}
	if hadOld {
		return os.RemoveAll(previous)
	}
	return nil
}

func copyBundleFile(src *os.Root, name, dst, want string) error {
	f, err := src.Open(filepath.FromSlash(name))
	if err != nil {
		return fmt.Errorf("распакуйте ZIP целиком: %w", err)
	}
	defer f.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
	if err != nil {
		return err
	}
	hash := sha256.New()
	_, writeErr := io.Copy(io.MultiWriter(out, hash), f)
	if err := errors.Join(writeErr, out.Close()); err != nil {
		return err
	}
	if want != "" && !strings.EqualFold(want, hex.EncodeToString(hash.Sum(nil))) {
		return fmt.Errorf("файл %s отличается от файла выпуска. Распакуйте ZIP заново", name)
	}
	return nil
}
