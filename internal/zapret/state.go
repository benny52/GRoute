package zapret

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// StateFile, in the lists folder, is where hyroute_circular (LuaFile)
// notes each method the circular orchestrator takes for a host key: the
// first one, and each switch after failures. HyRoute empties it when it
// starts winws2 and shows its last lines on the page («what runs now»).
const StateFile = "circular.log"

// Switch is one line of StateFile.
type Switch struct {
	At     time.Time
	Target Target
	// Key: the orchestrator's host key: a domain (youtube.com,
	// googlevideo.com, an own site) or "video:<cluster>".
	Key string
	// Strategy: the method's place in the plan (1…); From: the one before
	// (0: the first for this key since winws2 started).
	Strategy, From int
}

// maxState: how much of StateFile's end is read.
const maxState = 256 << 10

// ReadSwitches reads StateFile in dir (the newest maxState bytes); a line
// that does not parse is skipped.
func ReadSwitches(dir string) []Switch {
	f, err := os.Open(filepath.Join(dir, StateFile))
	if err != nil {
		return nil
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > maxState {
		f.Seek(st.Size()-maxState, io.SeekStart)
	}
	data, _ := io.ReadAll(io.LimitReader(f, maxState))
	if i := bytes.IndexByte(data, '\n'); i >= 0 && len(data) == maxState {
		data = data[i+1:] // a cut first line
	}
	var out []Switch
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		p := strings.Split(sc.Text(), "\t")
		if len(p) != 5 {
			continue
		}
		at, err1 := strconv.ParseInt(p[0], 10, 64)
		n, err2 := strconv.Atoi(p[3])
		from, err3 := strconv.Atoi(p[4])
		if err1 != nil || err2 != nil || err3 != nil || n < 1 || from < 0 || p[2] == "" {
			continue
		}
		out = append(out, Switch{At: time.Unix(at, 0), Target: Target(p[1]), Key: p[2], Strategy: n, From: from})
	}
	return out
}

// ResetSwitches empties StateFile (winws2 starts afresh: its orchestrator
// remembers nothing).
func ResetSwitches(dir string) error {
	err := os.Remove(filepath.Join(dir, StateFile))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
