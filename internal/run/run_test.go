package run

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestShownSplitsExtras(t *testing.T) {
	c := New("/tmp", "terraform", "plan", Extra("-input=false"), Extra("-no-color"), "-out=/data/plan 1.tfplan")
	got := c.Shown()
	if got.Command != "terraform plan '-out=/data/plan 1.tfplan'" {
		t.Errorf("command: %q", got.Command)
	}
	if got.Extra != "-input=false -no-color" {
		t.Errorf("extra: %q", got.Extra)
	}
	if line := c.Line(); line != "terraform plan -input=false -no-color '-out=/data/plan 1.tfplan'" {
		t.Errorf("line: %q", line)
	}
}

func TestQuote(t *testing.T) {
	cases := map[string]string{
		"plain":                       "plain",
		"":                            "''",
		"two words":                   "'two words'",
		"it's":                        `'it'\''s'`,
		`module.web["a"]`:             `'module.web["a"]'`,
		"name=curl state=present":     "'name=curl state=present'",
		"192.168.5.133,192.168.5.134": "192.168.5.133,192.168.5.134",
	}
	for in, want := range cases {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStripANSI(t *testing.T) {
	in := "\x1b[31m╷\x1b[0m\n\x1b[31m│\x1b[0m \x1b[1m\x1b[31mError: \x1b[0m\x1b[0m\x1b[1mError acquiring the state lock\x1b[0m"
	want := "╷\n│ Error: Error acquiring the state lock"
	if got := StripANSI(in); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestStripWriterKeepsCodesCutAcrossWrites(t *testing.T) {
	var out strings.Builder
	w := &stripWriter{w: &out}
	w.Write([]byte("plain \x1b[3"))
	w.Write([]byte("1mred\x1b[0m\nnext \x1b["))
	w.Write([]byte("0mend"))
	w.Flush()
	if got := out.String(); got != "plain red\nnext end" {
		t.Fatalf("got %q", got)
	}
}

func TestNewPanicsOnWrongType(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("no panic for an int argument")
		}
	}()
	New("", "terraform", 3)
}

func TestNewSliceArgs(t *testing.T) {
	c := New("", "ansible", "all", []string{"-i", "inventory.ini"}, "-m", "ping", Extra("-o"))
	if got := c.Shown().Command; got != "ansible all -i inventory.ini -m ping" {
		t.Errorf("got %q", got)
	}
}

// A secret reaches a program on its standard input, so it is in no argument and
// not in the command a page shows.
func TestStdinIsFedToTheProgramAndIsNotInTheCommand(t *testing.T) {
	if _, err := exec.LookPath("cat"); err != nil {
		t.Skip("there is no cat here")
	}
	c := New("", "cat")
	c.Stdin = "s3cr3t-value"
	res, err := Output(c, 10*time.Second)
	if err != nil || res.Stdout != "s3cr3t-value" {
		t.Fatalf("output: %+v %v", res, err)
	}
	if strings.Contains(c.Shown().Command, "s3cr3t") || strings.Contains(c.Line(), "s3cr3t") {
		t.Errorf("the value is in the command: %s", c.Line())
	}
}

func TestStreamHelperSleep(t *testing.T) {
	if os.Getenv("RUN_TEST_SLEEP") != "1" {
		return
	}
	time.Sleep(10 * time.Second)
}

func TestStreamTimesOut(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	c := New("", exe, "-test.run=^TestStreamHelperSleep$")
	c.Env = []string{"RUN_TEST_SLEEP=1"}

	var buf bytes.Buffer
	start := time.Now()
	exit, err := Stream(c, &buf, 200*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "did not finish within") {
		t.Fatalf("Stream() = (%d, %v), want timeout error", exit, err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("Stream took too long to time out: %s", time.Since(start))
	}
}
