package probe

import "testing"

func TestSelinuxConfigMode(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"enforcing", "SELINUX=enforcing\nSELINUXTYPE=targeted\n", ""},
		{"disabled", "# comment\nSELINUX=disabled\n", "disabled"},
		{"permissive", "SELINUX=permissive\n", "permissive"},
		{"spaces", "  SELINUX = Disabled  \n", "disabled"},
		{"commented-out", "#SELINUX=disabled\nSELINUX=enforcing\n", ""},
		{"empty", "", ""},
		{"unrelated", "SELINUXTYPE=targeted\n", ""},
	}
	for _, c := range cases {
		if got := selinuxConfigMode(c.in); got != c.want {
			t.Errorf("%s: selinuxConfigMode=%q want %q", c.name, got, c.want)
		}
	}
}

func TestSelinuxBootDisable(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"clean", "BOOT_IMAGE=/vmlinuz ro quiet", ""},
		{"selinux0", "ro quiet selinux=0", "selinux=0"},
		{"enforcing0", `GRUB_CMDLINE_LINUX="crashkernel=auto enforcing=0"`, "enforcing=0"},
		{"selinux1", "selinux=1 enforcing=1", ""},
		{"empty", "", ""},
	}
	for _, c := range cases {
		if got := selinuxBootDisable(c.in); got != c.want {
			t.Errorf("%s: selinuxBootDisable=%q want %q", c.name, got, c.want)
		}
	}
}
