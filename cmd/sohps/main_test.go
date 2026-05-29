package main

import (
	"os"
	"reflect"
	"testing"
)

func TestParseArgs(t *testing.T) {
	// Backup original os.Args
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	tests := []struct {
		name    string
		args    []string
		want    *Args
		wantErr bool
	}{
		{
			name:    "no arguments",
			args:    []string{"sohps"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "only target path",
			args:    []string{"sohps", "/bin/ls"},
			want:    &Args{TargetPath: "/bin/ls", LDLibraryPath: "", RootPath: "/", Verbose: false, NoColor: false},
			wantErr: false,
		},
		{
			name:    "with ld-path",
			args:    []string{"sohps", "--ld-path", "/usr/local/lib", "/bin/ls"},
			want:    &Args{TargetPath: "/bin/ls", LDLibraryPath: "/usr/local/lib", RootPath: "/", Verbose: false, NoColor: false},
			wantErr: false,
		},
		{
			name:    "with root path",
			args:    []string{"sohps", "--root", "/mnt", "/bin/ls"},
			want:    &Args{TargetPath: "/bin/ls", LDLibraryPath: "", RootPath: "/mnt", Verbose: false, NoColor: false},
			wantErr: false,
		},
		{
			name:    "with verbose flag",
			args:    []string{"sohps", "-v", "/bin/ls"},
			want:    &Args{TargetPath: "/bin/ls", LDLibraryPath: "", RootPath: "/", Verbose: true, NoColor: false},
			wantErr: false,
		},
		{
			name:    "with no-color flag",
			args:    []string{"sohps", "-nc", "/bin/ls"},
			want:    &Args{TargetPath: "/bin/ls", LDLibraryPath: "", RootPath: "/", Verbose: false, NoColor: true},
			wantErr: false,
		},
		{
			name:    "all flags",
			args:    []string{"sohps", "-v", "-nc", "--root", "/mnt", "--ld-path", "/usr/local/lib", "/bin/ls"},
			want:    &Args{TargetPath: "/bin/ls", LDLibraryPath: "/usr/local/lib", RootPath: "/mnt", Verbose: true, NoColor: true},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Args = tt.args
			got, err := parseArgs()
			if (err != nil) != tt.wantErr {
				t.Errorf("parseArgs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseArgs() = %v, want %v", got, tt.want)
			}
		})
	}
}
