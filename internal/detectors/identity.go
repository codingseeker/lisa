package detectors

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
)

const (
	passwdPath = "/etc/passwd"
	groupPath  = "/etc/group"
)

type Identity struct {
	mu     sync.RWMutex
	users  map[uint32]string
	groups map[uint32]string
}

func LoadIdentity(users, groups io.Reader) (*Identity, error) {
	identity := &Identity{
		users:  map[uint32]string{},
		groups: map[uint32]string{},
	}
	if users != nil {
		if err := identity.load(users, identity.users); err != nil {
			return nil, fmt.Errorf("detectors: parsing passwd data: %w", err)
		}
	}
	if groups != nil {
		if err := identity.load(groups, identity.groups); err != nil {
			return nil, fmt.Errorf("detectors: parsing group data: %w", err)
		}
	}
	return identity, nil
}

func SystemIdentity() *Identity {
	identity, err := LoadIdentity(openOptional(passwdPath), openOptional(groupPath))
	if err != nil {
		return &Identity{users: map[uint32]string{}, groups: map[uint32]string{}}
	}
	return identity
}

func openOptional(path string) io.Reader {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	return file
}

func (i *Identity) load(source io.Reader, into map[uint32]string) error {
	scanner := bufio.NewScanner(source)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r\n")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		id, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			continue
		}
		if fields[0] != "" {
			into[uint32(id)] = fields[0]
		}
	}
	return scanner.Err()
}

func (i *Identity) userName(uid uint32) (string, bool) {
	if i == nil {
		return "", false
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	name, ok := i.users[uid]
	return name, ok
}

func (i *Identity) groupName(gid uint32) (string, bool) {
	if i == nil {
		return "", false
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	name, ok := i.groups[gid]
	return name, ok
}

func (i *Identity) knownUser(uid uint32) bool {
	_, ok := i.userName(uid)
	return ok
}

func (i *Identity) knownGroup(gid uint32) bool {
	_, ok := i.groupName(gid)
	return ok
}

func (i *Identity) userCount() int {
	if i == nil {
		return 0
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return len(i.users)
}

func (i *Identity) groupCount() int {
	if i == nil {
		return 0
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return len(i.groups)
}
