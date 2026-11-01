//go:build windows

package watch

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi                = windows.NewLazySystemDLL("advapi32.dll")
	procAuditQuery        = advapi.NewProc("AuditQuerySystemPolicy")
	procAuditSet          = advapi.NewProc("AuditSetSystemPolicy")
	procAuditFree         = advapi.NewProc("AuditFree")
	fileSystemSubcategory = windows.GUID{Data1: 0x0CCE921D, Data2: 0x69AE, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}
)

const (
	policyAuditSuccess = 0x1
	policyAuditFailure = 0x2
	policyAuditNone    = 0x4
)

type auditPolicyInformation struct {
	SubCategory windows.GUID
	Auditing    uint32
	Category    windows.GUID
}

// systemPolicy uses the audit policy API directly: no command output to parse, so it works the
// same in every display language.
type systemPolicy struct{}

func (systemPolicy) Get() (bool, bool, error) {
	var out *auditPolicyInformation
	g := fileSystemSubcategory
	r, _, e := procAuditQuery.Call(uintptr(unsafe.Pointer(&g)), 1, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return false, false, e
	}
	defer procAuditFree.Call(uintptr(unsafe.Pointer(out)))
	if out == nil {
		return false, false, errors.New("no audit policy returned")
	}
	return out.Auditing&policyAuditSuccess != 0, out.Auditing&policyAuditFailure != 0, nil
}

func (systemPolicy) Set(success, failure bool) error {
	v := uint32(policyAuditNone)
	if success || failure {
		v = 0
		if success {
			v |= policyAuditSuccess
		}
		if failure {
			v |= policyAuditFailure
		}
	}
	// The policy is set per subcategory: query to learn the parent category GUID first.
	var cur *auditPolicyInformation
	g := fileSystemSubcategory
	if r, _, e := procAuditQuery.Call(uintptr(unsafe.Pointer(&g)), 1, uintptr(unsafe.Pointer(&cur))); r == 0 {
		return e
	}
	defer procAuditFree.Call(uintptr(unsafe.Pointer(cur)))
	info := auditPolicyInformation{SubCategory: g, Auditing: v, Category: cur.Category}
	if r, _, e := procAuditSet.Call(uintptr(unsafe.Pointer(&info)), 1); r == 0 {
		return e
	}
	return nil
}
