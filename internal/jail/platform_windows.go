package jail

import "errors"

func newPlatform() (platform, error) { return nil, errors.New("not built yet") }
func platformCleanupErrs() []error   { return nil }
func (r *runner) startProxy(string) (*toolProxy, error) {
	return nil, errors.New("not built yet")
}
